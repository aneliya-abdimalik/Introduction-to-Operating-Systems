#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include "game_structs.h"
#include "print_output.h"



typedef struct player {
    int fd; 
    pid_t pid; 
    char character; 
} player;


typedef struct game_state {
    int width;
    int height;
    int streak_size;
    int player_count;
    player *players;
    char **grid;
    int filled_positions;
    int game_over;
    char winner;
} game_state;


void init_game(game_state *g);
void setup_players(game_state *g);
void run_game(game_state *g);
int win(game_state *g, int x, int y, char c);
void print_output(cmp *client_msg, smp *server_msg, gu *grid_updates, int update_count);
ssize_t read_full(int fd, void *buf, size_t count);

void init_game(game_state *g) {
    scanf("%d %d %d %d", &g->width, &g->height, &g->streak_size, &g->player_count);

    g->grid = malloc(g->height * sizeof(char *));
    for (int i = 0; i < g->height; i++) {
        g->grid[i] = malloc(g->width * sizeof(char));
        memset(g->grid[i], 0, g->width);
    }

    g->players = malloc(g->player_count * sizeof(player));
    g->filled_positions = 0;
    g->game_over = 0;
    g->winner = 0;
}

void setup_players(game_state *g) {
    for (int i = 0; i < g->player_count; i++) {
        char character;
        int arg_count;
        char executable_path[256];
        char **args;


        scanf(" %c %d %s", &character, &arg_count, executable_path);

        args = malloc((arg_count + 2) * sizeof(char *));
        args[0] = executable_path;
        for (int j = 1; j <= arg_count; j++) {
            args[j] = malloc(256);
            scanf("%s", args[j]);
        }
        args[arg_count + 1] = NULL;

    
        int fd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
            perror("socketpair");
            exit(EXIT_FAILURE);
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (pid == 0) { 
            close(fd[0]); 

   
            dup2(fd[1], STDIN_FILENO);
            dup2(fd[1], STDOUT_FILENO);
            close(fd[1]);

            execvp(executable_path, args);
            perror("execvp");
            exit(EXIT_FAILURE);
        } 
        else { 
            close(fd[1]); 

            int flags = fcntl(fd[0], F_GETFL, 0);
            fcntl(fd[0], F_SETFL, flags | O_NONBLOCK);

            g->players[i].fd = fd[0];
            g->players[i].pid = pid;
            g->players[i].character = character;
        }

        for (int j = 1; j <= arg_count; j++) {
            free(args[j]);
        }
        free(args);
    }
}

void run_game(game_state *g) {
    fd_set read_fds;
    int max_fd = 0;

    for (int i = 0; i < g->player_count; i++) {
        if (g->players[i].fd > max_fd) {
            max_fd = g->players[i].fd;
        }
    }

    while (!g->game_over) {
        FD_ZERO(&read_fds);
   
        for (int i = 0; i < g->player_count; i++) {
            FD_SET(g->players[i].fd, &read_fds);
        }

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000; 

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }

        for (int i = 0; i < g->player_count; i++) {
            if (FD_ISSET(g->players[i].fd, &read_fds)) {
                cm message;
                int bytes_read = read_full(g->players[i].fd, &message, sizeof(cm));
                
                if (bytes_read == sizeof(cm)) {
                    cmp client_log = { .process_id = g->players[i].pid, .client_message = &message };
                    print_output(&client_log, NULL, NULL, 0);

                    sm response;
                    
                    if (message.type == START) {
                        response.type = RESULT;
                        response.success = 0;
                        
                        write(g->players[i].fd, &response, sizeof(sm));
                        smp server_log = { .process_id = g->players[i].pid, .server_message = &response };
                        gd grid_data[g->width * g->height];  // For transmission
                        gu print_updates[g->width * g->height];  // For printing
                        int update_count = 0;
                        int print_count = 0;

                        for (int y = 0; y < g->height; y++) {
                            for (int x = 0; x < g->width; x++) {
                                if (g->grid[y][x] != 0) {
                                    // For transmission
                                    grid_data[update_count].position.x = x;
                                    grid_data[update_count].position.y = y;
                                    grid_data[update_count].character = g->grid[y][x];
                                    update_count++;
                                    
                                    // For printing (if needed)
                                    print_updates[print_count].position.x = x;
                                    print_updates[print_count].position.y = y;
                                    print_updates[print_count].character = g->grid[y][x];
                                    print_count++;
                                }
                            }
                        }

                        print_output(NULL, &server_log, print_updates, print_count);
                        write(g->players[i].fd, grid_data, sizeof(gd) * update_count);
                    } else if (message.type == MARK) {
                        response.type = RESULT;
                    
                        if (message.position.x >= 0 && message.position.x < g->width &&
                            message.position.y >= 0 && message.position.y < g->height &&
                            g->grid[message.position.y][message.position.x] == 0) {
                    
                            g->grid[message.position.y][message.position.x] = g->players[i].character;
                            g->filled_positions++;
                            response.filled_count = g->filled_positions;
                            response.success = 1;
                    
                            if (win(g, message.position.x, message.position.y, g->players[i].character)) {
                                g->game_over = 1;
                                g->winner = g->players[i].character;
                            } else if (g->filled_positions == g->width * g->height) {
                                g->game_over = 1; // Draw
                            }
                        } else {
                            response.success = 0;
                        }
                    
                        // Send the result back to the originating player
                        write(g->players[i].fd, &response, sizeof(sm));
                    
                        smp server_log = { .process_id = g->players[i].pid, .server_message = &response };
                    
                        gu updates[g->width * g->height];
                        int update_count = 0;
                        for (int y = 0; y < g->height; y++) {
                            for (int x = 0; x < g->width; x++) {
                                if (g->grid[y][x] != 0) {
                                    updates[update_count].position.x = x;
                                    updates[update_count].position.y = y;
                                    updates[update_count].character = g->grid[y][x];
                                    update_count++;
                                }
                            }
                        }
                    
                        print_output(NULL, &server_log, updates, update_count);
                    
                        // Instead of sending one grid update at a time, use this code:
                        if (response.success) {
                            gd single_update;
                            single_update.position = message.position;
                            single_update.character = g->players[i].character;
                    
                            gd update_array[1];
                            update_array[0] = single_update;
                    
                            for (int j = 0; j < g->player_count; j++) {
                                if (j == i) continue;
                                if (g->players[j].fd != -1) {
                                    write(g->players[j].fd, update_array, sizeof(gd) * 1);
                                }
                            }
                        }
                    }
                    
                } else if (bytes_read == 0) {
                    close(g->players[i].fd);
                    g->players[i].fd = -1;
                }
            }
        }
    }

    sm end_msg;
    end_msg.type = END;
    for (int i = 0; i < g->player_count; i++) {
        if (g->players[i].fd != -1) {
            write(g->players[i].fd, &end_msg, sizeof(sm));

            smp end_log = { .process_id = g->players[i].pid, .server_message = &end_msg };
            print_output(NULL, &end_log, NULL, 0);
        }
    }
    if (g->winner) {
        printf("Winner: Player%c\n", g->winner);
    } else {
        printf("Draw\n");
    }
    fflush(stdout);

    for (int i = 0; i < g->player_count; i++) {
        if (g->players[i].fd != -1) {
            close(g->players[i].fd);              // Close socket
            waitpid(g->players[i].pid, NULL, 0);  // Reap the child
            g->players[i].fd = -1;
        }
    }
    
}

int win(game_state *g, int x, int y, char c) {
    int dx[] = {1, 0, 1, 1};
    int dy[] = {0, 1, 1, -1};
    
    for (int dir = 0; dir < 4; dir++) {
        int count = 1; 

        for (int step = 1; step < g->streak_size; step++) {
            int nx = x + dx[dir] * step;
            int ny = y + dy[dir] * step;
            
            if (nx < 0 || nx >= g->width || ny < 0 || ny >= g->height || 
                g->grid[ny][nx] != c) {
                break;
            }
            count++;
        }

        for (int step = 1; step < g->streak_size; step++) {
            int nx = x - dx[dir] * step;
            int ny = y - dy[dir] * step;
            
            if (nx < 0 || nx >= g->width || ny < 0 || ny >= g->height || 
                g->grid[ny][nx] != c) {
                break;
            }
            count++;
        }
        
        if (count >= g->streak_size) {
            return 1;
        }
    }
    
    return 0;
}

ssize_t read_full(int fd, void *buf, size_t count) {
    size_t total = 0;
    while (total < count) {
        ssize_t bytes = read(fd, (char *)buf + total, count - total);
        if (bytes <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return -1;
        }
        total += bytes;
    }
    return total == count ? total : -1;
}




int main() {
    game_state g;
    init_game(&g);
    setup_players(&g);
    run_game(&g);
    return 0;
}
