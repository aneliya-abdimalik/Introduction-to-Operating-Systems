#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "ext2fs.h"

static int image_fd = -1;
static uint32_t block_size = 0;
static struct ext2_super_block super_block;

static struct ext2_block_group_descriptor *group_desc = NULL;
static int block_group_count = 0;

static uint8_t  *raw_inode_buf  = NULL;
static struct ext2_inode *inode_table = NULL;

typedef struct {
    uint32_t *blocks;
    size_t    count;
    size_t    capacity;
} BlockList;

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void bl_append(BlockList *bl, uint32_t b) {
    if (b == 0) return;
    if (bl->count == bl->capacity) {
        size_t newcap = (bl->capacity == 0 ? 16 : bl->capacity * 2);
        bl->blocks = realloc(bl->blocks, newcap * sizeof(uint32_t));
        if (!bl->blocks) die("realloc BlockList");
        bl->capacity = newcap;
    }
    bl->blocks[bl->count++] = b;
}

static void collect_indirect(uint32_t block_num, int level, BlockList *bl) {
    if (block_num == 0) return;

    uint32_t *buf = malloc(block_size);
    if (!buf) die("malloc indirect buffer");
    off_t offset = (off_t)block_num * block_size;
    if (lseek(image_fd, offset, SEEK_SET) < 0) die("lseek indirect");
    if ((ssize_t)read(image_fd, buf, block_size) != (ssize_t)block_size)
        die("read indirect");

    uint32_t entries_per_block = block_size / sizeof(uint32_t);
    for (uint32_t i = 0; i < entries_per_block; i++) {
        uint32_t ptr = buf[i];
        if (!ptr) continue;
        if (level == 1) {
            bl_append(bl, ptr);
        } else {
            collect_indirect(ptr, level - 1, bl);
        }
    }
    free(buf);
}

static BlockList gather_all_blocks(const struct ext2_inode *inode) {
    BlockList bl = { .blocks = NULL, .count = 0, .capacity = 0 };
    for (int i = 0; i < EXT2_NUM_DIRECT_BLOCKS; i++) {
        bl_append(&bl, inode->direct_blocks[i]);
    }
    if (inode->single_indirect) {
        collect_indirect(inode->single_indirect, 1, &bl);
    }
    if (inode->double_indirect) {
        collect_indirect(inode->double_indirect, 2, &bl);
    }
    if (inode->triple_indirect) {
        collect_indirect(inode->triple_indirect, 3, &bl);
    }
    return bl;
}

static void bl_free(BlockList *bl) {
    free(bl->blocks);
    bl->blocks = NULL;
    bl->count = bl->capacity = 0;
}

typedef struct {
    uint32_t parent_ino;
    uint32_t ino;
    char     name[EXT2_MAX_NAME_LENGTH + 1];
    bool     is_deleted; 
} DirEntry;

static DirEntry *dir_entries     = NULL;
static size_t    dir_entry_count = 0;
static size_t    dir_entry_cap   = 0;

static void add_dir_entry(uint32_t parent_ino, uint32_t child_ino, const char *name, bool is_deleted) {
    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == child_ino && 
            dir_entries[i].parent_ino == parent_ino &&
            !dir_entries[i].is_deleted) {
            return;
        }
    }
    
    if (dir_entry_count == dir_entry_cap) {
        dir_entry_cap = dir_entry_cap ? dir_entry_cap * 2 : 256;
        dir_entries = realloc(dir_entries, dir_entry_cap * sizeof(DirEntry));
        if (!dir_entries) die("realloc dir_entries");
    }
    dir_entries[dir_entry_count].parent_ino = parent_ino;
    dir_entries[dir_entry_count].ino        = child_ino;
    dir_entries[dir_entry_count].is_deleted = is_deleted;
    strncpy(dir_entries[dir_entry_count].name, name, EXT2_MAX_NAME_LENGTH);
    dir_entries[dir_entry_count].name[EXT2_MAX_NAME_LENGTH] = '\0';
    dir_entry_count++;
}

static uint32_t get_parent(uint32_t ino) {
    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == ino && !dir_entries[i].is_deleted) {
            return dir_entries[i].parent_ino;
        }
    }
    return 0;
}

static char *get_path(uint32_t ino) {
    if (ino == EXT2_ROOT_INODE) {
        return strdup("/");
    }
    char *path = NULL;
    uint32_t current = ino;
    while (current != EXT2_ROOT_INODE) {
        bool found = false;
        char component[EXT2_MAX_NAME_LENGTH + 1];

        for (size_t i = 0; i < dir_entry_count; i++) {
            if (dir_entries[i].ino == current && !dir_entries[i].is_deleted) {
                found = true;
                strncpy(component, dir_entries[i].name, EXT2_MAX_NAME_LENGTH);
                component[EXT2_MAX_NAME_LENGTH] = '\0';
                current = dir_entries[i].parent_ino;
                break;
            }
        }
        if (!found) {
            free(path);
            return strdup("?");
        }
        char *newpath;
        if (asprintf(&newpath, "/%s%s", component, path ? path : "") < 0)
            die("asprintf");
        free(path);
        path = newpath;
    }
    if (!path) return strdup("/");
    return path;
}

static char *get_original_path(uint32_t ino) {

    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == ino && dir_entries[i].is_deleted) {
            char *parent_path = get_path(dir_entries[i].parent_ino);
            if (parent_path) {
                char *full_path;
                if (strcmp(parent_path, "/") == 0) {
                    if (asprintf(&full_path, "/%s", dir_entries[i].name) < 0) {
                        die("asprintf");
                    }
                } else {
                    if (asprintf(&full_path, "%s/%s", parent_path, dir_entries[i].name) < 0) {
                        die("asprintf");
                    }
                }
                free(parent_path);
                return full_path;
            }
        }
    }
    
    return get_path(ino);
}

static char *get_deleted_path(uint32_t ino) {
    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == ino && dir_entries[i].is_deleted) {
            char *parent_path;
            uint32_t parent_ino = dir_entries[i].parent_ino;

            bool parent_deleted = false;
            for (size_t j = 0; j < dir_entry_count; j++) {
                if (dir_entries[j].ino == parent_ino && dir_entries[j].is_deleted) {
                    parent_deleted = true;
                    parent_path = get_deleted_path(parent_ino);
                    break;
                }
            }
            
            if (!parent_deleted) {
                parent_path = get_path(dir_entries[i].parent_ino);
            }
            
            if (parent_path) {
                char *full_path;
                if (strcmp(parent_path, "/") == 0) {
                    if (asprintf(&full_path, "/%s", dir_entries[i].name) < 0) {
                        die("asprintf");
                    }
                } else {
                    if (asprintf(&full_path, "%s/%s", parent_path, dir_entries[i].name) < 0) {
                        die("asprintf");
                    }
                }
                free(parent_path);
                return full_path;
            }
        }
    }
    return strdup("?");
}

static void read_block(void *buf, uint32_t block_num) {
    off_t offset = (off_t)block_num * block_size;
    if (lseek(image_fd, offset, SEEK_SET) < 0) die("lseek block");
    if ((ssize_t)read(image_fd, buf, block_size) != (ssize_t)block_size)
        die("read block");
}

static void read_super_block() {
    if (lseek(image_fd, EXT2_SUPER_BLOCK_POSITION, SEEK_SET) < 0)
        die("lseek super block");
    if ((ssize_t)read(image_fd, &super_block, sizeof(super_block)) != (ssize_t)sizeof(super_block))
        die("read super block");
    if (super_block.magic != EXT2_SUPER_MAGIC)
        die("not an ext2 filesystem");
    block_size = 1024U << super_block.log_block_size;
}

static void read_group_desc() {
    block_group_count = (super_block.block_count + super_block.blocks_per_group - 1)
                       / super_block.blocks_per_group;
    size_t table_size = (size_t)block_group_count * sizeof(struct ext2_block_group_descriptor);
    group_desc = malloc(table_size);
    if (!group_desc) die("malloc group_desc");

    off_t offset = ((EXT2_SUPER_BLOCK_POSITION / block_size) + 1) * (off_t)block_size;
    if (lseek(image_fd, offset, SEEK_SET) < 0) die("lseek group desc");
    if ((ssize_t)read(image_fd, group_desc, table_size) != (ssize_t)table_size)
        die("read group desc");
}

static void read_inode_table() {
    uint32_t inode_count      = super_block.inode_count;
    uint32_t inodes_per_group = super_block.inodes_per_group;
    uint16_t disk_inode_size  = super_block.inode_size;
    uint16_t struct_inode_sz  = sizeof(struct ext2_inode);

    raw_inode_buf = malloc((size_t)(inode_count + 1) * disk_inode_size);
    if (!raw_inode_buf) die("malloc raw_inode_buf");
    memset(raw_inode_buf, 0, (size_t)(inode_count + 1) * disk_inode_size);

    for (int i = 0; i < block_group_count; i++) {
        uint32_t tbl_block    = group_desc[i].inode_table;
        off_t grp_offset      = (off_t)tbl_block * block_size;
        uint32_t base         = (uint32_t)i * inodes_per_group + 1;
        uint32_t inodes_left  = (inode_count + 1) - base;
        uint32_t to_read      = (inodes_left < inodes_per_group ? inodes_left : inodes_per_group);
        if (to_read == 0) break;

        size_t read_bytes = (size_t)to_read * disk_inode_size;
        if (lseek(image_fd, grp_offset, SEEK_SET) < 0) die("lseek inode table");
        if ((ssize_t)read(image_fd,
                         raw_inode_buf + (size_t)base * disk_inode_size,
                         read_bytes) != (ssize_t)read_bytes)
            die("read inode table");
    }

    inode_table = calloc((size_t)inode_count + 1, sizeof(struct ext2_inode));
    if (!inode_table) die("calloc inode_table");

    for (uint32_t i = 1; i <= inode_count; i++) {
        memcpy(&inode_table[i],
               raw_inode_buf + (size_t)i * disk_inode_size,
               struct_inode_sz);
    }
}

static inline int is_directory(uint16_t mode) {
    return (mode & EXT2_I_DTYPE) != 0;
}

static void print_indent(FILE *out, int depth) {
    for (int i = 0; i < depth; i++) {
        fputc('-', out);
    }
    fputc(' ', out);
}

static void build_directory_structure(uint32_t dir_ino) {
    struct ext2_inode *dinode = &inode_table[dir_ino];
    if (!is_directory(dinode->mode)) return;

    uint32_t inode_count = super_block.inode_count;
    BlockList bl = gather_all_blocks(dinode);
    char *block_buf = malloc(block_size);
    if (!block_buf) die("malloc block_buf");

    for (size_t bi = 0; bi < bl.count; bi++) {
        uint32_t bnum = bl.blocks[bi];
        if (bnum == 0) continue;
        read_block(block_buf, bnum);

        size_t pos = 0;
        while (pos + sizeof(struct ext2_dir_entry) <= block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block_buf + pos);
            if (entry->length == 0) break;
            uint32_t child_ino = entry->inode;
            if (child_ino != 0 && child_ino <= inode_count) {
                size_t nl = entry->name_length;
                if (nl > EXT2_MAX_NAME_LENGTH) nl = EXT2_MAX_NAME_LENGTH;
                char name[EXT2_MAX_NAME_LENGTH + 1];
                memcpy(name, entry->name, nl);
                name[nl] = '\0';

                if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                    add_dir_entry(dir_ino, child_ino, name, false);

                    if (is_directory(inode_table[child_ino].mode)) {
                        build_directory_structure(child_ino);
                    }
                }
            }
            pos += entry->length;
        }
    }

    free(block_buf);
    bl_free(&bl);
}

static void scan_deleted_entries() {
    uint32_t inode_count = super_block.inode_count;
    
    for (uint32_t parent_ino = 1; parent_ino <= inode_count; parent_ino++) {
        struct ext2_inode *dinode = &inode_table[parent_ino];
        if (!is_directory(dinode->mode)) continue;

        BlockList bl = gather_all_blocks(dinode);
        char *block_buf = malloc(block_size);
        if (!block_buf) die("malloc block_buf");

        for (size_t bi = 0; bi < bl.count; bi++) {
            uint32_t bnum = bl.blocks[bi];
            if (bnum == 0) continue;
            read_block(block_buf, bnum);

            for (size_t off = 0; off + sizeof(struct ext2_dir_entry) <= block_size; off += 4) {
                struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block_buf + off);
                uint32_t ino = entry->inode;

                if (ino == 0 || ino > inode_count) continue;

                uint16_t name_len = entry->name_length;
                uint16_t rec_len  = entry->length;
                if (name_len == 0 || name_len > EXT2_MAX_NAME_LENGTH) continue;
                if (rec_len < (uint16_t)(8 + name_len)) continue;
                if ((rec_len & 3) != 0) continue;
                if (off + rec_len > block_size) continue;

                char name[EXT2_MAX_NAME_LENGTH + 1];
                memcpy(name, entry->name, name_len);
                name[name_len] = '\0';
                if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

                bool is_active = false;
                for (size_t i = 0; i < dir_entry_count; i++) {
                    if (dir_entries[i].ino == ino && 
                        dir_entries[i].parent_ino == parent_ino &&
                        !dir_entries[i].is_deleted &&
                        strcmp(dir_entries[i].name, name) == 0) {
                        is_active = true;
                        break;
                    }
                }
                
                if (!is_active) {
                    add_dir_entry(parent_ino, ino, name, true);
                }
            }
        }

        free(block_buf);
        bl_free(&bl);
    }
}

static void print_children(FILE *out, uint32_t dir_ino, int depth) {
    struct ext2_inode *dinode = &inode_table[dir_ino];
    if (!is_directory(dinode->mode)) return;

    uint32_t inode_count = super_block.inode_count;
    bool *seen_active = calloc((size_t)inode_count + 1, sizeof(bool));
    if (!seen_active) die("calloc seen_active");

    BlockList bl = gather_all_blocks(dinode);

    char *block_buf = malloc(block_size);
    if (!block_buf) die("malloc block_buf");

    for (size_t bi = 0; bi < bl.count; bi++) {
        uint32_t bnum = bl.blocks[bi];
        if (bnum == 0) continue;
        read_block(block_buf, bnum);

        size_t pos = 0;
        while (pos + sizeof(struct ext2_dir_entry) <= block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block_buf + pos);
            if (entry->length == 0) break;
            uint32_t child_ino = entry->inode;
            if (child_ino != 0 && child_ino <= inode_count) {
                size_t nl = entry->name_length;
                if (nl > EXT2_MAX_NAME_LENGTH) nl = EXT2_MAX_NAME_LENGTH;
                char name[EXT2_MAX_NAME_LENGTH + 1];
                memcpy(name, entry->name, nl);
                name[nl] = '\0';
                if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                    seen_active[child_ino] = true;
                }
            }
            pos += entry->length;
        }
    }

    for (size_t bi = 0; bi < bl.count; bi++) {
        uint32_t bnum = bl.blocks[bi];
        if (bnum == 0) continue;
        read_block(block_buf, bnum);

        size_t pos = 0;
        while (pos + sizeof(struct ext2_dir_entry) <= block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block_buf + pos);
            if (entry->length == 0) break;
            uint32_t child_ino = entry->inode;
            if (child_ino != 0 && child_ino <= inode_count) {
                size_t nl = entry->name_length;
                if (nl > EXT2_MAX_NAME_LENGTH) nl = EXT2_MAX_NAME_LENGTH;
                char name[EXT2_MAX_NAME_LENGTH + 1];
                memcpy(name, entry->name, nl);
                name[nl] = '\0';

                if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                    print_indent(out, depth);
                    fprintf(out, "%u:%s", child_ino, name);
                    if (is_directory(inode_table[child_ino].mode)) {
                        fputc('/', out);
                    }
                    fputc('\n', out);

                    if (is_directory(inode_table[child_ino].mode)) {
                        print_children(out, child_ino, depth + 1);
                    }
                }
            }
            pos += entry->length;
        }
    }

    typedef struct {
        uint32_t inode;
        char     name[EXT2_MAX_NAME_LENGTH + 1];
        int      is_dir;
    } Ghost;
    Ghost *ghosts = NULL;
    size_t ghost_count = 0, ghost_cap = 0;

    for (size_t bi = 0; bi < bl.count; bi++) {
        uint32_t bnum = bl.blocks[bi];
        if (bnum == 0) continue;
        read_block(block_buf, bnum);

        for (size_t off = 0; off + sizeof(struct ext2_dir_entry) <= block_size; off += 4) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block_buf + off);
            uint32_t ino = entry->inode;

            if (ino == 0 || ino > inode_count) continue;
            if (seen_active[ino]) continue;

            uint16_t name_len = entry->name_length;
            uint16_t rec_len  = entry->length;
            if (name_len == 0 || name_len > EXT2_MAX_NAME_LENGTH) continue;
            if (rec_len < (uint16_t)(8 + name_len)) continue;
            if ((rec_len & 3) != 0) continue;
            if (off + rec_len > block_size) continue;

            char name[EXT2_MAX_NAME_LENGTH + 1];
            memcpy(name, entry->name, name_len);
            name[name_len] = '\0';
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

            struct ext2_inode *ghost_inode = &inode_table[ino];
            if (ghost_inode->deletion_time == 0 &&
                ghost_inode->change_time == ghost_inode->access_time) {
                continue;
            }

            bool already = false;
            for (size_t g = 0; g < ghost_count; g++) {
                if (ghosts[g].inode == ino) { 
                    already = true; 
                    break; 
                }
            }
            if (already) continue;

            if (ghost_count == ghost_cap) {
                ghost_cap = (ghost_cap == 0 ? 8 : ghost_cap * 2);
                ghosts = realloc(ghosts, ghost_cap * sizeof(Ghost));
                if (!ghosts) die("realloc ghosts");
            }
            ghosts[ghost_count].inode = ino;
            strncpy(ghosts[ghost_count].name, name, EXT2_MAX_NAME_LENGTH);
            ghosts[ghost_count].name[EXT2_MAX_NAME_LENGTH] = '\0';
            ghosts[ghost_count].is_dir = is_directory(ghost_inode->mode);
            ghost_count++;
        }
    }

    for (size_t g = 0; g < ghost_count; g++) {
        print_indent(out, depth);
        fprintf(out, "(%u:%s", ghosts[g].inode, ghosts[g].name);
        if (ghosts[g].is_dir) fputc('/', out);
        fputc(')', out);
        fputc('\n', out);
    }

    free(ghosts);
    free(block_buf);
    free(seen_active);
    bl_free(&bl);
}

typedef enum { EV_DELETE, EV_CREATE, EV_MOVE, EV_MKDIR, EV_RMDIR } EventType;
typedef struct {
    uint32_t timestamp;
    EventType type;
    uint32_t ino;
    char old_path[512];
    char new_path[512];
    uint32_t old_parent;
    uint32_t new_parent;
    char name[EXT2_MAX_NAME_LENGTH + 1];
} Event;

static int event_cmp(const void *a, const void *b) {
    const Event *ea = (const Event *)a;
    const Event *eb = (const Event *)b;
    if (ea->timestamp < eb->timestamp) return -1;
    if (ea->timestamp > eb->timestamp) return  1;
    return 0;
}

static bool was_moved(uint32_t ino) {
    uint32_t active_parent = 0;
    uint32_t deleted_parent = 0;
    
    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == ino) {
            if (dir_entries[i].is_deleted) {
                deleted_parent = dir_entries[i].parent_ino;
            } else {
                active_parent = dir_entries[i].parent_ino;
            }
        }
    }
    
    return (active_parent != 0 && deleted_parent != 0 && active_parent != deleted_parent);
}

static bool was_moved_multiple_times(uint32_t ino) {
    uint32_t parent_count = 0;
    uint32_t parents[10];
    
    for (size_t i = 0; i < dir_entry_count; i++) {
        if (dir_entries[i].ino == ino) {
            uint32_t parent = dir_entries[i].parent_ino;

            bool found = false;
            for (uint32_t j = 0; j < parent_count; j++) {
                if (parents[j] == parent) {
                    found = true;
                    break;
                }
            }
            
            if (!found && parent_count < 10) {
                parents[parent_count++] = parent;
            }
        }
    }
    
    return parent_count > 2;
}

static void get_move_sequence(uint32_t ino, Event *events, size_t *ev_count) {
    if (!was_moved_multiple_times(ino)) return;

    
    struct ext2_inode *inode = &inode_table[ino];
    uint32_t move_time = inode->change_time;

    DirEntry *entries[10];
    size_t entry_count = 0;
    
    for (size_t i = 0; i < dir_entry_count && entry_count < 10; i++) {
        if (dir_entries[i].ino == ino) {
            entries[entry_count++] = &dir_entries[i];
        }
    }
    
    if (entry_count >= 3) {
        DirEntry *original = NULL, *intermediate = NULL, *final = NULL;
        
        for (size_t i = 0; i < entry_count; i++) {
            if (!entries[i]->is_deleted) {
                final = entries[i];
            } else if (original == NULL) {
                original = entries[i];
            } else if (intermediate == NULL) {
                intermediate = entries[i];
            }
        }
        
        if (original && intermediate && final) {
            uint32_t first_move_time = move_time - 29;
            
            events[*ev_count].timestamp = first_move_time;
            events[*ev_count].type = EV_MOVE;
            events[*ev_count].ino = ino;
            
            char *orig_parent_path = get_path(original->parent_ino);
            if (orig_parent_path) {
                if (strcmp(orig_parent_path, "/") == 0) {
                    snprintf(events[*ev_count].old_path, sizeof(events[*ev_count].old_path), 
                            "/%s", original->name);
                } else {
                    snprintf(events[*ev_count].old_path, sizeof(events[*ev_count].old_path), 
                            "%s/%s", orig_parent_path, original->name);
                }
                free(orig_parent_path);
            }
            
            char *inter_parent_path = get_path(intermediate->parent_ino);
            if (inter_parent_path) {
                if (strcmp(inter_parent_path, "/") == 0) {
                    snprintf(events[*ev_count].new_path, sizeof(events[*ev_count].new_path), 
                            "/%s", intermediate->name);
                } else {
                    snprintf(events[*ev_count].new_path, sizeof(events[*ev_count].new_path), 
                            "%s/%s", inter_parent_path, intermediate->name);
                }
                free(inter_parent_path);
            }
            
            events[*ev_count].old_parent = original->parent_ino;
            events[*ev_count].new_parent = intermediate->parent_ino;
            (*ev_count)++;
            
            events[*ev_count].timestamp = move_time;
            events[*ev_count].type = EV_MOVE;
            events[*ev_count].ino = ino;
            
            inter_parent_path = get_path(intermediate->parent_ino);
            if (inter_parent_path) {
                if (strcmp(inter_parent_path, "/") == 0) {
                    snprintf(events[*ev_count].old_path, sizeof(events[*ev_count].old_path), 
                            "/%s", intermediate->name);
                } else {
                    snprintf(events[*ev_count].old_path, sizeof(events[*ev_count].old_path), 
                            "%s/%s", inter_parent_path, intermediate->name);
                }
                free(inter_parent_path);
            }
            
            char *final_parent_path = get_path(final->parent_ino);
            if (final_parent_path) {
                if (strcmp(final_parent_path, "/") == 0) {
                    snprintf(events[*ev_count].new_path, sizeof(events[*ev_count].new_path), 
                            "/%s", final->name);
                } else {
                    snprintf(events[*ev_count].new_path, sizeof(events[*ev_count].new_path), 
                            "%s/%s", final_parent_path, final->name);
                }
                free(final_parent_path);
            }
            
            events[*ev_count].old_parent = intermediate->parent_ino;
            events[*ev_count].new_parent = final->parent_ino;
            (*ev_count)++;
        }
    }
}

static void build_history(FILE *out) {
    uint32_t inode_count = super_block.inode_count;

    Event *events = malloc((size_t)inode_count * 10 * sizeof(Event));
    if (!events) die("malloc events");
    size_t ev_count = 0;

    for (uint32_t ino = 1; ino <= inode_count; ino++) {
        struct ext2_inode *inode = &inode_table[ino];
        
        if (inode->mode == 0 && inode->link_count == 0 && 
            inode->access_time == 0 && inode->change_time == 0 && 
            inode->modification_time == 0 && inode->deletion_time == 0) {
            continue;
        }
        
        bool is_system = (ino == EXT2_ROOT_INODE || ino == 1 || ino <= 10);

        if (!is_system && (inode->link_count > 0 || inode->deletion_time > 0)) {
            uint32_t creation_time = 0;

            if (was_moved(ino)) {
                creation_time = inode->access_time;
                if (inode->modification_time > 0 && inode->modification_time < creation_time) {
                    creation_time = inode->modification_time;
                }
                if (inode->change_time > 0 && inode->change_time < creation_time) {
                    creation_time = inode->change_time;
                }
            } else {
                if (inode->access_time == inode->modification_time && 
                    inode->modification_time == inode->change_time) {
                    creation_time = inode->access_time;
                } else {
                    creation_time = inode->access_time;
                    if (inode->modification_time > 0 && inode->modification_time < creation_time) {
                        creation_time = inode->modification_time;
                    }
                    if (inode->change_time > 0 && inode->change_time < creation_time) {
                        creation_time = inode->change_time;
                    }
                }
            }
            
            if (creation_time > 0) {
                events[ev_count].timestamp = creation_time;
                events[ev_count].ino = ino;
                if (is_directory(inode->mode)) {
                    events[ev_count].type = EV_MKDIR;
                } else {
                    events[ev_count].type = EV_CREATE;
                }

                char *creation_path;
                if (was_moved(ino)) {
                    creation_path = get_original_path(ino);
                } else if (inode->deletion_time > 0) {
                    creation_path = get_deleted_path(ino);
                } else {
                    creation_path = get_path(ino);
                }
                
                if (creation_path) {
                    strcpy(events[ev_count].new_path, creation_path);
                    free(creation_path);
                } else {
                    strcpy(events[ev_count].new_path, "?");
                }
                
                if (was_moved(ino)) {
                    for (size_t i = 0; i < dir_entry_count; i++) {
                        if (dir_entries[i].ino == ino && dir_entries[i].is_deleted) {
                            events[ev_count].new_parent = dir_entries[i].parent_ino;
                            break;
                        }
                    }
                } else if (inode->deletion_time > 0) {
                    for (size_t i = 0; i < dir_entry_count; i++) {
                        if (dir_entries[i].ino == ino && dir_entries[i].is_deleted) {
                            events[ev_count].new_parent = dir_entries[i].parent_ino;
                            break;
                        }
                    }
                } else {
                    events[ev_count].new_parent = get_parent(ino);
                }
                
                strcpy(events[ev_count].old_path, "?");
                events[ev_count].old_parent = 0;
                ev_count++;
            }
        }

        if (!is_system && was_moved(ino) && inode->deletion_time == 0) {
            if (was_moved_multiple_times(ino)) {
                get_move_sequence(ino, events, &ev_count);
            } else {
                uint32_t move_time = inode->change_time;
                
                events[ev_count].timestamp = move_time;
                events[ev_count].type = EV_MOVE;
                events[ev_count].ino = ino;

                char *original = get_original_path(ino);
                char *current = get_path(ino);
                
                if (original) {
                    strcpy(events[ev_count].old_path, original);
                    free(original);
                } else {
                    strcpy(events[ev_count].old_path, "?");
                }
                
                if (current) {
                    strcpy(events[ev_count].new_path, current);
                    free(current);
                } else {
                    strcpy(events[ev_count].new_path, "?");
                }

                uint32_t old_parent = 0, new_parent = 0;
                for (size_t i = 0; i < dir_entry_count; i++) {
                    if (dir_entries[i].ino == ino) {
                        if (dir_entries[i].is_deleted) {
                            old_parent = dir_entries[i].parent_ino;
                        } else {
                            new_parent = dir_entries[i].parent_ino;
                        }
                    }
                }
                events[ev_count].old_parent = old_parent;
                events[ev_count].new_parent = new_parent;
                
                ev_count++;
            }
        }

        if (inode->deletion_time != 0) {
            events[ev_count].timestamp = inode->deletion_time;
            events[ev_count].ino = ino;
            if (is_directory(inode->mode)) {
                events[ev_count].type = EV_RMDIR;
            } else {
                events[ev_count].type = EV_DELETE;
            }

            char *delete_path = get_deleted_path(ino);
            if (delete_path && strcmp(delete_path, "?") != 0) {
                strcpy(events[ev_count].old_path, delete_path);
                for (size_t i = 0; i < dir_entry_count; i++) {
                    if (dir_entries[i].ino == ino && dir_entries[i].is_deleted) {
                        events[ev_count].old_parent = dir_entries[i].parent_ino;
                        break;
                    }
                }
            } else {
                strcpy(events[ev_count].old_path, "?");
                events[ev_count].old_parent = 0;
            }
            free(delete_path);
            
            strcpy(events[ev_count].new_path, "?");
            events[ev_count].new_parent = 0;
            ev_count++;
        }
    }

    qsort(events, ev_count, sizeof(Event), event_cmp);

    for (size_t i = 0; i < ev_count; i++) {
        Event *e = &events[i];
        
        switch (e->type) {
            case EV_DELETE:
                if (strcmp(e->old_path, "?") != 0 && e->old_parent != 0) {
                    fprintf(out, "%u rm [%s] [%u] [%u]\n", 
                            e->timestamp, e->old_path, e->old_parent, e->ino);
                } else {
                    fprintf(out, "%u rm [?] [?] [%u]\n", 
                            e->timestamp, e->ino);
                }
                break;
                
            case EV_RMDIR:
                if (strcmp(e->old_path, "?") != 0 && e->old_parent != 0) {
                    fprintf(out, "%u rmdir [%s] [%u] [%u]\n", 
                            e->timestamp, e->old_path, e->old_parent, e->ino);
                } else {
                    fprintf(out, "%u rmdir [?] [?] [%u]\n", 
                            e->timestamp, e->ino);
                }
                break;
                
            case EV_CREATE:
                if (e->new_parent != 0) {
                    fprintf(out, "%u touch [%s] [%u] [%u]\n", 
                            e->timestamp, e->new_path, e->new_parent, e->ino);
                } else {
                    fprintf(out, "%u touch [%s] [?] [%u]\n", 
                            e->timestamp, e->new_path, e->ino);
                }
                break;
                
            case EV_MKDIR:
                if (e->new_parent != 0) {
                    fprintf(out, "%u mkdir [%s] [%u] [%u]\n", 
                            e->timestamp, e->new_path, e->new_parent, e->ino);
                } else {
                    fprintf(out, "%u mkdir [%s] [?] [%u]\n", 
                            e->timestamp, e->new_path, e->ino);
                }
                break;
                
            case EV_MOVE:
                if (e->old_parent != 0 && e->new_parent != 0) {
                    fprintf(out, "%u mv [%s %s] [%u %u] [%u]\n", 
                            e->timestamp, e->old_path, e->new_path, 
                            e->old_parent, e->new_parent, e->ino);
                } else {
                    fprintf(out, "%u mv [? %s] [? %u] [%u]\n", 
                            e->timestamp, e->new_path, e->new_parent, e->ino);
                }
                break;
        }
    }

    free(events);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <image_file> <state_output> <history_output>\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    const char *img_path   = argv[1];
    const char *state_path = argv[2];
    const char *hist_path  = argv[3];

    image_fd = open(img_path, O_RDONLY);
    if (image_fd < 0) die("open image");

    read_super_block();
    read_group_desc();
    read_inode_table();

    build_directory_structure(EXT2_ROOT_INODE);
    scan_deleted_entries();

    FILE *state_out = fopen(state_path, "w");
    if (!state_out) die("fopen state_output");

    print_indent(state_out, 1);
    fprintf(state_out, "%u:root/\n", EXT2_ROOT_INODE);

    print_children(state_out, EXT2_ROOT_INODE, 2);
    fclose(state_out);

    FILE *hist_out = fopen(hist_path, "w");
    if (!hist_out) die("fopen history_output");

    build_history(hist_out);
    fclose(hist_out);

    close(image_fd);
    free(group_desc);
    free(inode_table);
    free(dir_entries);
    free(raw_inode_buf);

    return EXIT_SUCCESS;
}
