# Multi-Process Real-Time Game Server

## Overview

This project implements a multi-process, real-time multiplayer Tic-Tac-Toe game server in C. The server manages multiple player processes concurrently using **Unix domain sockets**, **non-blocking I/O**, and **IPC mechanisms** (via `socketpair` and `select`). Players interact in a race-based game — **not turn-based** — where valid moves are accepted in the order received.

## Features

- Real-time multiplayer support (not turn-based)
- Dynamic grid size and win-streak configuration
- Non-blocking I/O using `select()` for concurrent communication
- Player isolation via forked processes with `execvp`
- Game state consistency across multiple players
- Graceful termination and child reaping to avoid zombie processes
- Structured communication using custom protocol messages

## Technologies Used

- C (C99)
- Unix domain sockets (`socketpair`)
- `select()` for multiplexed I/O
- Shared memory within the server process
- Process management with `fork`, `execvp`, and `waitpid`

## How It Works

### Server Initialization

- Reads the following from `stdin`:
  - Grid width and height
  - Streak size to win
  - Number of players
  - For each player: character, executable path, and arguments
- Creates a bidirectional communication channel with each player via `socketpair`
- Forks and executes each player process, redirecting their `stdin`/`stdout` to the socket

### Gameplay Loop

- Continuously monitors all player connections using `select()`
- Handles two types of player messages:
  - `START`: Player is ready — sends back current game state
  - `MARK`: Player attempts to mark a cell — server validates and updates grid
- Checks for win condition or draw after every valid move
- Sends `RESULT` or `END` messages back to players
- Notifies all players of game result and shuts down gracefully

## Message Protocol

### Client to Server

```c
typedef enum { START, MARK } cmt;

typedef struct {
    cmt type;
    coordinate position; // Used only for MARK
} cm;
