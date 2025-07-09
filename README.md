# Introduction-to-Operating-Systems
This repository contains three core Operating Systems projects that explore IPC, concurrent programming, and file system internals on Linux.

## Technology Stack
- **Environment:** Linux (e.g., METU lab machines)
- **Language:** C / C++
- **Build Tools:** GNU Make, gcc/g++
- **Libraries & APIs:** POSIX IPC (pipes, sockets), `select()`/`poll()`, POSIX threads, semaphores
- **Filesystem:** EXT2 image parsing via `ext2fs.h`

## Projects Overview

1. **Multiplayer Tic-Tac-Toe Game** (`homework1/`)
   - **Stack:** Unix domain socket pairs (bidirectional pipes), non-blocking I/O with `select()`/`poll()`, process management
   - **Description:** A server for real-time, multi-process Tic-Tac-Toe. Demonstrates message protocols (`START`, `MARK`, `RESULT`, `END`), custom grid sizes, and graceful cleanup.

2. **Store Simulation** (`hw2/`)
   - **Stack:** POSIX threads (`pthread`), mutexes, semaphores, condition variables
   - **Description:** A thread-safe store library and test harness simulating suppliers and customers. Exercises synchronization primitives to enforce capacity limits and avoid deadlocks.

3. **EXT2 File System Chronology** (`homework3/`)
   - **Stack:** EXT2 filesystem headers, inode and directory parsing, timestamp analysis
   - **Description:** A tool (`histext2fs`) that reconstructs filesystem history from an ext2 image. Prints current directory tree and infers events (`touch`, `mkdir`, `rm`, `mv`) from inode timestamps.


