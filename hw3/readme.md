# EXT2 File System Forensics Engine

## Overview

This project implements a low-level digital forensics tool to parse EXT2 file system images and reconstruct deleted directory structures. Developed in **C**, it analyzes the **inode**, **directory entry**, and **block metadata** to rebuild both the current and deleted file hierarchy and generate an audit trail of file operations.

## Features

- Recovers deleted directory entries and reconstructs their paths
- Traverses inodes and parses direct and indirect blocks
- Detects moves, deletions, and creations of files and directories
- Generates a detailed **timeline of file system events**
- Handles singly, doubly, and triply indirect blocks
- Builds hierarchical structure from raw binary image input

## Technologies Used

- C (C99)
- Raw EXT2 filesystem parsing
- Bit-level and structure-based block inspection
- Dynamic memory and file descriptor handling
- Recursive data structure reconstruction

## How It Works

### Input

The engine takes a raw EXT2 image file and produces two outputs:
1. **State File**: Current reconstructed file/directory hierarchy
2. **History File**: Ordered list of create/move/delete events based on inode timestamps

### Architecture

- **Superblock and Group Descriptor Reading**: Determines filesystem layout
- **Inode Table Parsing**: Reads inode metadata into memory
- **Directory Traversal**: Extracts names, parent-child relationships, and active vs deleted entries
- **Deleted Entry Recovery**: Scans block padding and gaps for previously allocated directory entries
- **Path Resolution**: Rebuilds full path strings from parent inode chains
- **Event Inference**: Reconstructs high-level operations (e.g., `mv`, `rm`, `mkdir`) from inode timestamps and directory state

### Supported Operations

- `mkdir` — inferred from creation time of directory inodes
- `touch` — file creation detection from timestamps
- `rm` / `rmdir` — detected using deletion timestamps
- `mv` — inferred from changes in parent directory associations and timestamps

## Input Format

```bash
./histext2fs <image_file> <state_output> <history_output>
