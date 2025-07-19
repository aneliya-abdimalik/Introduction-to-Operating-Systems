# Concurrent Inventory Management System

## Overview

This project simulates a **multithreaded inventory management system** for a store that sells three types of items: **AAA, BBB, and CCC**. The system handles concurrent **supplier and customer threads** using **POSIX threads (pthreads)**, **mutexes**, and **condition variables** to ensure synchronization and data integrity.

It models a real-world scenario where suppliers deliver bulk packages and customers place transactional batch orders, all managed under strict concurrency rules.

## Features

- Simulates real-world supplier/customer inventory interaction
- Uses **mutexes** and **condition variables** for thread synchronization
- Supports **deadlock-free**, **fair**, and **efficient** resource allocation
- Enforces inventory capacity and reservation constraints
- No busy-waiting; all synchronization is blocking-based
- Supports arbitrary number of customer and supplier threads

## Technologies Used

- C++
- POSIX Threads (`pthread`)
- Mutexes and Condition Variables

## How It Works

### Store Parameters

- `capacity[AAA/BBB/CCC]`: Max capacity for each item
- `available[AAA/BBB/CCC]`: Items currently available for sale
- `reservedStock[AAA/BBB/CCC]`: Reserved stock by pending suppliers
- `maxOrder`: Max allowed per-item count in a customer order

### Thread Behavior

#### Customer Threads

Call the `buy(countAAA, countBBB, countCCC)` function:
- Blocks if **any item** in the order is unavailable
- Deducts items in a single atomic transaction
- Notifies suppliers upon successful purchase

#### Supplier Threads

Call `maysupply(itemtype, count)` followed by `supply(itemtype, count)`:
- `maysupply`: Blocks if there isn’t enough capacity
- Reserves space immediately upon proceeding
- `supply`: Adds items to inventory and unblocks customers

### Synchronization Rules Enforced

- **Buyers block** if insufficient stock exists
- **Suppliers block** if capacity is insufficient
- No starvation: orders that can proceed are not blocked by unfulfillable ones
- **One maysupply call → One supply call** (mandatory)
- System is **deadlock-free**, **race-free**, and **non-busy waiting**

## Message API

```cpp
void initStore(int capAAA, int capBBB, int capCCC, int maxOrder);
void buy(int countAAA, int countBBB, int countCCC);
void maysupply(int itemtype, int count);
void supply(int itemtype, int count);
void monitorStore(int cap[3], int avail[3]);
