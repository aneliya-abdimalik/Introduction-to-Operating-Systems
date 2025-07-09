#include <iostream>

enum ItemType { AAA, BBB, CCC };

static int capacity[3];           
static int available[3];          
static int reservedStock[3];     
static int maxOrder;          

pthread_mutex_t storeMutex;
pthread_cond_t customerCond;
pthread_cond_t supplierCond;

void initStore(int cA, int cB, int cC, int mO) {
    capacity[AAA] = cA;
    capacity[BBB] = cB;
    capacity[CCC] = cC;

    available[AAA] = cA;
    available[BBB] = cB;
    available[CCC] = cC;

    reservedStock[AAA] = 0;
    reservedStock[BBB] = 0;
    reservedStock[CCC] = 0;

    maxOrder = mO;

    pthread_mutex_init(&storeMutex, nullptr);
    pthread_cond_init(&customerCond, nullptr);
    pthread_cond_init(&supplierCond, nullptr);
}

void buy(int aA, int aB, int aC) {
    pthread_mutex_lock(&storeMutex);

    while (aA > available[AAA] || aB > available[BBB] || aC > available[CCC]) {
        pthread_cond_wait(&customerCond, &storeMutex);
    }

    available[AAA] -= aA;
    available[BBB] -= aB;
    available[CCC] -= aC;

    pthread_cond_broadcast(&supplierCond);
    pthread_mutex_unlock(&storeMutex);
}

void maysupply(int itype, int n) {
    pthread_mutex_lock(&storeMutex);

    while (available[itype] + reservedStock[itype] + n > capacity[itype]) {
        pthread_cond_wait(&supplierCond, &storeMutex);
    }

    reservedStock[itype] += n;
    pthread_mutex_unlock(&storeMutex);
}

void supply(int itype, int n) {
    pthread_mutex_lock(&storeMutex);

    reservedStock[itype] -= n;
    available[itype] += n;

    pthread_cond_broadcast(&customerCond);
    pthread_cond_broadcast(&supplierCond);
    pthread_mutex_unlock(&storeMutex);
}

void monitorStore(int c[3], int a[3]) {
    pthread_mutex_lock(&storeMutex);
    for (int i = 0; i < 3; ++i) {
        c[i] = capacity[i];
        a[i] = available[i];
    }
    pthread_mutex_unlock(&storeMutex);
}

