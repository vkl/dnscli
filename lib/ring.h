#ifndef  _RING_H
#define  _RING_H

#include <stdatomic.h>

typedef struct {
    void *items;
    size_t item_size;
    size_t capacity;
    atomic_size_t head;
    atomic_size_t tail;
} Ring;

int init_ring(Ring *ring, size_t item_size, size_t capacity);
void deinit_ring(Ring *ring);
void *ring_producer_slot(Ring *ring);
void *ring_consumer_slot(Ring *ring);
void ring_produce(Ring *ring);
void ring_consume(Ring *ring);

#endif