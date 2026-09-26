#include <stdlib.h>
#include <stdio.h>

#include "ring.h"

int
init_ring(Ring *ring, size_t item_size, size_t capacity)
{
    int ret = -1;

    if ((ring == NULL) || (item_size == 0) || (capacity < 2)) {
        goto out;
    }
    ring->item_size = item_size;
    ring->capacity = capacity;
    ring->head = 0;
    ring->tail = 0;
    ret = 0;
    ring->items = malloc(item_size * capacity);
    if (!ring->items) {
        perror("memory error");
        ret = -1;
    }

out:
    return ret;
}

void
deinit_ring(Ring *ring)
{
    free(ring->items);

out:
    return;
}

void *
ring_producer_slot(Ring *ring)
{
    size_t head = atomic_load_explicit(&ring->head,
            memory_order_relaxed);
    size_t next = (head + 1) % ring->capacity;
    size_t tail = atomic_load_explicit(
            &ring->tail, memory_order_acquire);
    if (next == tail)
        return NULL;       // full
    return (unsigned char *)ring->items + head * ring->item_size;
}

void
ring_produce(Ring *ring)
{
    size_t head = atomic_load_explicit(&ring->head,
                                       memory_order_relaxed);
    size_t next = (head + 1) % ring->capacity;
    atomic_store_explicit(&ring->head,
                          next,
                          memory_order_release);
}

void *
ring_consumer_slot(Ring *ring)
{
    size_t tail = atomic_load_explicit(&ring->tail,
            memory_order_relaxed);
    size_t head = atomic_load_explicit(&ring->head,
            memory_order_acquire);
    if (tail == head)
        return NULL;       // empty
    return (unsigned char *)ring->items + tail * ring->item_size;
}

void
ring_consume(Ring *ring)
{
    size_t tail = atomic_load_explicit(&ring->tail,
            memory_order_relaxed);
    size_t next = (tail + 1) % ring->capacity;
    atomic_store_explicit(&ring->tail, next, memory_order_release);
}
