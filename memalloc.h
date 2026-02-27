#include <stdlib.h>
#include <stddef.h>
#include <stdalign.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

typedef struct mem_block {
    size_t block_size;
    uint8_t is_allocated;
    struct mem_block* next_b;
    uint32_t padding; // for memory alignment purposes
} mem_block;

mem_block* block_head = NULL; mem_block* block_tail = NULL; // for optimization purposes, pointer to last block in the list

static const uint8_t PLATFORM_BYTE_ALIGNMENT = alignof(max_align_t);
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* lookup_block(size_t req_size) {
    mem_block* tmp = block_head;
    while (tmp != NULL) {
        if (tmp->block_size >= req_size && !tmp->is_allocated) {
            tmp->is_allocated = 1;
            if (req_size + sizeof(mem_block) < tmp->block_size && tmp->block_size - req_size - sizeof(mem_block) >= PLATFORM_BYTE_ALIGNMENT) {
                mem_block rem_block = {0};
                rem_block.block_size = tmp->block_size - req_size - sizeof(mem_block);
                rem_block.is_allocated = 0;
                rem_block.next_b = tmp->next_b;
                mem_block* rem_block_p = (mem_block*)((char*)tmp + sizeof(mem_block) + req_size);
                *rem_block_p = rem_block;
                if (tmp->next_b == NULL) block_tail = rem_block_p;
                tmp->block_size = req_size;
                tmp->next_b = rem_block_p; // update tmp->next_b to be rem_block;
            }
            return tmp;
        }
        if (tmp->next_b == NULL) block_tail = tmp;
        tmp = tmp->next_b;
    }
    return NULL;
}

void* my_malloc(size_t size) {

    if (pthread_mutex_lock(&mutex)) return NULL;

    if (block_head == NULL) block_tail = NULL;

    size = (size + PLATFORM_BYTE_ALIGNMENT - 1) & ~(PLATFORM_BYTE_ALIGNMENT-1); // memory alignment 

    if (size == 0 || size > SIZE_MAX - sizeof(mem_block)) {
        pthread_mutex_unlock(&mutex);
        return NULL;
    }

    void* ret;
    ret = lookup_block(size);
    if (ret != NULL) {
        if (pthread_mutex_unlock(&mutex)) return NULL;
        return ((char*)ret + sizeof(mem_block)); // block already available
    }

    ret = sbrk(size + sizeof(mem_block)); // contains the address of the previous BRK in case of success
    if (ret == (void*)-1) {
        pthread_mutex_unlock(&mutex);
        return NULL;
    }

    mem_block mb = {0};
    mb.block_size = size;
    mb.is_allocated = 1;
    mb.next_b = NULL;
    *((mem_block*)ret) = mb;

    if (block_head == NULL) {
        block_head = (mem_block*)ret;
        block_tail = block_head;
    }

    else {
        block_tail->next_b = (mem_block*)ret;
        block_tail = block_tail->next_b;
    }

    if (pthread_mutex_unlock(&mutex)) return NULL;
    return (char*)ret + sizeof(mem_block);
}

void my_free(void* ptr) {
    if (ptr == NULL) return;
    mem_block* mb = (mem_block*)ptr - 1; // under the assumption that the user passed the correct address to free!
    if (pthread_mutex_lock(&mutex)) return;
    mb->is_allocated = 0;
    while (mb->next_b != NULL && !mb->is_allocated && !mb->next_b->is_allocated
        && ((char*)mb->next_b == (char*)mb + sizeof(mem_block) + mb->block_size)) { // contiguous blocks can be merged into one
                
        mb->block_size += mb->next_b->block_size + sizeof(mem_block);
        if (mb->next_b == block_tail) block_tail = mb; // update block tail
        mb->next_b = mb->next_b->next_b;
    }
    pthread_mutex_unlock(&mutex);
    return;
}

void* my_realloc(void* ptr, size_t new_size) {

    if (ptr == NULL) return my_malloc(new_size); // standard behaviour

    if (pthread_mutex_lock(&mutex)) return NULL;

    if (block_head == NULL) block_tail = NULL;

    if (new_size > SIZE_MAX - sizeof(mem_block)) { 
        pthread_mutex_unlock(&mutex);
        return NULL;
    }

    mem_block* mb = (mem_block*)ptr - 1; // we once again assume that the user has passed a previously allocated block

    new_size = (new_size + PLATFORM_BYTE_ALIGNMENT - 1) & ~(PLATFORM_BYTE_ALIGNMENT-1); // memory alignment 
 
    if (new_size == 0) {
        pthread_mutex_unlock(&mutex);
        my_free(ptr);
        return NULL;
    }

    if (new_size == mb->block_size) { 
        if (pthread_mutex_unlock(&mutex)) return NULL;
        return ptr; // no need to modify the block
    }

    if (new_size > mb->block_size && mb->next_b != NULL && !mb->next_b->is_allocated && mb->block_size + mb->next_b->block_size + sizeof(mem_block) >= new_size
        && (char*)mb + sizeof(mem_block) + mb->block_size == (char*)mb->next_b) {
        mb->block_size += (mb->next_b->block_size + sizeof(mem_block));
        mb->next_b = mb->next_b->next_b;
        if (pthread_mutex_unlock(&mutex)) return NULL;
        return ptr;
    }

    else if (new_size + sizeof(mem_block) < mb->block_size && mb->block_size - new_size - sizeof(mem_block) >= PLATFORM_BYTE_ALIGNMENT) {
        mem_block rem_block = {0};
        rem_block.block_size = mb->block_size - new_size - sizeof(mem_block);
        rem_block.is_allocated = 0;
        rem_block.next_b = mb->next_b;
        mem_block* rem_block_p = (mem_block*)((char*)mb + sizeof(mem_block) + new_size);
        *rem_block_p = rem_block;
        mb->block_size = new_size; // update block size accordingly
        mb->next_b = rem_block_p; // update mb->next_b to be rem_block;
        if (rem_block_p->next_b == NULL) block_tail = rem_block_p;
        if (pthread_mutex_unlock(&mutex)) return NULL;
        return ptr;
    }

    else { // cannot merge nor split, call my_malloc() to allocate a new block and then free the original one 
        if (pthread_mutex_unlock(&mutex)) return NULL;
        void* ret = my_malloc(new_size);
        if (ret == NULL) return NULL;
        size_t cpy_bytes = new_size > mb->block_size ? mb->block_size : new_size;
        memcpy(ret, ptr, cpy_bytes); // copy data
        my_free(ptr);
        return ret;
    }
}

void* my_calloc(size_t num_e, size_t elem_size) { // all elements initialized to 0
    if (elem_size != 0 && num_e > SIZE_MAX / elem_size) return NULL; // check for integer overflow
    void* mem_p = my_malloc(num_e * elem_size); 
    if (mem_p == NULL) return NULL;
    memset(mem_p, 0x0, num_e * elem_size);
    return mem_p;
}
