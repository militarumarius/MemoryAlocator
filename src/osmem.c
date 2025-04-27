// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include <block_meta.h>
#include <string.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define MMAP_TRESHOLD (128*1024)
#define SIZE_BLOCK ALIGN(sizeof(struct block_meta))
#define SIZE_PAGE 4096

void *start_heap;
int check_prealocation;

// prealocation the heap
// type = 0 - malloc
// type = 1 - calloc
void *init_heap_sbrk(int type)
{
	check_prealocation = 1;
	start_heap = sbrk(0);
	struct block_meta *heap_p = (struct block_meta *) start_heap;

	DIE(sbrk(MMAP_TRESHOLD) == (void *)-1, "sbrk failed\n");
	heap_p->next = NULL;
	heap_p->prev = NULL;
	heap_p->status = STATUS_ALLOC;
	if (!type)
		heap_p->size = MMAP_TRESHOLD - SIZE_BLOCK;
	else
		heap_p->size = SIZE_PAGE - SIZE_BLOCK;
	return (void *)((char *)start_heap + SIZE_BLOCK);
}

// allocate the first mmap block
void *init_heap_mmap(size_t size)
{
	size_t size_to_map = ALIGN(size) + SIZE_BLOCK;

	void *result = mmap(NULL, size_to_map, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

	DIE(result == MAP_FAILED, "mmap failed\n");

	struct block_meta *new_block = (struct block_meta *) result;

	new_block->size = size;
	new_block->next = NULL;
	new_block->status = STATUS_MAPPED;
	struct block_meta *start_block = (struct block_meta *) start_heap;

	start_block = new_block;
	start_block->next = start_block->prev = NULL;
	start_block->status = STATUS_MAPPED;
	start_block->size = size;
	return (void *)((char *) start_block + SIZE_BLOCK);
}

// allocate a block with sbrk
void *sbrk_alloc(size_t size)
{
	void *new_block = sbrk(0);

	struct block_meta *heap_p = (struct block_meta *) new_block;

	size_t size_to_alloc = ALIGN(size) + SIZE_BLOCK;

	DIE(sbrk(size_to_alloc) == (void *)-1, "sbrk failed\n");

	struct block_meta *contor = (struct block_meta *) start_heap;

	while (contor->next)
		contor = contor->next;
	heap_p->prev = contor;
	contor->next = heap_p;
	heap_p->size = ALIGN(size);
	heap_p->next = NULL;
	heap_p->status = STATUS_ALLOC;
	return (void *)((char *)new_block + SIZE_BLOCK);
}

// merge free blocks
void coalesce_free_blocks(void)
{
	// merge two appropiate free blocks
	struct block_meta *current = (struct block_meta *) start_heap;

	while (current && current->next) {
		if (current->status == STATUS_FREE && current->next->status == STATUS_FREE) {
			current->size = current->size + current->next->size + SIZE_BLOCK;
			if (current->next->next)
				current->next->prev = current;
			current->status = STATUS_FREE;
			current->next = current->next->next;
		} else {
			current = current->next;
		}
	}
}

// merge next free block, if this exist, for the reallocated block
void coalesce_next_free_block_realloc(struct block_meta *block)
{
	if (block->next && block->next->status == STATUS_FREE) {
		block->size = block->size + block->next->size + SIZE_BLOCK;
		if (block->next->next)
			block->next->prev = block;
		block->next = block->next->next;
	}
}

void remove_from_heap(struct block_meta *block_to_remove)
{
	if (!block_to_remove)
		return;
	if (!block_to_remove->prev) {
		start_heap = block_to_remove->next;
	} else if (!block_to_remove->next) {
		block_to_remove->prev->next = NULL;
	} else {
		block_to_remove->prev->next = block_to_remove->next;
		block_to_remove->next->prev = block_to_remove->prev;
	}
}

// allocate a new block with mmap
void *mmap_alloc(size_t size)
{
	size_t size_to_map = ALIGN(size) + SIZE_BLOCK;

	void *result = mmap(NULL, size_to_map, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

	DIE(result == MAP_FAILED, "mmap failed\n");
	struct block_meta *new_block = (struct block_meta *) result;

	new_block->size = ALIGN(size);
	new_block->next = NULL;
	new_block->status = STATUS_MAPPED;
	struct block_meta *contor = (struct block_meta *) start_heap;
	// if first element is mapped
	if (contor->status == STATUS_MAPPED) {
		while (contor->next && contor->next->status == STATUS_MAPPED)
			contor = contor->next;
		new_block->prev = contor;
		new_block->next = contor->next;
		if (contor->next->next)
			contor->next->next->prev = new_block;
		contor->next = new_block;
	} else {
		//  add new_block at the beggining at the list
		new_block->prev = NULL;
		new_block->next = contor;
		contor = (struct block_meta *) start_heap;
		contor = new_block;
	}
	return (void *)((char *)result + SIZE_BLOCK);
}

// find first free block that respects the if conditions
struct block_meta *find_free_block(size_t size)
{
	struct block_meta *current = (struct block_meta *) start_heap;

	while (current) {
		if (current->size >= ALIGN(size) && current->status == STATUS_FREE)
			return current;
	current = current->next;
	}
	return NULL;
}

// split block in two blocks, one free and one allocated
void *split_block(size_t size, struct block_meta *block_to_split)
{
	struct block_meta *new_block = (struct block_meta *)((char *)block_to_split + ALIGN(size) + SIZE_BLOCK);

	new_block->size = ALIGN(block_to_split->size - ALIGN(size) - SIZE_BLOCK);
	new_block->status = STATUS_FREE;
	new_block->next = block_to_split->next;
	new_block->prev = block_to_split;
	block_to_split->size = ALIGN(size);
	block_to_split->status = STATUS_ALLOC;
	if (block_to_split->next)
		block_to_split->next->prev = new_block;
	block_to_split->next = new_block;
	// merge free blocks after split
	coalesce_free_blocks();
	return (void *)((char *)block_to_split + SIZE_BLOCK);
}

void *realocate_last_block(size_t size, struct block_meta *last_block)
{
	size_t more_space = ALIGN(size) - last_block->size;

	DIE(sbrk(more_space) == (void *)-1, "sbrk failed\n");
	last_block->size = ALIGN(size);
	last_block->status = STATUS_ALLOC;
	return (void *)((char *) last_block + SIZE_BLOCK);
}

void *find_best_block(size_t size)
{
	struct block_meta *best_block = NULL;

	coalesce_free_blocks();
	struct block_meta *free_block = find_free_block(size);
	// find the best free block
	while (free_block) {
		if ((!best_block || (best_block->size > free_block->size &&
		free_block->size >= ALIGN(size))) && free_block->status == STATUS_FREE)
			best_block = free_block;
	free_block = free_block->next;
	}

	if (best_block && best_block->size) {
		if (best_block->size >= 1 + ALIGN(size) + SIZE_BLOCK)
			return split_block(size, best_block);
		best_block->status = STATUS_ALLOC;
		return (void *)((char *)best_block + SIZE_BLOCK);
	}
	// realocate the last free block
	struct block_meta *last_block = (struct block_meta *) start_heap;

	while (last_block->next)
		last_block = last_block->next;
	if (last_block != NULL && last_block->status == STATUS_FREE)
		return realocate_last_block(size, last_block);
	// alocate new block
	return sbrk_alloc(size);
}

void *os_malloc(size_t size)
{
	// invalid size
	if (!size)
		return NULL;
	// size to allocate
	size_t size_to_alloc = ALIGN(size) + SIZE_BLOCK;

	if (!start_heap && size_to_alloc < MMAP_TRESHOLD)
		return init_heap_sbrk(0);
	else if (!start_heap && size_to_alloc >= MMAP_TRESHOLD)
		return init_heap_mmap(size);
	else if (size_to_alloc >= MMAP_TRESHOLD)
		return mmap_alloc(size);
	else if (!check_prealocation)
		return init_heap_sbrk(0);
	else
		return find_best_block(size);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;
	ptr -= SIZE_BLOCK;
	struct block_meta *block_to_free = (struct block_meta *) ptr;

	size_t size_to_be_free = block_to_free->size + SIZE_BLOCK;

	if (block_to_free->status == STATUS_MAPPED) {
		// remove from heap
		remove_from_heap(block_to_free);
		DIE(munmap(block_to_free, size_to_be_free) == -1, "munmap() failed!\n");
	} else if (block_to_free->status == STATUS_ALLOC) {
		block_to_free->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	//  invalid size
	if (size == 0 || nmemb == 0)
		return NULL;
	// size to allocate
	void *block_calloced = NULL;

	size_t size_calloc = nmemb * size;

	size_t size_to_alloc = ALIGN(size_calloc) + SIZE_BLOCK;

	if (!start_heap && size_to_alloc < SIZE_PAGE)
		block_calloced = init_heap_sbrk(1);
	else if (!start_heap && size_to_alloc >= SIZE_PAGE)
		block_calloced = init_heap_mmap(size_calloc);
	else if (size_to_alloc >= SIZE_PAGE)
		block_calloced = mmap_alloc(size_calloc);
	else if (!check_prealocation)
		block_calloced =  init_heap_sbrk(1);
	else
		block_calloced = find_best_block(size_calloc);
	if (!block_calloced)
		return NULL;
	memset(block_calloced, 0, size_calloc);
	return block_calloced;
}

size_t get_min_size(size_t size1, size_t size2)
{
	if (size1 >= size2)
		return size2;
	return size1;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (!size) {
		os_free(ptr);
		return NULL;
	}
	ptr -= SIZE_BLOCK;
	struct block_meta *block = (struct block_meta *) ptr;

	ptr += SIZE_BLOCK;
	if (block->status == STATUS_FREE)
		return NULL;
	if (block->status == STATUS_MAPPED || ALIGN(size) + SIZE_BLOCK >= MMAP_TRESHOLD) {
		void *new_block = os_malloc(size);

		if (!new_block)
			return NULL;
		memcpy(new_block, ptr, get_min_size(ALIGN(size), block->size));
		os_free(ptr);
		return (void *)new_block;
	} else if (ALIGN(size) < block->size) {
		if (block->size >= 1 + ALIGN(size) + SIZE_BLOCK)
			return split_block(size, block);
		else
			return (void *)ptr;
	}
	// realocate the block if is the last one
	if (!block->next)
		return realocate_last_block(size, block);
	coalesce_free_blocks();
	coalesce_next_free_block_realloc(block);
	if (ALIGN(size) <= block->size) {
		if (block->size >= 1 + ALIGN(size) + SIZE_BLOCK)
			return split_block(size, block);
		else
			return (void *)ptr;
	}
	// allocate a new block
	void *new_block = os_malloc(size);

	memcpy(new_block, ptr, get_min_size(block->size, ALIGN(size)));
	os_free(ptr);
	return (void *)new_block;
}
