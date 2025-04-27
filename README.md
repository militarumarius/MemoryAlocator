# Custom Memory Allocator

## Overview

This project implements a custom dynamic memory allocator in C, providing functionality similar to the standard `malloc()`, `calloc()`, `realloc()`, and `free()` functions. It handles memory management using two main strategies:
- **Heap expansion** via `sbrk()`
- **Memory mapping** via `mmap()`

The allocator is optimized for small and large allocations, supporting memory block splitting, coalescing free blocks, and minimizing fragmentation.

## Features

- **`os_malloc(size_t size)`**:  
  Allocates a block of memory of the specified `size`.  
  - Small allocations (less than 128KB) use `sbrk()` to extend the heap.
  - Large allocations (128KB or more) use `mmap()` to directly map memory pages.

- **`os_free(void *ptr)`**:  
  Frees a previously allocated memory block.  
  - For `mmap`-ed blocks, it unmaps the memory using `munmap()`.
  - For heap-allocated blocks, it marks them as free and allows coalescing.

- **`os_calloc(size_t nmemb, size_t size)`**:  
  Allocates memory for an array of `nmemb` elements, each of `size` bytes, and initializes all bytes to zero.

- **`os_realloc(void *ptr, size_t size)`**:  
  Changes the size of the memory block pointed to by `ptr` to the new `size`.
  - If possible, it resizes in-place.
  - If resizing in-place isn't possible, a new block is allocated and the old data is copied.

- **Block Management**:
  - **Block Metadata**: Each block has metadata (`block_meta`) containing its size, status (allocated/free/mapped), and links to adjacent blocks.
  - **Splitting**: Larger blocks are split into smaller blocks when possible to minimize waste.
  - **Coalescing**: Free blocks are merged together to reduce fragmentation.

- **Heap Preallocation**:
  - When the heap is initialized with `sbrk()`, a large block (128KB) or a page (4KB) is preallocated depending on the first allocation (`malloc` or `calloc`).
  - Future allocations will reuse this preallocated memory if possible.

## Constants and Macros

- `ALIGNMENT = 8`: Ensures all memory blocks are 8-byte aligned.
- `MMAP_TRESHOLD = 128 * 1024`: Allocations larger than 128KB use `mmap`.
- `SIZE_PAGE = 4096`: Standard page size for memory allocation.

## Files

- **`osmem.h`**: Header file with allocator declarations.
- **`block_meta.h`**: Defines the metadata structure for memory blocks.
- **Implementation file** (this one): Contains all memory management functions.

## Memory Allocation Strategy

1. **First Allocation**:
   - If no memory has been allocated yet, initialize the heap.
   - Small allocations use `sbrk()`, large ones use `mmap()`.

2. **Subsequent Allocations**:
   - Try to find a free block.
   - If not possible, extend the heap (`sbrk`) or allocate a new memory mapping (`mmap`).

3. **Freeing Memory**:
   - Mark heap blocks as free and attempt to merge adjacent free blocks.
   - Completely unmap `mmap`-allocated memory.

4. **Reallocating Memory**:
   - If there is enough adjacent space, expand the block in-place.
   - Otherwise, allocate a new block and move the data.

## Known Limitations

- This implementation does not shrink the heap when memory is freed.
- Fragmentation can still occur if many different-sized blocks are allocated and freed.
- Thread safety is not implemented (no synchronization).
