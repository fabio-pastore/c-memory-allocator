# c-memory-allocator
A small C project consisting in a replica of the standard library functions malloc(), calloc(), realloc() and free(), used to dynamically allocate and free process memory. 

### Features

- Thread safety
- Architecture-specific memory alignment
- Singly linked list to keep track of both in-use and free memory blocks
- O(1) insert optimization through the use of a tail pointer
- O(n) first-fit block lookup 
- Basic block splitting and merging logic to reduce both internal and external fragmentation

**NOTE:** since this allocator employs the sbrk() system call, this header file may only be used on UNIX-like systems, such as Linux (or WSL if using Windows). If you wish to try the allocator, simply copy the header file in the working directory and add

> #include "memalloc.h"

then compile the header file with your source code file(s). 
