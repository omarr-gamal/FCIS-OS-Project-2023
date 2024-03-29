
#include <inc/lib.h>

// malloc()
//	This function use BEST FIT strategy to allocate space in heap
//  with the given size and return void pointer to the start of the allocated space

//	To do this, we need to switch to the kernel, allocate the required space
//	in Page File then switch back to the user again.
//
//	We can use sys_allocateMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls allocateMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the allocateMem function is empty, make sure to implement it.


//==================================================================================//
//============================ REQUIRED FUNCTIONS ==================================//
//==================================================================================//


#define UHEAP_MAX_PAGES ((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE)


// array with index of page number and value being the size
// of the block that was allocated to it in malloc() in bytes.
uint32 _uheap_allocation_sizes[UHEAP_MAX_PAGES];

// store for each page if it's used or not.
bool _page_used[UHEAP_MAX_PAGES];


uint32 __get_suitable_virtual_address_best_fit(uint32 size) {
	size = ROUNDUP(size, PAGE_SIZE);

	uint32 required_number_of_pages = size / PAGE_SIZE;
	uint32 uheap_total_number_of_pages = (USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE;

	uint32 current_start_page = 0;
	uint32 current_end_page = 0;
	uint32 current_number_of_pages = 0;

	uint32 best_start_page = 0;
	uint32 best_number_of_pages = 0xffffffff; //arbitrary large value.

	for (uint32 i = 0; i <= uheap_total_number_of_pages; i++) {
		if (i == uheap_total_number_of_pages) {
			if (current_number_of_pages >= required_number_of_pages && current_number_of_pages < best_number_of_pages) {
				best_number_of_pages = current_number_of_pages;
				best_start_page = current_start_page;
			}
			break;
		}
		if (!_page_used[i]) { // page is free
			if (current_number_of_pages == 0) {
				current_start_page = i;
			}
			current_number_of_pages++;
			current_end_page = i;

		} else { // page is used
			if (current_number_of_pages >= required_number_of_pages && current_number_of_pages < best_number_of_pages) {
				best_number_of_pages = current_number_of_pages;
				best_start_page = current_start_page;
			}
			current_number_of_pages = 0;
		}
	}

	if (best_number_of_pages != 0xffffffff) {
		return best_start_page * PAGE_SIZE + USER_HEAP_START; // virtual address of best_start_page.
	} else {
		return 0;
	}
}

void* malloc(uint32 size)
{
	if(!sys_isUHeapPlacementStrategyBESTFIT())
		return NULL;

	size = ROUNDUP(size, PAGE_SIZE);
	uint32 number_of_pages = size / PAGE_SIZE;

	uint32 va = __get_suitable_virtual_address_best_fit(size);

	if (va == 0)
		return NULL;

	sys_allocateMem(va, size);

	_uheap_allocation_sizes[(va - USER_HEAP_START) / PAGE_SIZE] = size;

	uint32 first_allocated_page = (va - USER_HEAP_START) / PAGE_SIZE;
	for (uint32 i = first_allocated_page; i < first_allocated_page + number_of_pages; i++) {
		_page_used[i] = 1;
	}

	return (void*) va;
}

void* smalloc(char *sharedVarName, uint32 size, uint8 isWritable)
{
	// Write your code here, remove the panic and write your code
	panic("smalloc() is not required...!!");

	// Steps:
	//	1) Implement BEST FIT strategy to search the heap for suitable space
	//		to the required allocation size (space should be on 4 KB BOUNDARY)
	//	2) if no suitable space found, return NULL
	//	 Else,
	//	3) Call sys_createSharedObject(...) to invoke the Kernel for allocation of shared variable
	//		sys_createSharedObject(): if succeed, it returns the ID of the created variable. Else, it returns -ve
	//	4) If the Kernel successfully creates the shared variable, return its virtual address
	//	   Else, return NULL

	//This function should find the space of the required range
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

void* sget(int32 ownerEnvID, char *sharedVarName)
{
	// Write your code here, remove the panic and write your code
	panic("sget() is not required ...!!");

	// Steps:
	//	1) Get the size of the shared variable (use sys_getSizeOfSharedObject())
	//	2) If not exists, return NULL
	//	3) Implement BEST FIT strategy to search the heap for suitable space
	//		to share the variable (should be on 4 KB BOUNDARY)
	//	4) if no suitable space found, return NULL
	//	 Else,
	//	5) Call sys_getSharedObject(...) to invoke the Kernel for sharing this variable
	//		sys_getSharedObject(): if succeed, it returns the ID of the shared variable. Else, it returns -ve
	//	6) If the Kernel successfully share the variable, return its virtual address
	//	   Else, return NULL
	//

	//This function should find the space for sharing the variable
	// ******** ON 4KB BOUNDARY ******************* //

	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	//change this "return" according to your answer
	return 0;
}

// free():
//	This function frees the allocation of the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from page file and main memory then switch back to the user again.
//
//	We can use sys_freeMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls freeMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the freeMem function is empty, make sure to implement it.

void free(void* virtual_address)
{
	uint32 va = ROUNDDOWN((uint32 ) virtual_address, PAGE_SIZE);

	uint32 size = _uheap_allocation_sizes[(va - USER_HEAP_START)/ PAGE_SIZE];
	uint32 number_of_pages = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;

	sys_freeMem(va, size);

	uint32 first_allocated_page = (va - USER_HEAP_START) / PAGE_SIZE;
	for (uint32 i = 0; i < number_of_pages; i++) {
		_page_used[first_allocated_page + i] = 0;
	}
}


//==================================================================================//
//============================== BONUS FUNCTIONS ===================================//
//==================================================================================//

//=============
// [1] sfree():
//=============
//	This function frees the shared variable at the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from main memory then switch back to the user again.
//
//	use sys_freeSharedObject(...); which switches to the kernel mode,
//	calls freeSharedObject(...) in "shared_memory_manager.c", then switch back to the user mode here
//	the freeSharedObject() function is empty, make sure to implement it.

void sfree(void* virtual_address)
{
	// Write your code here, remove the panic and write your code
	panic("sfree() is not required ...!!");

	//	1) you should find the ID of the shared variable at the given address
	//	2) you need to call sys_freeSharedObject()

}


//===============
// [2] realloc():
//===============

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to malloc().
//	A call with new_size = zero is equivalent to free().

//  Hint: you may need to use the sys_moveMem(uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		which switches to the kernel mode, calls moveMem(struct Env* e, uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		in "memory_manager.c", then switch back to the user mode here
//	the moveMem function is empty, make sure to implement it.

void *realloc(void *virtual_address, uint32 new_size)
{
	//TODO: [PROJECT 2023 - MS2 - [4] Bonus1] realloc() [User Side]
	// Write your code here, remove the panic and write your code
	panic("realloc() is not implemented yet...!!");
}
