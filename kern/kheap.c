#include <inc/memlayout.h>
#include <kern/kheap.h>
#include <kern/helpers.h>
#include <kern/memory_manager.h>

//NOTE: All kernel heap allocations are multiples of PAGE_SIZE (4KB)

#define MAX_BLOCK_SIZES ((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE)


// this array will have index of page number and store the size of the
// block(number of pages) that was allocated to it in kmalloc.
uint32 block_sizes[MAX_BLOCK_SIZES];

uint32 frame_virtual_addresses[131073]; // maximum frame number as in number_of_frames.

void* kmalloc(unsigned int size)
{
    // Allocate memory in multiples of PAGE_SIZE (4KB)
    size = ROUNDUP(size, PAGE_SIZE);

    // Search for a free block of memory using first-fit strategy
    uint32 i, j, count = 0;
    for (i = KERNEL_HEAP_START; i < KERNEL_HEAP_MAX; i += PAGE_SIZE) {
    	uint32 *ptr_frame_page_table = NULL;
        if (get_frame_info(ptr_page_directory, (uint32*) i, &ptr_frame_page_table) == 0) {
            count += PAGE_SIZE;
        } else {
            count = 0;
        }

        if (count >= size) {
            // Allocate free frames for the required size
            uint32 start = ROUNDDOWN(i - count + PAGE_SIZE, PAGE_SIZE);
            for (j = start; j < start + size; j += PAGE_SIZE) {
            	struct Frame_Info * frames_info_ptr = NULL;

            	allocate_frame(&frames_info_ptr);
            	map_frame(ptr_page_directory, frames_info_ptr, (void *)j, PERM_WRITEABLE);

            	frame_virtual_addresses[to_frame_number(frames_info_ptr)] = j;
            }

            // store block size (as number of pages) to use in kfree
            block_sizes[(start - KERNEL_HEAP_START) / PAGE_SIZE] = size / PAGE_SIZE;

            // Return the starting virtual address of the allocated memory block
            return (void*)start;
        }
    }
    // Memory allocation failed
    return NULL;
}

void kfree(void* virtual_address)
{
	uint32 page_count = block_sizes[((int32 ) virtual_address - KERNEL_HEAP_START)/ PAGE_SIZE];

	uint32 vAddress = ROUNDDOWN((int32)virtual_address, PAGE_SIZE);
	for(uint32 i = 0; i < page_count ; i++) {
		uint32 *ptr_page_table = NULL;
		struct Frame_Info *ptr_frame_info = get_frame_info(ptr_page_directory, (void*)vAddress, &ptr_page_table);
		if (ptr_frame_info != 0) {
			free_frame(ptr_frame_info);

			frame_virtual_addresses[to_frame_number(ptr_frame_info)] = 0;
		}

		unmap_frame(ptr_page_directory, (void*) vAddress);

		vAddress += PAGE_SIZE;
	}
}

unsigned int kheap_virtual_address(unsigned int physical_address)
{
	uint32 pa = ROUNDDOWN(physical_address, PAGE_SIZE);

	struct Frame_Info* ptr_frame_info = to_frame_info(physical_address);
	uint32 frame_number = to_frame_number(ptr_frame_info);

	if (frame_virtual_addresses[frame_number])
		return frame_virtual_addresses[frame_number] + (physical_address - pa);
	else
		return 0;
}

unsigned int kheap_physical_address(unsigned int virtual_address)
{
	uint32* ptr_page_table = NULL;
	get_page_table(ptr_page_directory, (void *)virtual_address, &ptr_page_table);
	if (ptr_page_table != NULL) {
		uint32 table_entry = ptr_page_table[PTX(virtual_address)];

		return (table_entry & 0xFFFFF000) + (virtual_address & 0x00000FFF);
	}

	return 0;
}


//=================================================================================//
//============================== BONUS FUNCTION ===================================//
//=================================================================================//
// krealloc():

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to kmalloc().
//	A call with new_size = zero is equivalent to kfree().

void *krealloc(void *virtual_address, uint32 new_size)
{
	panic("krealloc() is not implemented yet...!!");
	return NULL;

}
