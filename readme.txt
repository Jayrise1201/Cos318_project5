/* Author(s): Austin Li, Jayson Badal
 * COS 318, Fall 2019: Project 5 Virtual Memory
 * Readme
*/

We did not attempt the extra credit. Everything works as expected. 

In this project, we added memory management and support for virtual memory to the kernel. Here we 
extended the provided kernel with a demand-paged virtual memory manager and restricted user processes 
to user mode privileges instead of kernel mode privileges. Specifically, we implemented virtual address 
space for user processes, page allocation, paging to and from disk and page fault handler. As a result,
each process in this project gets its own address space and is not allowed to use certain instructions 
that could be used to interfere with the rest of the system. 

Firstly, was the task of page table setup. Here, we set up a two level page table to map virtual
to physical addresses. One page memory is set aside as a directory that has 1024 entries pointing 
to the actual page tables. Each of these page tables also has 1024 entries  describing pages of 
virtual memory. Kernel threads all share the same address space and screen memory so they can use 
the same page table. Each kernel page table contains 1024 entries until the page base address of a 
page reaches MAX_PHYSICAL MEMORY. Here, we also implemented init_memory() to initially map your 
physical memory pages to run the kernel threads. Ultimately, we implemented setup_page_table() to 
load the code and data of a user process into its virtual address space. We also needed to allocate 
its pages and load the process and obtain the page directory of a task. 

Secondly, we implemented a Page Allocator in the function page_alloc() to prepare a free page of 
physical memory. If there are free pages available, we simply pick one. Otherwise, we choose a page
to page out to disk using our policy in page_replacement_policy(). Then this page is reset to be 
used again. Here, we also leveraged a mechanism for pinning pages so that some frequently accessed 
pages are never evicted. 

For the page_fault_handler(), we handle the case where a process tries to access a page that is
not currently in RAM. We proceed to find the faulting page in virtual memory. Then, we allocate a 
new page, call page_swap_in(), and update the table. This function also uses locks to ensure 
synchronization. 

We call page_swap_in() when there are no more physical pages in memory for allocation. The function
gets a page from disk and puts it in a physical memory location. We use the scsi_read() function 
to do this. The disk sector tells us where to start reading from. For the number of sectors to 
read, we compute the minimum of SECTORS_PER_PAGE (8) and the amount of sectors left (swap_loc 
+ swap_size - disk_sector). 

We call page_swap_out() when we need to evict a page from physical memory. The function first finds
the physical page’s corresponding page entry in virtual memory. Then, we check if the entry is 
dirty to determine if we need to write it to disk or not. We use the scsi_write() function to 
do the writing. Finally, we reset the mode to not present and not dirty in the page entry. 

Our page_replacement_policy() is based upon a FIFO ordering. We use an array implementation of a
queue with a head and tail pointer. Whenever a non-pinned page is allocated in physical memory,
we insert it into the queue. Page replacement will take the first thing inserted into the queue 
and remove it. This way we maintain a FIFO ordering. 
