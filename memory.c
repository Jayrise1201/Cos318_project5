/* Author(s): <Your name here>
 * COS 318, Fall 2019: Project 5 Virtual Memory
 * Implementation of the memory manager for the kernel.
*/

/* memory.c
 *
 * Note: 
 * There is no separate swap area. When a data page is swapped out, 
 * it is stored in the location it was loaded from in the process' 
 * image. This means it's impossible to start two processes from the 
 * same image without screwing up the running. It also means the 
 * disk image is read once. And that we cannot use the program disk.
 *
 */

#include "common.h"
#include "kernel.h"
#include "scheduler.h"
#include "memory.h"
#include "thread.h"
#include "util.h"
#include "interrupt.h"
#include "tlb.h"
#include "usb/scsi.h"

/* Static global variables */
// Keep track of all pages: their vaddr, status, and other properties
static page_map_entry_t page_map[PAGEABLE_PAGES];

// address of the kernel page directory (shared by all kernel threads)
static uint32_t *kernel_pdir;

// allocate the kernel page tables
static uint32_t *kernel_ptabs[N_KERNEL_PTS];

//other global variables...

/* Main API */

/* Use virtual address to get index in page directory. */
uint32_t get_dir_idx(uint32_t vaddr){
  return (vaddr & PAGE_DIRECTORY_MASK) >> PAGE_DIRECTORY_BITS;
}

/* Use virtual address to get index in a page table. */
uint32_t get_tab_idx(uint32_t vaddr){
  return (vaddr & PAGE_TABLE_MASK) >> PAGE_TABLE_BITS;
}

/* TODO: Returns physical address of page number i */
uint32_t* page_addr(int i){

  // ? is this right?
  return (uint32_t*)(MEM_START + i * PAGE_SIZE);

  // page_map_entry_t page_entry = page_map[i];

  // uint32_t vaddr = page_entry.vaddr;

  // uint32_t dir_index = get_dir_idx(vaddr);

  // uint32_t tab_index = get_tab_idx(vaddr);

  // // uint32_t* dir_ptr = kernel_pdir + (sizeof(uint32_t) * dir_index);

  // // uint32_t tab_ptr = *dir_ptr;

  // // uint32_t page_ptr = tab_ptr +  (sizeof(uint32_t) * tab_index);

  // // uint32_t page = *page_ptr;

  // // similar format from set_ptab_entry_flags
  // uint32_t dir_entry = kernel_pdir[dir_index];
  // uint32_t tab_ptr = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  // uint32_t page = tab_ptr[tab_index];

  // uint32_t physical_addr = page + (vaddr & PAGE_MASK);

  // return physical_addr;
}

/* Set flags in a page table entry to 'mode' */
void set_ptab_entry_flags(uint32_t * pdir, uint32_t vaddr, uint32_t mode){
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t tab_idx = get_tab_idx((uint32_t) vaddr);
  uint32_t dir_entry;
  uint32_t *tab;
  uint32_t entry;

  dir_entry = pdir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */
  tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  /* clear table[index] bits 11..0 */
  entry = tab[tab_idx] & PE_BASE_ADDR_MASK;

  /* set table[index] bits 11..0 */
  entry |= mode & ~PE_BASE_ADDR_MASK;
  tab[tab_idx] = entry;

  /* Flush TLB because we just changed a page table entry in memory */
  flush_tlb_entry(vaddr);
}

/* Initialize a page table entry
 *  
 * 'vaddr' is the virtual address which is mapped to the physical
 * address 'paddr'. 'mode' sets bit [12..0] in the page table entry.
 *   
 * If user is nonzero, the page is mapped as accessible from a user
 * application.
 */
void init_ptab_entry(uint32_t * table, uint32_t vaddr,
         uint32_t paddr, uint32_t mode){
  int index = get_tab_idx(vaddr);
  table[index] =
    (paddr & PE_BASE_ADDR_MASK) | (mode & ~PE_BASE_ADDR_MASK);
  flush_tlb_entry(vaddr);
}

/* Insert a page table entry into the page directory. 
 *   
 * 'mode' sets bit [12..0] in the page table entry.
 */
void insert_ptab_dir(uint32_t * dir, uint32_t *tab, uint32_t vaddr, 
		       uint32_t mode){

  uint32_t access = mode & MODE_MASK;
  int idx = get_dir_idx(vaddr);

  dir[idx] = ((uint32_t)tab & PE_BASE_ADDR_MASK) | access;
}

/* TODO: Allocate a page. Return page index in the page_map directory.
 * 
 * Marks page as pinned if pinned == TRUE. 
 * Swap out a page if no space is available. 
 */
int page_alloc(int pinned){

  for(int i = 0; i < PAGEABLE_PAGES; i++){
    // find a free page_map entry to allocate
    if(page_map[i].free){
      page_map[i].pinned = pinned;
      page_map[i].free = FALSE;
      bzero(&page_map[i], PAGE_SIZE);
      return i;
    }

  }

  // nothing available in page_map so swap out
  int page_swap_index = page_replacement_policy();
  page_swap_out(page_swap_index);

  page_map[page_swap_index].pinned = pinned;
  page_map[page_swap_index].free = FALSE;

  bzero(&page_map[i], PAGE_SIZE);
  return page_swap_index;
}

/* TODO: Set up kernel memory for kernel threads to run.
 *
 * This method is only called once by _start() in kernel.c, and is only 
 * supposed to set up the page directory and page tables for the kernel.
 */
void init_memory(void){
  // set kernel page directory
  // maybe similar to page table?
  kernel_pdir = (uint32_t*)(MEM_START);
  
  page_map[0].vaddr = kernel_pdir; 
  page_map[0].free = FALSE;
  page_map[0].pinned = TRUE;

  // setup kernel page tables
  for(int i = 0; i < N_KERNEL_PTS; i++){
    uint32_t vaddr = MEM_START + PAGE_SIZE * (i+1);
    uint32_t mode = 0;
    mode |= (1 << PE_P) | (1 << PE_RW);
    // identity map for physical and virtual for kernel
    init_ptab_entry(kernel_ptabs[i], vaddr, vaddr, mode);
    // insert into page directory?
    insert_ptab_dir(kernel_pdir, kernel_ptabs[i], vaddr, mode);

    page_map[1+i].vaddr = vaddr; 
    page_map[1+i].free = FALSE;
    page_map[1+i].pinned = TRUE;
  }

  // setup rest of page_map
  for(int i = N_KERNEL_PTS+1; i < PAGEABLE_PAGES; i++){
    page_map[i].free = TRUE;
    page_map[i].pinned = FALSE;
  }

}


/* TODO: Set up a page directory and page table for a new 
 * user process or thread. */
void setup_page_table(pcb_t * p){

  int page_index = page_alloc(1);

  // ASSUME pcb->page_directory is a physical address
  p->page_directory = page_addr(page_index);

  // setup page tables for the page directory
  for(int i = 0; i < N_KERNEL_PTS; i++){
    uint32_t vaddr = MEM_START + PAGE_SIZE * (i+1);  /// CHECK IS THIS CORRECT ???
    uint32_t mode = 0;
    mode |= (1 << PE_P) | (1 << PE_RW);
    // identity map for physical and virtual for kernel
    uint32_t page_table_addr = p->page_directory + (PAGE_SIZE * (i+1));  
    init_ptab_entry(page_table_addr, vaddr, vaddr, mode);

    // insert into page directory?
    insert_ptab_dir(kernel_pdir, kernel_ptabs[i], vaddr, mode);

    page_map[1+i].vaddr = vaddr; 
    page_map[1+i].free = FALSE;
    page_map[1+i].pinned = TRUE;
  }
}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){

  int index = -1;
  for(int i = 0; i < PAGEABLE_PAGES; i++){
    // find a free page_map entry to allocate
    if(page_map[i].free){
      page_map[i].free = FALSE;
      bzero(&page_map[i], PAGE_SIZE);
      index = i;
      break;
    }
  }

  if (index == -1) {
    int page_replaced = page_replacement_policy();
    page_swap_out(page_replaced);
    return;
  }

  page_swap_in(index); // Question ?? what is index? is this the index on disk?

  return;
}

/* Get the sector number on disk of a process image
 * Used for page swapping. */
int get_disk_sector(page_map_entry_t * page){
  return page->swap_loc +
    ((page->vaddr - PROCESS_START) / PAGE_SIZE) * SECTORS_PER_PAGE;
}

/* TODO: Swap i-th page in from disk (i.e. the image file) */
void page_swap_in(int i){
   
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){
  
}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
 
}
