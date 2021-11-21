/* Author(s): Austin Li, Jayson Badal 
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
static lock_t lock;

// queue for FIFO page replacement policy
struct queue {
  int pages[PAGEABLE_PAGES];
  int head;
  int tail;
  int size;
};
// queue of pages in FIFO order to be replaced
static struct queue q; 

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
  return (uint32_t*)(MEM_START + i * PAGE_SIZE);
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
  int i;

  for(i = 0; i < PAGEABLE_PAGES; i++){
    // find a free page_map entry to allocate
    if(page_map[i].free){
      page_map[i].pinned = pinned;
      page_map[i].free = FALSE;

      // zero out the memory at physical addr 
      bzero((char*)page_addr(i), PAGE_SIZE);

      // page replacement policy queue
      if(!pinned){
        q.pages[q.head] = i;
        q.size++;
        q.head = (q.head + 1) % PAGEABLE_PAGES;
      }

      return i;
    }

  }

  // nothing available in page_map so swap out
  int page_swap_index = page_replacement_policy();
  page_swap_out(page_swap_index);

  page_map[page_swap_index].pinned = pinned;
  page_map[page_swap_index].free = FALSE;

  // zero out here too at physical addr
  bzero((char*)page_addr(page_swap_index), PAGE_SIZE);

  // page replacement policy queue
  if(!pinned){
    q.pages[q.head] = page_swap_index;
    q.size++;
    q.head = (q.head + 1) % PAGEABLE_PAGES;
  }

  return page_swap_index;
}

/* TODO: Set up kernel memory for kernel threads to run.
 *
 * This method is only called once by _start() in kernel.c, and is only 
 * supposed to set up the page directory and page tables for the kernel.
 */
void init_memory(void){
  int i;
  uint32_t temp_mem;

  // inititalize lock
  lock_init(&lock);
  // initialize queue
  q.head = 0;
  q.tail = 0;
  q.size = 0;

  // do at beginning of function over all page_map
  for(i = 0; i < PAGEABLE_PAGES; i++){
    page_map[i].free = TRUE;
    page_map[i].pinned = FALSE;
  }

  // allocate a page
  int page_dir_index = page_alloc(TRUE);
  // then physical memory address is pdir
  kernel_pdir = page_addr(page_dir_index);
  page_map[page_dir_index].vaddr = (uint32_t)kernel_pdir; 
  page_map[page_dir_index].pdir = kernel_pdir;

  // setup kernel page tables
  for(i = 0; i < N_KERNEL_PTS; i++){

    // allocate page
    int page_table_index = page_alloc(TRUE);
    // set the physical memeory entry in array (like pdir)
    // kernel_ptabs[i] = physical addr
    kernel_ptabs[i] = page_addr(page_table_index);

    // set up entry in pdir for each table (needs mode), use insert_ptab_dir
    uint32_t mode = 0;
    mode |= PE_P;
    // identity map for physical and virtual for kernel
    // insert into page directory ?? is second arg correct?
    insert_ptab_dir(kernel_pdir, kernel_ptabs[i], (uint32_t)kernel_ptabs[i], mode);

    page_map[page_table_index].vaddr = (uint32_t)kernel_ptabs[i];
    page_map[page_table_index].pdir = kernel_pdir;
  }
  // map in all of 0-MAX PHYSICAL MEMORY
  for(temp_mem = 0; temp_mem < MAX_PHYSICAL_MEMORY; temp_mem += PAGE_SIZE){
    uint32_t mode = 0;
    mode |= PE_P;
    init_ptab_entry(kernel_ptabs[0], temp_mem, temp_mem, mode);
  }

  // screen address page
  uint32_t mode = 0;
  mode |= PE_P | PE_RW | PE_US;
  set_ptab_entry_flags(kernel_pdir, SCREEN_ADDR, mode);
}


/* TODO: Set up a page directory and page table for a new 
 * user process or thread. */
void setup_page_table(pcb_t * p){
  lock_acquire(&lock);
  // kernel thread
  if(p->is_thread){
    // same page directory as kernel (all shared)
    p->page_directory = kernel_pdir;
  }
  else{  // user process

    // set up two page tables for each user process 
    // one for code and data, one for stack

    // get a location to put a new page directory
    int page_index = page_alloc(TRUE);
  
    // pcb->page_directory is a physical address
    p->page_directory = page_addr(page_index);

    // PROCESS_START
    // allocate a page for this table
    page_index = page_alloc(TRUE);

    // physical memory address
    uint32_t* page_table_addr = page_addr(page_index);
    uint32_t vaddr = PROCESS_START;
    uint32_t mode = 0;
    mode |= PE_P | PE_RW | PE_US;

    insert_ptab_dir(p->page_directory, page_table_addr, vaddr, mode);
    page_map[page_index].vaddr = vaddr;
    page_map[page_index].pdir = p->page_directory;

    // PROCESS_STACK
    // allocate a page for this table
    page_index = page_alloc(TRUE);
    // physical memory address
    page_table_addr = page_addr(page_index);
    vaddr = PROCESS_STACK;
    insert_ptab_dir(p->page_directory, page_table_addr, vaddr, mode);
    page_map[page_index].vaddr = vaddr;
    page_map[page_index].pdir = p->page_directory;

    int i; 
    for(i = 0; i < N_PROCESS_STACK_PAGES; i++) {
      
      page_index = page_alloc(TRUE);
      vaddr = PROCESS_STACK - (PAGE_SIZE * (i));  // here

      init_ptab_entry(page_table_addr, vaddr, (uint32_t) page_addr(page_index),mode);
      
    }

    // special case- user process will have an entry in its dir that points to kernel table
    insert_ptab_dir(p->page_directory,kernel_ptabs[0], (uint32_t) kernel_ptabs[0], mode);
  }

  lock_release(&lock);

}

/* TODO: Swap into a free page upon a page fault.
 * This method is called from interrupt.c: exception_14(). 
 * Should handle demand paging.
 */
void page_fault_handler(void){
  lock_acquire(&lock);
  // increment page fault count
  current_running->page_fault_count++;

  uint32_t* page_dir = current_running->page_directory;
  uint32_t vaddr = current_running->fault_addr;
  // get directory index from fault addr
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t dir_entry = page_dir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */
  uint32_t *tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  // allocate a page 
  int page_index = page_alloc(FALSE);
  // set page map entry
  page_map[page_index].vaddr = vaddr;
  page_map[page_index].swap_loc = current_running->swap_loc;
  page_map[page_index].swap_size = current_running->swap_size;
  page_map[page_index].pdir = page_dir;
  // load contents from disk
  page_swap_in(page_index);
  // vaddr is the faulting address
  // physical address is the newly allocated page
  // update page table
  uint32_t mode = 0;
  mode |= PE_P | PE_RW | PE_US;
  init_ptab_entry(tab, vaddr, (uint32_t)page_addr(page_index), mode);
  lock_release(&lock);
}

/* Get the sector number on disk of a process image
 * Used for page swapping. */
int get_disk_sector(page_map_entry_t * page){
  return page->swap_loc +
    ((page->vaddr - PROCESS_START) / PAGE_SIZE) * SECTORS_PER_PAGE;
}

/* TODO: Swap i-th page in from disk (i.e. the image file) */
void page_swap_in(int i) {

  // min(swap_size + swap_loc - get_disk_sector, 8)
  int block_count = SECTORS_PER_PAGE;
  int disk_sector = get_disk_sector(&page_map[i]);
  int sectors = current_running->swap_size + current_running->swap_loc - disk_sector;
  if(sectors < block_count){
    block_count = sectors;
  }

  // read page from disk into respective page at physical memory 
  int check  = scsi_read(disk_sector, block_count, (char *) page_addr(i));
  ASSERT(check == 0);
}

/* TODO: Swap i-th page out to disk.
 *   
 * Write the page back to the process image.
 * There is no separate swap space on the USB.
 * 
 */
void page_swap_out(int i){

  // find in table
  uint32_t vaddr = page_map[i].vaddr;
  uint32_t* page_dir = page_map[i].pdir;
  // get directory index and entry
  uint32_t dir_idx = get_dir_idx((uint32_t) vaddr);
  uint32_t dir_entry = page_dir[dir_idx];
  ASSERT(dir_entry & PE_P); /* dir entry present */

  // get table index and table entry
  uint32_t *tab = (uint32_t *) (dir_entry & PE_BASE_ADDR_MASK);
  uint32_t tab_idx = get_tab_idx((uint32_t) vaddr);
  uint32_t entry = tab[tab_idx];

  
  // set to not present and not dirty
  uint32_t mode = entry & MODE_MASK; 
  mode &= (~PE_P);
  set_ptab_entry_flags(page_dir, vaddr, mode);


  // only write back if dirty
  if(entry & MODE_MASK & PE_D){
    // min(swap_size + swap_loc - get_disk_sector, 8)
    int block_count = SECTORS_PER_PAGE;
    int disk_sector = get_disk_sector(&page_map[i]);
    int sectors = page_map[i].swap_size + page_map[i].swap_loc - disk_sector;
    if(sectors < block_count){
      block_count = sectors;
    }
    int check = scsi_write(disk_sector, block_count, (char *) page_addr(i));
    ASSERT(check == 0);
  }

  flush_tlb_entry(vaddr);

}


/* TODO: Decide which page to replace, return the page number  */
int page_replacement_policy(void){
  ASSERT(q.size > 0);
  int page_replace_index = q.pages[q.tail];
  // update queue
  q.size--;
  q.tail = (q.tail + 1) % PAGEABLE_PAGES;
  
  return page_replace_index;
}
