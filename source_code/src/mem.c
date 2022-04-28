
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct
{
	uint32_t proc; // ID of process currently uses this page

	int index;	   // Index of the page in the list of pages allocated to the process.

	int next;	   // The next page in the list. -1 if it is the last page.

} _mem_stat[NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void)
{
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);  //fill all _mem_stat by 0;
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);   //fill all _ram by 0;
	pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr)
{
	return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr)
{
	return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr)
{
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t *get_page_table(
	addr_t index, // Segment level index
	struct seg_table_t *seg_table)
{ // first level table

	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [seg_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < seg_table->size; i++)
	{
		// Enter your code here
		if (seg_table->table[i].v_index == index)
		{
			return seg_table->table[i].pages;
		}
	}
	return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
	addr_t virtual_addr,   // Given virtual address
	addr_t *physical_addr, // Physical address to be returned
	struct pcb_t *proc)
{ // Process uses given virtual address

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);
	/* Search in the first level */
	struct page_table_t *page_table = NULL;
	page_table = get_page_table(first_lv, proc->seg_table);
	if (!page_table)
	{
		return 0;
	}

	int i;
	for (i = 0; i < page_table->size; i++)
	{
		if (page_table->table[i].v_index == second_lv)
		{
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of page_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			addr_t p_index;
			p_index = page_table->table[i].p_index;
			*physical_addr = (p_index << OFFSET_LEN) | (offset);
			return 1;
		}
	}
	return 0;
}
int check(int num_pages, struct pcb_t *proc)
{
	//num_pages is number of pages will be use
	int free_pages = 0, mem_avail;
	for (int i = 0; i < NUM_PAGES; i++)
	{
		if (_mem_stat[i].proc == 0)
		{
			free_pages++;
			if (free_pages == num_pages)
				break;
		}
	}
	if (free_pages >= num_pages)
	{
		if ((proc->bp + num_pages * PAGE_SIZE) < RAM_SIZE)   //PAGE_SIZE = 1024 byte
			mem_avail = 1;
	};
	return mem_avail;
}

addr_t alloc_mem(uint32_t size, struct pcb_t *proc)
{
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	/* 
	 * TODO: Allocate [size] byte in the memory for the process [proc] and 
	 * save the address of the first byte in the allocated memory region to [ret_mem].
	 */

	// Number of pages we will use for this process
	uint32_t num_pages = (size % PAGE_SIZE) ? size / PAGE_SIZE : size / PAGE_SIZE + 1; // Number of pages we will use
	num_pages++;
	int mem_avail = 0;
	mem_avail = check(num_pages, proc);
	if (mem_avail)
	{
		ret_mem = proc->bp;
		proc->bp += num_pages * PAGE_SIZE;
		int allo_pages = 0, last = -1, index;
		for (int i = 0; i < NUM_PAGES; ++i)
		{
			if (_mem_stat[i].proc)
				continue;

			_mem_stat[i].proc = proc->pid;
			_mem_stat[i].index = allo_pages;

			if (last > -1)
			{
				_mem_stat[last].next = i;
			};
			last = i;
			addr_t v_address = ret_mem + allo_pages * PAGE_SIZE;
			addr_t v_segment = get_first_lv(v_address);
			struct page_table_t *v_table = get_page_table(v_segment, proc->seg_table);
			if (!v_table)
			{
				index = proc->seg_table->size;
				proc->seg_table->table[index].v_index = v_segment;
				v_table = proc->seg_table->table[index].pages = (struct page_table_t *)malloc(sizeof(struct page_table_t));
				proc->seg_table->size++;
			}
			index = v_table->size++;
			v_table->table[index].v_index = get_second_lv(v_address);
			v_table->table[index].p_index = i;
			allo_pages++;
			if (allo_pages == num_pages)
			{
				_mem_stat[i].next = -1;
				break;
			}
		}
	};
	//printf("---------Allocation---------\n");
	//dump();

	pthread_mutex_unlock(&mem_lock);
	return ret_mem;
}

int free_mem(addr_t address, struct pcb_t *proc)
{
	/**
	 * TODO: Release memory region allocated by [proc]. 
	 * The first byte of this region is indicated by [address]. 
	 * Tasks to do:
	 * 	+ Set flag [proc] of physical page use by the memory block 
	 * 	+ back to zero to indicate that it is free.
	 * 	+ Remove unused entries in segment table and page tables of the process [proc].
	 * 	+ Remember to use lock to protect the memory from other processes.
	 */
	pthread_mutex_lock(&mem_lock);
	addr_t v_addr, p_addr, p_seg_pindex, v_page, v_seg, last_addr, last_seg, last_page;

	v_addr = address;
	p_addr = 0;
	if (!translate(v_addr, &p_addr, proc))
		return 1;
	p_seg_pindex = p_addr >> OFFSET_LEN;
	int num_pages = 0;
	for (int i = p_seg_pindex; i != -1; i = _mem_stat[i].next)
	{
		num_pages++;
		_mem_stat[i].proc = 0;
	}
	for (int i = 0; i < num_pages; i++)
	{
		v_addr = v_addr + i * PAGE_SIZE;
		v_page = get_second_lv(v_addr);
		v_seg = get_first_lv(v_addr);
		struct page_table_t *p_table;
		p_table = get_page_table(v_seg, proc->seg_table);
		if (!p_table)
			continue;
		for (int j = 0; j < p_table->size; j++)
		{
			if (p_table->table[j].v_index == v_page)
			{
				int last = --p_table->size;
				p_table->table[j] = p_table->table[last];
				break;
			}
		}
		if (p_table->size == 0)
		{
			if (!proc->seg_table)
				break;
			for (int i = 0; i < proc->seg_table->size; i++)
			{
				if (proc->seg_table->table[i].v_index == v_seg)
				{
					int idx = proc->seg_table->size - 1;
					proc->seg_table->table[i] = proc->seg_table->table[idx];
					proc->seg_table->table[idx].v_index = 0;
					free(proc->seg_table->table[idx].pages);
					proc->seg_table->size--;
					break;
				};
			}
			break;
		}
	}
	if (v_addr + num_pages * PAGE_SIZE == proc->bp)
	{
		while (proc->bp >= PAGE_SIZE)
		{
			last_addr = proc->bp - PAGE_SIZE;
			last_seg = get_first_lv(last_addr);
			last_page = get_second_lv(last_addr);
			struct page_table_t *p_table;
			p_table = get_page_table(last_seg, proc->seg_table);
			if (!p_table)
				break;
			for (int i = 0; i < p_table->size; i++)
			{
				if (p_table->table[i].v_index == last_page)
				{
					proc->bp -= PAGE_SIZE;
					last_page--;
					break;
				}
				if (last_page < 0)
					break;
			}
			if (last_page >= 0)
				break;
		}
	};
	//printf("---------Deallocation---------\n");
	//dump();
	pthread_mutex_unlock(&mem_lock);
	return 0;
}

int read_mem(addr_t address, struct pcb_t *proc, BYTE *data)
{
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc))
	{
		*data = _ram[physical_addr];
		return 0;
	}
	else
	{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t *proc, BYTE data)
{
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc))
	{
		_ram[physical_addr] = data;
		return 0;
	}
	else
	{
		return 1;
	}
}

void dump(void)
{
	int i;
	for (i = 0; i < NUM_PAGES; i++)
	{
		if (_mem_stat[i].proc != 0)
		{
			printf("%03d: ", i);
			printf("%05x - %05x - PID: %02d (index %03d, next: %03d)\n",
				   (i << OFFSET_LEN),
				   ((i + 1) << OFFSET_LEN) - 1,
				   _mem_stat[i].proc,
				   _mem_stat[i].index,
				   _mem_stat[i].next);
			int j;
			for (j = i << OFFSET_LEN;
				 j < ((i + 1) << OFFSET_LEN) - 1;
				 j++)
			{

				if (_ram[j] != 0)
				{
					printf("\t%05x: %02x\n", j, _ram[j]);
				}
			}
		}
	}
}
