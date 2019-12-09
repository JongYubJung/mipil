#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  char str1[16];
  char str2[16];
  char *temp;
  char *command;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  //strlcpy(str1, file_name, 16);
  //strlcpy(str2, strtok_r(str1, " ", &temp), 16);
  //str2[strlen(str2)] = '\0';
  //parse_filename(file_name, command);
  char *cpfile, *ptr;
  cpfile = (char*)malloc(sizeof(char)*256);
  strlcpy(cpfile, file_name, PGSIZE);
  command = strtok_r(cpfile, " ", &ptr);

  if (filesys_open(command) == NULL)
	  return -1;
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (command, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  //printf("\ncreated thread ID : %d\n", tid);
  return tid;
}
void 
set_esp(char *file_name, void **esp){
	char *command;
	char *argv[50], *start[50];
	char *fn_copy, *ret_ptr, *next_ptr;
	int argCnt = 0, i, templen, alllen = 0;
	// cut all arguments by space
	fn_copy = (char*)malloc(sizeof(char) * 256);
	strlcpy (fn_copy, file_name, PGSIZE);

	command = strtok_r(fn_copy, " ", &next_ptr);
	argv[argCnt] = command;
	argCnt++;
	while(1){
		ret_ptr = strtok_r(NULL, " ", &next_ptr);
		if(ret_ptr == NULL)
			break;
		argv[argCnt] = ret_ptr;

//	printf("\n\n\n%s\n\n\n", argv[argCnt]);
		argCnt++;
	}

	// argv[n][...]
		for(i = argCnt - 1; i >= 0; i--){
			templen = strlen(argv[i]) + 1;
			*esp = *esp - templen;
			start[i] = *esp;
			alllen = alllen + templen;
			strlcpy(*esp, argv[i], templen);
		}

		*esp = *esp - (4 - (alllen % 4));
	//printf("\n\n\n%d\n\n\n", alllen);
		*esp = *esp - 4;
		memset(*esp, 0, sizeof(uint32_t));
		for(i = argCnt - 1; i >= 0; i--){
			*esp = *esp - 4;
			**(uint32_t**)esp = start[i];
		}
		*esp = *esp - 4;
		**(uint32_t**)esp = *esp + 4;
		*esp = *esp - 4;
		**(uint32_t**)esp = argCnt;
		*esp = *esp - 4;
		memset(*esp, 0, sizeof(uint32_t)); 

	//	hex_dump(*esp, *esp, 100, 1);
	//	printf("\n\n\n!!!!!!!!!!!!!!!!!!\n\n\n");
	//	printf("\n\n");

}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  //---------------------------------------------
  char *realName, *ptr;
  char *tempName = (char*)malloc(sizeof(char)*256);
  strlcpy(tempName, file_name, PGSIZE);
  realName = strtok_r(tempName, " ", &ptr);
  realName[strlen(realName)] = '\0';
  //-------------------------------------------
  success = load (realName, &if_.eip, &if_.esp);

  if(success){
	  set_esp(file_name, &if_.esp);
  }
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

/*int busy_wait(struct thread *temp)
{
	if (temp->status == 3)
		return 1;
	else
		return 0;
}*/


int
process_wait (tid_t child_tid) 
{
	struct thread *t, *child, *curr = thread_current();
	int ret, cnt = 0;
	int64_t ticks = 300; 
	int flag = 0;


	struct list_elem *e = list_begin(&curr->child_list);
	int size = list_size(&thread_current()->child_list);
	for(cnt = 0; cnt < size; cnt++)
	{
	//	printf("%d %d %d\n",list_size(&curr->child_list), child_tid, list_entry(e, struct thread, child_elem)->tid);
		if (child_tid == list_entry(e, struct thread, child_elem)->tid)
		{
			flag = 1;
			break;
		}

		else
			e = list_next(e);
	}
	if (flag == 1)
	{
		child = list_entry(e, struct thread, child_elem);
	}
	else
		return -1;

	//	printf("11111111111111111111111111\n");
	//	intr_set_level(INTR_OFF);
		while(1)
		{
		//	barrier();
			if((child->status == 0)||(child->status == 1)||(child->status == 2))
				timer_sleep(1);
			else
				break;

		}
		return curr->exit_status;
}

		

	


//	printf("\nchild_tid : %d\n", child_tid);
//	printf("thread_current()->tid : %d\n", thread_current()->tid);
//	printf("thread_current()->name : %s\n", thread_current()->name);
//	printf("list_size : %d\n", list_size(&(thread_current()->child_list)));
/*	if(thread_current()->tid == 1){
		//timer_sleep(1);
		return child_tid;
	}
	else if(thread_current()->tid > 3) // child to kill
	{	printf("\n111111111111111\n");
		thread_current() -> die_flag = true;
		printf("\n22222222222222\n");
		return child_tid;
	}
	else if (thread_current()->tid == 3) // main 
	{	for(child = list_begin(&(thread_current()->child_list)); child != list_end(&(thread_current()->child_list)); child = list_next(child))
		{
			t = list_entry(child, struct thread, child_elem);
			if(t->die_flag)
				cnt++;
		}
		if(cnt == list_size(&(thread_current()->child_list)))
		{   printf("\n3333333333333333\n");
			thread_current()->die_flag = true;
			return child_tid;
		}
		timer_sleep(1);
		return child_tid;
		if (list_size(&(thread_current()->child_list)) > 0)
		{	printf("\n55555555555555\n");
			//timer_sleep(1);
			for(child = list_begin(&(thread_current()->child_list)); child != list_end(&(thread_current()->child_list)); child = list_next(child))
			{	printf("\n9999999999999\n");
				t = list_entry(child, struct thread, child_elem);
				if (t->die_flag) 
				{	
					printf("%d\n", thread_current()->tid);
					list_remove(&(t->child_elem));
				}
			}
			return child_tid;
		}
		else
		{	printf("\n66666666666666666\n");
			timer_sleep(1);
			printf("\n7777777777777777\n");
			thread_current()->die_flag = true;
			return child_tid;
		}
	}
	else{
		printf("\n88888888888\n");
		return -1;
	}*/
//	printf("00000000000000000\n");
//	for(; child->next != NULL; child = child->next)
//	{
//		t = list_entry(child, struct thread, child_elem);
	//	list_remove(&(t->child_elem));

//		if(die_flag == false){;}
//		else{
		//		if(child_tid == t->tid){
//					ret = t -> exit_status;
//					list_remove(&(t->child_elem));
//		//printf("\n\n\n%d\n\n\n", list_size(&(thread_current()->child_list)));
//					return child_tid;
		//		}
//		}

//	}
//	printf("3333333333333333\n\n");


/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;
	int flag = 0;
  int i;
  //printf("%d\n", curr->die_flag);
  printf("%s: exit(%d)\n", curr->name, curr->exit_status);
  if (curr->parent)
	  curr->parent->exit_status = curr->exit_status;

	struct list_elem *e = list_begin(&curr->parent->child_list);
	int size = list_size(&curr->parent->child_list);
	for(i = 0; i < size; i++)
	{
		if (curr->tid == list_entry(e, struct thread, child_elem)->tid)
		{
			list_remove(e);
		//	flag = 1;
			break;
		}
		else
			e = list_next(e);
	}

	//if (flag == 1)
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
 // printf("33333333333333333333333333333333\n");
 // list_entry(&(cur->child_elem), struct thread, child_elem)->die_flag = true;
//	printf("12312321thread_current()->tid : %d\n", thread_current()->tid);
//	printf("12312313list_size : %d\n", list_size(&(thread_current()->child_list)));
//	if(thread_current()->tid == 1 && list_size(&(thread_current()->child_list) > 0)){
//	}
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofset;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
//-------------------------여기서 parsing-------------------------//
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofset = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofset < 0 || file_ofset > file_length (file))
        goto done;
      file_seek (file, file_ofset);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofset += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
// ------------------------------여기서 esp------------------------//
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
 /* if (phdr->p_vaddr < PGSIZE)
    return false;*/

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *knpage = palloc_get_page (PAL_USER);
      if (knpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, knpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (knpage);
          return false; 
        }
      memset (knpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, knpage, writable)) 
        {
          palloc_free_page (knpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *th = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (th->pagedir, upage) == NULL
          && pagedir_set_page (th->pagedir, upage, kpage, writable));
}
