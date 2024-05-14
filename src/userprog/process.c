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
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

// starts a new thread running a user program loaded from the specified file name
// creates a copy of the file name to avoid race conditions
// creates a new thread to execute the file name using thread_create
// on failure, frees the allocated memory and returns TID_ERROR
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;
  /* Allocates a page for the file name using palloc_get_page */
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  // create child thread that runs function start_process with the file name as an argument
  // which means from this point we will have parent thread and child thread
// CHILD AND PARENT COMMUNICATION IS CREATED HERE
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);  // it creates child as thread* t
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  /* ------------------------ ADDED ------------------------ */
  /* wait for the child to be created successfully here and return pid if success */

  /* After creating a new thread, the parent process waits for the child process to signal whether it was created successfully using sema_down */
  /* Depending on the success flag isChildCreationSuccess, it returns the new thread's ID or an error. */
  sema_down(&thread_current()->semaChildSync);
  if (thread_current()->isChildCreationSuccess)
  {
    return tid;
  }
  else
  {
    return TID_ERROR;
  }
  /* ------------------------ ADDED ------------------------ */
}

/* A thread function that loads a user process and starts it
   running. */

// initializes the interrupt frame and loads the executable
// parse the file name and then use load to load the executable 
// loads the executable file name and sets the success flag to true
// if the load is successful, adds the child to the list of children
// if the load is successful, signals the parent that the child is created successfully and wakes it up
// if the load is not successful, signals the parent that the child is not created successfully and wakes it up
// if loading fails, frees the allocated memory and exits the thread
// if loading succeeds, sets up the user process stack and starts the process by simulating a return from an interrupt

static void
start_process(void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // calls load to load the executable file name into memory and sets the success flag to true
  success = load(file_name, &if_.eip, &if_.esp);

  /* ------------------------ ADDED ------------------------ */

  /* parent thread/process */
  struct thread *parent = thread_current()->parent;
  // use the communication link to return the success of creation to parent, insert child into parent list, push arguments into stack, then wake up the parent and block the child
  if (success)
  {
    // If successful, the child process is added to the parent's list of children
    // Signals the parent that the child was created successfully and waits for the parent to proceed
    /* the list of children for the current parent thread/process */
    struct list *children = &parent->children;

    /* current child thread  */
    struct thread *child = thread_current();

    /* add the child to the parent's list of children */
    list_push_back(children, &child->elemChild);

    /* set the child to true that it's created successfully */
    parent->isChildCreationSuccess = 1;

    /* signal the parent that the child is created successfully and wake it up */
    sema_up(&parent->semaChildSync);

    /* wait for the parent to execute the child or wakes it up  in other words,
    the cild waits for the parent to alllow it to proceed using sema_down */
    sema_down(&thread_current()->semaChildSync);
  }
  else
  {
    // If loading fails, signals the parent of the failure and exits the thread
    /* set the child to false that it's not created successfully */
    parent->isChildCreationSuccess = 0;

    /* signal the parent that the child is not created successfully and wake it up */
    sema_up(&parent->semaChildSync);
  }

  /* ------------------------ ADDED ------------------------ */

  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (!success)
    thread_exit();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t tid) // This function waits for a child thread to die and returns its exit status
{
  /* ------------------------ ADDED ------------------------ */
  // while (true)
  // {
  //   thread_yield();
  // }

  /* set childWaiting to tid of thread to wait for */
  thread_current()->waitingForChild = tid;

  /* get the child thread with the given tid */
  struct thread *child = getChildThread(tid);

  if (child == NULL)
  {
    /* child_tid is invalid */
    return -1;
  }

  /* if child_tid is valid and child exists*/
  // Removes the child from the list of children.
  // Wakes the child up and blocks the parent until the child signals completion
  // Returns the exit status of the child 
  else
  {
    list_remove(&child->elemChild);
    /* wake the child up */
    sema_up(&child->semaChildSync);
    /* let parent sleep till child wakes him up,,
    block the parent until the child signals completion */
    sema_down(&thread_current()->semaChild);
    /* get the exit status of the child */
    return thread_current()->exitChildStatus;
  }
  /* ------------------------ ADDED ------------------------ */
}

/* Free the current process's resources. */

// its function is to clean up resources allocated to the process, including closing files and removing page directory mappings
void process_exit(void)
{
  struct thread *cur = thread_current();

  /* ------------------------ ADDED ------------------------ */
  /* check if the cuuent thread has a parent and not initial one */
  if (cur->parent != NULL)
  {
    /* get its parent thread */
    struct thread *parent = cur->parent;

    /* check if the parent is waiting for the child,
    if so, then set all parent attributes to 0 or -1 (reset them all as first initiallaized)
    and set exitChildStatus to the current thread's exitFileStatus
    and wake the parent up */

    if (parent->waitingForChild == cur->tid)
    {
      /* set the exit status of the child */
      parent->exitChildStatus = thread_current()->exitFileStatus;

      /* reset the parent attributes */
      /* no thread/child to wait for */
      parent->waitingForChild = -1;

      /* child is not created */
      parent->isChildCreationSuccess = false;

      /* signal the parent that the child is done and wake him up*/
      sema_up(&parent->semaChild);
    }
  }

  /* close the executable file and release its resources and reset all pointers */
  file_close(thread_current()->fileExecutable);
  thread_current()->fileExecutable = NULL;
  thread_current()->parent = NULL;

  /* frees file descriptors and signals any child processes to clean up their resources */
  struct list *process_files = &thread_current()->fileDescriptors;

  for (struct list_elem *e = list_begin(process_files); e != list_end(process_files);)
  {
    struct fileDescriptor *file = list_entry(e, struct fileDescriptor, elem);
    e = list_next(e);
    file_close(file->file);
    list_remove(&file->elem);
    free(file);
  }

  /* remove all children from children list and wake them up */
  struct list *children = &thread_current()->children;
  struct list_elem *e = list_begin(children);
  while (e != list_end(children))
  {
    struct thread *child = list_entry(e, struct thread, elemChild);
    e = list_next(e);
    child->parent = NULL;
    sema_up(&child->semaChildSync);
    list_remove(&child->elemChild);
  }
  /* ------------------------ ADDED ------------------------ */

  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);

/* ------------------------ ADDED ------------------------ */
// handle argument pushing onto the stack
void stackArgs(void **esp, char *file_name_args);

/* ------------------------ ADDED ------------------------ */

static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */

// to load a user process from an executable file
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* ------------------------ ADDED ------------------------ */

  /* copy of file name to be used in strtok_r function to get the first token which is the file name*/

  /* how strtok_r works */
  /* strtok_r is similar to strtok but it takes an extra argument which is
   a pointer to a char pointer which is used to store the position of the next token */
  /* strtok_r is used to get the file name without the arguments passed to it
  and strtok is not used because it's not implemented in pintOS */

  char *fnCopy;
  char *savePtr;

  int len = strlen(file_name) + 1;
  fnCopy = malloc(len);
  strlcpy(fnCopy, file_name, len);
  fnCopy = strtok_r(fnCopy, " ", &savePtr);

  /* ------------------------ ADDED ------------------------ */

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(fnCopy);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", fnCopy);
    goto done;
  }

  /* ------------------------ ADDED ------------------------ */

  /* after file was opened successfully,
     we set the current thread/process executable to the file */
  thread_current()->fileExecutable = file;

  /* ------------------------ ADDED ------------------------ */

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
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
      if (validate_segment(&phdr, file))
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
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* ------------------------ ADDED ------------------------ */
  /* push the command line arguments onto the stack */
  push_stack(fnCopy, esp, &savePtr);
  free(fnCopy);
  /* ------------------------ ADDED ------------------------ */

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  /* ------------------------ ADDED ------------------------ */
  /* iin case of file loaded successfully, 
    deny file write to prevent modifications while the process is running */
  if (success)
  {
    file_deny_write(file);
  }
  /* ------------------------ ADDED ------------------------ */
  // file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
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
  if (phdr->p_vaddr < PGSIZE)
    return false;

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
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable))
    {
      palloc_free_page(kpage);
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
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* ------------------------ ADDED ------------------------ */
/* push the arguments to the stack */
/* file_name  The file name */
/* esp  The stack pointer */
/* save_ptr  The save pointer */

void push_stack(char *file_name, void **esp, char **save_ptr)
{
  void *stackPointer = *esp;
  int numArgs = 0;
  char *ptr = file_name;
  int argsSize = 0;

  /* count the number of arguments */
  while (ptr != NULL)
  {
    stackPointer -= strlen(ptr) + 1;
    memcpy(stackPointer, ptr, strlen(ptr) + 1); // copy the argument to the stack
    argsSize += strlen(ptr) + 1;
    numArgs++;
    ptr = strtok_r(NULL, " ", save_ptr);
  }

  char *stackArgs = stackPointer;
  /* word align */
  int wordAlign = (4 - (argsSize % 4)) % 4;
  if (wordAlign != 0)
  {
    stackPointer -= wordAlign;
    memset(stackPointer, 0, wordAlign);
  }

  /* push null at the end of arguments */
  stackPointer -= sizeof(char *);
  memset(stackPointer, 0, sizeof(char *));

  /* push the address of each argument */
  for (int i = numArgs - 1; i >= 0; i--)
  {
    stackPointer -= sizeof(char *);
    *(char **)stackPointer = stackArgs;
    stackArgs += strlen(stackArgs) + 1;
  }

  /* push the address of the first argument */
  char **argv = (char **)stackPointer;
  stackPointer -= sizeof(char **);
  *(char ***)stackPointer = argv;

  /* push the number of arguments */
  stackPointer -= sizeof(int);
  *(int *)stackPointer = numArgs;

  /* push a fake return address */
  stackPointer -= sizeof(int *);
  *(int **)stackPointer = NULL;

  *esp = stackPointer;
}

/* ------------------------ ADDED ------------------------ */

/* ------------------------ ADDED ------------------------ */
/* get the child thread with the given tid */
/* tid -> tid of child to get */
/* return the child thread with the given tid if found  from the current process's list of children */
struct thread *getChildThread(tid_t tid)
{
  /* get the list of children for the current thread/process */
  struct thread *current = thread_current();
  struct list *children = &current->children;
  struct list_elem *e = list_begin(children);

  /* iterate over the list of children and get the child with the given tid */
  while (e != list_end(children))
  {
    struct thread *entry = list_entry(e, struct thread, elemChild);
    e = list_next(e);
    if (entry->tid == tid)
    {
      return entry;
    }
  }

  /* child with this tid doesn't exist */
  return NULL;
}

/* ------------------------ ADDED ------------------------ */

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
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}
