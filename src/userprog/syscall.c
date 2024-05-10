#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

static void syscall_handler(struct intr_frame *f);

/* ------------------------ ADDED ------------------------ */
/* define a lock to be used when writing to a file shared between all threads */
struct lock fileLock;
/* ------------------------ ADDED ------------------------ */

/* called first abl ay system call */
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* ------------------------ ADDED ------------------------ */
  /* initialize the lock */
  lock_init(&fileLock);
  /* ------------------------ ADDED ------------------------ */
}

static void
syscall_handler(struct intr_frame *f)
{
  /* ------------------------ ADDED ------------------------ */
  /* check if the stack pointer is valid */
  if (!isValid_esp(f))
  {
    /* exit if it's not valid */
    exit(-1);
  }

  /* get the system call number */
  /* call the function that maps to the number*/
  switch (*(int *)f->esp)
  {
  case SYS_HALT:
    halt();
    break;

  case SYS_EXIT:
    exit_handler(f);
    break;

  case SYS_EXEC:
    exec_handler(f);
    break;

  case SYS_WAIT:
    wait_handler(f);
    break;

  case SYS_CREATE:
    create_handler(f);
    break;

  case SYS_REMOVE:
    remove_handler(f);
    break;

  case SYS_OPEN:
    open_handler(f);
    break;
    
  case SYS_FILESIZE:
    countSize(f);
    break;

  case SYS_READ:
    read_handler(f);
    break;

  case SYS_WRITE:
    write_handler(f);
    break;

  case SYS_SEEK:
    seek(f);
    break;

  case SYS_TELL:
    tell(f);
    break;

  case SYS_CLOSE:
    close_handler(f);
    break;

  default:
    exit(-1); /* exit if the system call number is invalid */
  }

  // printf ("system call!\n");
  // thread_exit ();
}

/* halt or shutdown system */
void halt(void)
{
  printf("(halt) begin\n");
  shutdown_power_off();
}

/* exit the current thread */
void exit_handler(struct intr_frame *f)
{
  int status = *((int *)f->esp + 1);
  if (!is_user_vaddr(status))
  {
    f->eax = -1;
    exit(-1);
  }
  f->eax = status;
  exit(status);
}


/* exit the current thread */
void exit(int status)
{
  char *name = thread_current()->name;
  char *save_ptr;
  char *fileExecutable = strtok_r(name, " ", &save_ptr);
  thread_current()->exitFileStatus = status;
  printf("%s: exit(%d)\n", fileExecutable, status);
  thread_exit();
}


/* execute a new process */
void exec_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  f->eax = process_execute(file_name);
}

/* wait for a child process to finish */
void wait_handler(struct intr_frame *f)
{
  if (!isValid((int *)f->esp + 1))
    exit(-1);
  tid_t tid = *((int *)f->esp + 1);
  f->eax = wait(tid);
}

/* wait for the child process/thread with that tid */
tid_t wait(tid_t tid)
{
  return process_wait(tid);
}

/* create a new file */
void create_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  if (!isValid(file_name))
  {
    exit(-1);
  }
  int initial_size = (unsigned)*((int *)f->esp + 2);
  f->eax = create(file_name, initial_size);
}

int create(char *file_name, int initial_size)
{
  int result = 0;
  lock_acquire(&fileLock);
  result = filesys_create(file_name, initial_size);
  lock_release(&fileLock);
  return result;
}

/* remove a file */
/* Check the pointer to file , if it is valid , then call remove function */
void remove_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  if (!isValid(file_name))
  {
    exit(-1);
  }
  f->eax = remove(file_name);
}

/* remove a file */
int remove(char *file_name)
{
  int result = -1;
  lock_acquire(&fileLock);
  result = filesys_remove(file_name);
  lock_release(&fileLock);
  return result;
}

/* open a file */
/* Check the pointer to file , if it is valid , then call open function */
void open_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  if (!isValid(file_name))
  {
    exit(-1);
  }
  f->eax = open(file_name);
}

/* open file with its name and return its fd */
int open(char *name)
{
  static unsigned long curr_fd = 2;

  lock_acquire(&fileLock);
  struct file *fileOpened = filesys_open(name);
  lock_release(&fileLock);
  if (fileOpened == NULL)
  {
    return -1;
  }
  else
  {
    /* wrapper containing fd and the file */
    struct fileDescriptor *fileDescriptor = (struct fileDescriptor *)malloc(sizeof(struct fileDescriptor));
    int file_fd = curr_fd;
    fileDescriptor->fd = curr_fd;
    fileDescriptor->file = fileOpened;

    lock_acquire(&fileLock);
    curr_fd++;
    lock_release(&fileLock);

    struct list_elem *elem = &fileDescriptor->elem;
    list_push_back(&thread_current()->fileDescriptors, elem);
    return file_fd;
  }
}

/* get the size of the file by taking its fd */
void countSize(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  struct fileDescriptor *file = getFile(fd);
  if (file == NULL)
  {
    f->eax = -1;
    exit(-1);
  }
  else
  {
    lock_acquire(&fileLock);
    f->eax = file_length(file->file);
    lock_release(&fileLock);
  }
}

/* get the file by its fd if it gets opened by current thread */
struct fileDescriptor *getFile(int fd)
{
  struct fileDescriptor *ans = NULL;
  struct list *files = &(thread_current()->fileDescriptors);
  for (struct list_elem *e = list_begin(files); e != list_end(files); e = list_next(e))
  {
    struct fileDescriptor *file = list_entry(e, struct fileDescriptor, elem);
    if ((file->fd) == fd)
    {
      return file;
    }
  }
  return NULL;
}

/* read from a file */
/* check on fd and buffer,
if they're valid, then call read function ..
if not, then exit */
void read_handler(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  char *buffer = (char *)(*((int *)f->esp + 2));
  /* fd == 1 means stdout */
  if (!isValid(buffer) || fd == 1) /* check if the buffer is valid */
  {
    exit(-1);
  }
  unsigned size = *((unsigned *)f->esp + 3);
  f->eax = read(fd, buffer, size);
}

/* read from a file */
int read(int fd, char *buffer, unsigned size)
{
  int result = size;
  /* fd ==0 mean stdin */
  if (fd == 0)
  {
    while (size--)
    {
      lock_acquire(&fileLock);
      /* read data with input_getc */
      char c = input_getc();
      lock_release(&fileLock);
      buffer += c;
    }
    return result;
  }
  if (fd == 1)
  {
    /* negative area */
  }
  struct fileDescriptor *user_file = getFile(fd);
  if (user_file == NULL)
  {
    return -1;
  }
  else
  {
    struct file *file = user_file->file;
    lock_acquire(&fileLock);
    size = file_read(file, buffer, size);
    lock_release(&fileLock);
    return size;
  }
}

/* write to a file */
/* check on fd and buffer,
if they're valid, then call write function ..
if not, then exit */
void write_handler(struct intr_frame *f)
{
  int fd = *((int *)f->esp + 1);
  char *buffer = (char *)(*((int *)f->esp + 2));
  if (!isValid(buffer) || fd == 0) /* check if the buffer is valid */
  {
    exit(-1);
  }
  unsigned size = (unsigned)(*((int *)f->esp + 3));
  f->eax = write(fd, buffer, size);
}

/* write to a file */
int write(int fd, char *buffer, unsigned size)
{
  if (fd == 0)
  {
    /* fd == 0 means stdin */
    /* negative area */
  }
  else if (fd == 1)
  {
    lock_acquire(&fileLock);
    /* write data with putbuf */
    putbuf(buffer, size);
    lock_release(&fileLock);
    return size;
  }

  struct fileDescriptor *file = getFile(fd);
  if (file == NULL)
  {
    return -1;
  }
  else
  {
    int ans = 0;
    lock_acquire(&fileLock);
    ans = file_write(file->file, buffer, size);
    lock_release(&fileLock);
    return ans;
  }
}

/* close a file */
void close_handler(struct intr_frame *f)
{
  int fd = (int)(*((int *)f->esp + 1));
  /* if target is stdin (fd == 0) or stdout (fd == 1) */
  if (fd < 2)
  {
    exit(-1);
  }
  f->eax = close(fd);
}

/* close a file */
/* Take the fd for target file and close it if it exist to current process ..
otherwise return -1*/
int close(int fd)
{
  struct fileDescriptor *file = getFile(fd);
  if (file == NULL)
  {
    return -1;
  }
  else
  {
    lock_acquire(&fileLock);
    file_close(file->file);
    lock_release(&fileLock);
    list_remove(&file->elem);
    return 1;
  }
}

/* change the position of file to be read or written */
void seek(struct intr_frame *f)
{
  /* take fd and position where the file to be written */
  int fd = (int)(*((int *)f->esp + 1));
  unsigned position = (unsigned)(*((int *)f->esp + 2));
  struct fileDescriptor *file = getFile(fd);
  if (file == NULL)
  {
    f->eax = -1;
  }
  else
  {
    lock_acquire(&fileLock);
    file_seek(file->file, position);
    f->eax = position;
    lock_release(&fileLock);
  }
}

/* get the position of file to be read or written */
void tell(struct intr_frame *f)
{
  /* take fd and return position where to be read or written */
  int fd = (int)(*((int *)f->esp + 1));
  struct fileDescriptor *file = getFile(fd);
  if (file == NULL)
  {
    f->eax = -1;
  }
  else
  {
    lock_acquire(&fileLock);
    f->eax = file_tell(file->file);
    lock_release(&fileLock);
  }
}

/* check if the pointer is valid */
bool isValid(void *name)
{
  return name != NULL && is_user_vaddr(name) && pagedir_get_page(thread_current()->pagedir, name) != NULL;
}

/* check if the stack pointer is valid */
bool isValid_esp(struct intr_frame *f)
{
  return isValid((int *)f->esp) || ((*(int *)f->esp) < 0) || (*(int *)f->esp) > 12;
}

/* ------------------------ ADDED ------------------------ */