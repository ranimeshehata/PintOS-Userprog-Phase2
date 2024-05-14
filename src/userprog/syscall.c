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
/* define a lock to be used when writing to a file shared between all threads to ensure mutual exclusion */
struct lock fileLock;
/* ------------------------ ADDED ------------------------ */

/* called first abl ay system call */
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* ------------------------ ADDED ------------------------ */
  /* initialize the lock to ensure mutual exclusion when performing file operations across multiple threads */
  lock_init(&fileLock);
  /* ------------------------ ADDED ------------------------ */
}

// This function handles system calls by dispatching them to the appropriate handler functions based on the system call number
// Retrieves the system call number from the stack pointer (f->esp)
// Uses a switch statement to call the appropriate handler function based on the system call number.
// If the system call number is invalid, it calls exit(-1)
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
  /* call the function that maps to the number */
  /* the system call number is extracted from the stack pointer (esp), 
  and a corresponding handler function is called based on the system call number */
  switch (*(int *)f->esp)
  {
    /* Each function performs necessary validation and invokes corresponding file system operations
     while holding the fileLock to ensure thread safety */

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
// Calls shutdown_power_off() to power off the machine
void halt(void)
{
  printf("(halt) begin\n");
  shutdown_power_off();
}


/* exit the current thread */
// Handles the SYS_EXIT system call to terminate the current process
// Retrieves the exit status from the stack pointer (f->esp)
// Validates the status using is_user_vaddr(status)
// Sets the exit status in the register f->eax and calls exit(status) to terminate the process
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
// Terminates the current thread with the specified exit status
// Retrieves the current thread's name and prepares the exit message
// Sets the thread's exit status
// Prints the exit message and calls thread_exit() to terminate the thread
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
// Handles the SYS_EXEC system call to execute a new process
// Retrieves the file name from the stack pointer (f->esp)
// Calls process_execute(file_name) to create a new process and stores the result in f->eax
void exec_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  f->eax = process_execute(file_name);
}



/* wait for a child process to finish */
// Handles the SYS_WAIT system call to wait for a child process to finish
// Validates the argument using isValid()
// The thread id (tid) of the child process is retrieved from the stack
// Calls wait(tid) to wait for the child process to finish and stores the result in f->eax
// f->eax is the register used to store the return value of the system call
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
// Handles the SYS_CREATE system call to create a new file
// Retrieves the file name and initial size from the stack pointer (f->esp)
// validate the file name using isValid()
// Calls create(file_name, initial_size) to create the file and stores the result in f->eax
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



// create a new file with the specified name and initial size
// Acquires the fileLock to ensure mutual exclusion when creating the file
// Calls filesys_create(file_name, initial_size) to create the file
// Releases the fileLock after creating the file and returns the result
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
// Handles the SYS_REMOVE system call to remove a file
// Retrieves the file name from the stack pointer (f->esp)
// validate the file name using isValid()
// Calls remove(file_name) to remove the file and stores the result in f->eax
void remove_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  if (!isValid(file_name))
  {
    exit(-1);
  }
  f->eax = remove(file_name);
}



/* remove a file with the specified name */
// Acquires the fileLock to ensure mutual exclusion when removing the file
// Calls filesys_remove(file_name) to remove the file
// Releases the fileLock after removing the file and returns the result
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
// Handles the SYS_OPEN system call to open a file
// Retrieves the file name from the stack pointer (f->esp)
// validate the file name using isValid()
// Calls open(file_name) to open the file and stores the result in f->eax
void open_handler(struct intr_frame *f)
{
  char *file_name = (char *)(*((int *)f->esp + 1));
  if (!isValid(file_name))
  {
    exit(-1);
  }
  f->eax = open(file_name);
}


/* open file with its name and return its fd (a file descriptor) */
// Acquires the fileLock to ensure mutual exclusion when opening the file
// Calls filesys_open(file_name) to open the file
// release the fileLock after opening the file and returns the file descriptor
// If the file is not opened, returns -1
// if the file is opened, it creates a file descriptor structue, assigns it a unique file descriptor 
// and adds it to the current thread's fileDescriptors list
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
// Handles the SYS_FILESIZE system call to get the size of a file
// Retrieves the file descriptor (fd) from the stack pointer (f->esp)
// Calls getFile(fd) to get the fileDescriptor structure
// If the file is not found, sets f->eax to - 1 and exits
// If the file is found, acquires the fileLock, calls file_length(file->file) to get the file size, and releases the fileLock
// Stores the file size in f -> eax 
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
// Retrieves the file descriptor (file users) structure for a given file descriptor
// Iterates through the current thread's fileDescriptors list to find the file descriptor with the specified file descriptor (fd)
// Returns the file descriptor structure if found, otherwise returns NULL
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
// Handles the SYS_READ system call to read from a file
// Retrieves the file descriptor (fd), buffer, and size from the stack pointer (f->esp)
// Validates the buffer using isValid() and checks if fd is 1 (stdout)
// Calls read(fd, buffer, size) to read from the file and stores the result in f->eax
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
// Reads data from a file or stdin
// If fd is 0 (stdin), reads characters using input_getc() and stores them in the buffer
// If fd is 1 (stdout), does nothing (invalid case for reading)
// calls getFile(fd) to get the fileDescriptor structure
// If the file is not found, returns -1
// If the file is found, acquires the fileLock, calls file_read(file, buffer, size) to read from the file, and releases the fileLock
// Returns the number of bytes read
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
    /* stdout */
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
// Handles the SYS_WRITE system call to write to a file
// Retrieves the file descriptor (fd), buffer, and size from the stack pointer (f->esp)
// Validates the buffer using isValid() and checks if fd is 0 (stdin)
// Calls write(fd, buffer, size) to write to the file and stores the result in f->eax
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
// Writes data to a file or stdout
// If fd is 0 (stdin), does nothing (invalid case for writing)
// If fd is 1 (stdout), acquires the fileLock, writes characters using putbuf(buffer, size)
// releases the fileLock, and returns the size
// if the file is not found, returns -1
// If the file is found, acquires the fileLock, calls file_write(file, buffer, size) to write to the file, and releases the fileLock
// Returns the number of bytes written
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
// Handles the SYS_CLOSE system call to close a file
// Retrieves the file descriptor (fd) from the stack pointer (f->esp)
// Ensures the file descriptor is not stdin or stdout (fd < 2) 
// Calls close(fd) to close the file and stores the result in f->eax
void close_handler(struct intr_frame * f)
{
  int fd = (int)(*((int *)f->esp + 1));
  /* if target is stdin (fd == 0) or stdout (fd == 1) */
  if (fd < 2)
  {
    exit(-1);
  }
  f->eax = close(fd);
}



/* close a file with the specified file descriptor */
/* Take the fd for target file and close it if it exist to current process ..
otherwise return -1*/
// If the file is not found, returns -1
// If the file is found, acquires the fileLock, calls file_close(file->file) to close the file, and releases the fileLock
// Removes the file descriptor from the current thread's fileDescriptors list and returns 1
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
// Handles the SYS_SEEK system call to change the file position to be read or written
// Retrieves the file descriptor (fd) and position from the stack pointer (f->esp)
// Calls getFile(fd) to get the fileDescriptor structure
// If the file is not found, sets f->eax to -1
// If the file is found, acquires the fileLock, calls file_seek(file->file, position) to change the file position, and releases the fileLock
// Stores the position in f->eax
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
// Handles the SYS_TELL system call to get the position of the file to be read or written
// Retrieves the file descriptor (fd) from the stack pointer (f->esp)
// Calls getFile(fd) to get the fileDescriptor structure
// If the file is not found, sets f->eax to -1
// If the file is found, acquires the fileLock, calls file_tell(file->file) to get the file position, and releases the fileLock
// Stores the file position in f->eax
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



/* check if the given pointer is valid */
bool isValid(void *name)
{
  return name != NULL && is_user_vaddr(name) && pagedir_get_page(thread_current()->pagedir, name) != NULL;
}



/* check if the stack pointer is valid */
// Returns f != NULL && is_user_vaddr(f->esp) to ensure the stack pointer is not NULL and within user address space
bool isValid_esp(struct intr_frame *f)
{
  return isValid((int *)f->esp) || ((*(int *)f->esp) < 0) || (*(int *)f->esp) > 12;
}

/* ------------------------ ADDED ------------------------ */