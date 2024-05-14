#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* ------------------------ ADDED ------------------------ */
#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

/* ------------------------ ADDED ------------------------ */
 // registers the interupt handler for system calls and initializes the fileLock
void syscall_init(void);

/* ------------------------ ADDED ------------------------ */
/* SYSTEM CALLS */
void halt();
void exit(int status);


// Handles the SYS_SEEK system call to change the file position to be read or written
void seek(struct intr_frame *f); 


// Handles the SYS_TELL system call to get the position of the file to be read or written
void tell(struct intr_frame *f); 


// Closes a file, ensuring thread safety using fileLock
int close(int fd);


// Opens a file and returns a file descriptor, ensuring thread safety using fileLock
int open(char *file_name);


// Removes a file, ensuring thread safety using fileLock
int remove(char *file_name);


// Creates a file with the specified name and initial size, ensuring thread safety using fileLock
int create(char *file_name, int initial_size);


// Reads data from a file or stdin, ensuring thread safety using fileLock
int read(int fd, char *buffer, unsigned size);


// Writes data to a file or stdout, ensuring thread safety using fileLock
int write(int fd, char *buffer, unsigned size);


tid_t wait(tid_t tid);


/* HANDLERS */

// Handles the SYS_OPEN system call by invoking the open() function
void open_handler(struct intr_frame *f);


// Handles the SYS_CLOSE system call by invoking the close() function
void close_handler(struct intr_frame *f);


// Handles the SYS_READ system call by invoking the read() function
void read_handler(struct intr_frame *f);


// Handles the SYS_WRITE system call by invoking the write() function
void write_handler(struct intr_frame *f);

void exit_handler(struct intr_frame *f);


// Handles the SYS_REMOVE system call by invoking the remove() function
void remove_handler(struct intr_frame *f);


//  Handles the SYS_CREATE system call by invoking the create() function 
void create_handler(struct intr_frame *f);

void wait_handler(struct intr_frame *f);

void exec_handler(struct intr_frame *f);


// Handles the SYS_FILESIZE system call to get the size of a file
void countSize(struct intr_frame *f);


// Retrieves a file descriptor structure for a given file descriptor
struct fileDescriptor *getFile(int fd);

// check if a given pointer is valid
bool isValid(void *name);

// check if the stack pointer is valid
bool isValid_esp(struct intr_frame *f);
/* ------------------------ ADDED ------------------------ */

#endif /* userprog/syscall.h */
