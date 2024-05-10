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

void syscall_init(void);

/* ------------------------ ADDED ------------------------ */
/* SYSTEM CALLS */
void halt();
void exit(int status);
void seek(struct intr_frame *f); /* change position of file to be read or written */
void tell(struct intr_frame *f); /* get position of file to be read or written */

int close(int fd);
int open(char *file_name);
int remove(char *file_name);
int create(char *file_name, int initial_size);

int read(int fd, char *buffer, unsigned size);
int write(int fd, char *buffer, unsigned size);

tid_t wait(tid_t tid);

/* HANDLERS */
void open_handler(struct intr_frame *f);
void close_handler(struct intr_frame *f);
void read_handler(struct intr_frame *f);
void write_handler(struct intr_frame *f);
void exit_handler(struct intr_frame *f);
void remove_handler(struct intr_frame *f);
void create_handler(struct intr_frame *f);
void wait_handler(struct intr_frame *f);
void exec_handler(struct intr_frame *f);

void countSize(struct intr_frame *f);
struct fileDescriptor *getFile(int fd);

bool isValid(void *name);
bool isValid_esp(struct intr_frame *f);
/* ------------------------ ADDED ------------------------ */

#endif /* userprog/syscall.h */
