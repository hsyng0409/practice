#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void valid_address(void *addr) {
  if(!is_user_vaddr(addr) || addr == NULL) exit(-1);
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t syscall_num = *(uint32_t *)f->esp;
  // printf ("system call!\nsyscall_num: %d\n", syscall_num);
  switch(syscall_num) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      valid_address(f->esp + 4);
      exit((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_EXEC:
      valid_address(f->esp + 4);
      exec((char *)*(uint32_t *)(f->esp + 4));

    case SYS_WAIT:
      valid_address(f->esp + 4);
      wait((pid_t)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_CREATE:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      create((char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_REMOVE:
      valid_address(f->esp + 4);
      remove((char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_OPEN:
      valid_address(f->esp + 4);
      open((char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_FILESIZE:
      valid_address(f->esp + 4);
      filesize((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_READ:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      valid_address(f->esp + 12);
      read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), 
            (unsigned int)*(uint32_t *)(f->esp + 12));
      break;

    case SYS_WRITE:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      valid_address(f->esp + 12);
      write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), 
            (unsigned int)*(uint32_t *)(f->esp + 12));
      break;

    case SYS_SEEK:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_TELL:
      valid_address(f->esp + 4);
      tell((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_CLOSE:
      valid_address(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_SIGACTION:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      sigaction((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_SENDSIG:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      sendsig((pid_t)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_YIELD:
      sched_yield();
      break;
  }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  thread_current()->status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec(const char *cmd_line){
  return process_execute(cmd_line);
}

int wait(pid_t pid){
  return process_wait((tid_t) pid);
}

bool create(const char *file, unsigned initial_size){
  return true;
}

bool remove(const char *file){
  return true;
}

int open(const char *file){
  struct file *f;

  valid_address(file);
  lock_acquire(&file_lock);

  f = filesys_open(file);
  if(f == NULL) {
    lock_release(&file_lock);
    return -1;
  }
  
  for(int i=3; i<128; i++){
    if(thread_current()->fd[i] == NULL) {
      if(strcmp(thread_name(), file) == 0){
        file_deny_write(f);
      }
      thread_current()->fd[i] = f;
      lock_release(&file_lock);
      return i;
    }
  }
  lock_release(&file_lock);
  return -1;
}

int filesize(int fd){
  return 0;
}

int read(int fd, void *buffer, unsigned size) {
  int i;
  if(fd == 0) {
    for (i=0; i<size; i++) {
      if(((char *) buffer)[i] == '\0') {
        break;
      }
    }
  }
  return i;
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}

void seek(int fd, unsigned position){
  
}

unsigned tell(int fd){
  return 0;
}

void close(int fd){

}

void sigaction(int signum, void *handler){

}

void sendsig(pid_t pid, int signum){

}

void sched_yield(void){

}