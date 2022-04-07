#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
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
      exit(*(uint32_t *)(f->esp + 4));
      break;

    case SYS_EXEC:
      exec(*(uint32_t *)(f->esp + 4));

    case SYS_WAIT:
      break;

    case SYS_CREATE:
      break;

    case SYS_REMOVE:
      break;

    case SYS_OPEN:
      break;

    case SYS_FILESIZE:
      break;

    case SYS_READ:
      break;

    case SYS_WRITE:
      write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), 
            (unsigned int)*(uint32_t *)(f->esp + 12));
      break;

    case SYS_SEEK:
      break;

    case SYS_TELL:
      break;

    case SYS_CLOSE:
      break;

    case SYS_SIGACTION:
      break;

    case SYS_SENDSIG:
      break;

    case SYS_YIELD:
      break;
  }
}

static bool valid_address(void *addr) {
  if(!is_user_vaddr(addr) || addr == NULL) return false;
  return true;
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