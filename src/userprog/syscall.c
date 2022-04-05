#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  thread_exit ();
}

// static bool valid_address(void *addr) {
//   if(!is_user_vaddr(addr) || addr == NULL) return false;
//   return true;
// }

// void halt(void){

// }

// void exit(int status){

// }

// pid_t exec(const char *cmd_line){

// }

// int wait(pid_t pid){

// }