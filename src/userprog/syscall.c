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
  if(!is_user_vaddr(addr) || addr == NULL) {
    //pagedir_clear_page(addr);
    exit(-1);
  }
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
  //hread_current()->status = status;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec(const char *cmd_line){
  tid_t tid;
  /*struct thread *parent = thread_current();
  struct thread *child;
  struct list_elem *e;*/

  tid = process_execute(cmd_line);
  // Search the descriptor of the child process by using child_tid 
  /*
  for (e = list_begin (&parent->children); e != list_end (&parent->children);
       e = list_next (e)){
    child = list_entry(e, struct thread, child_elem);
    if(child->tid == tid) break;
  }
  if(child == NULL) return -1;

  // The caller blocks until the child process exits
  sema_down(&child->exec_sema);
  */

  return (pid_t) tid;
}

int wait(pid_t pid){
  return process_wait((tid_t) pid);
}

bool create(const char *file, unsigned initial_size){
  ASSERT(file != NULL);
  ASSERT(initial_size >= 0);
  return filesys_create(file,initial_size);
}

bool remove(const char *file){
  return filesys_remove(file);
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
  
  struct thread *t = thread_current();

  for(int i=2; i<128; i++){
    if(t->fd[i] == NULL) {
      if(strcmp(t->name, file) == 0){
        file_deny_write(f);
      }
      t->fd[i] = f;
      lock_release(&file_lock);
      return i;
    }
    else if(t->fd[i] == f){
      close(i);
    }
  }
  lock_release(&file_lock);
  return -1;
}

int filesize(int fd){
  struct file *f;
  f = thread_current() -> fd[fd];
  return file_length(f);
}

int read(int fd, void *buffer, unsigned size) {
  ASSERT(fd >= 0);
  int i;
  if(fd == 0) {
    input_getc();
    for (i=0; i<size; i++) {
      if(((char *) buffer)[i] == '\0') {
        return i;
        //break;
      }
    }
  }
  else{
    struct file *f = thread_current() -> fd[fd];
    return file_read(f,buffer,size);
  }
  //return i;
}

int write(int fd, const void *buffer, unsigned size) {
  ASSERT(fd >= 0);
  if(fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  else{
    struct file *f = thread_current() -> fd[fd];
    return file_write(f, buffer, size);
  }
  //return -1;
}

void seek(int fd, unsigned position){
  struct file *f = thread_current() -> fd[fd];
  file_seek(f,position);
}

unsigned tell(int fd){
  struct file *f = thread_current() -> fd[fd];
  return file_tell(f);
}

void close(int fd){
  struct file *f;
  struct thread *t = thread_current();

  f = t -> fd[fd];
  file_close(f);
  t -> fd[fd] = NULL;
}

void sigaction(int signum, void *handler){
  struct thread *t = thread_current();
  struct handler_reg *h;
  h -> signum = signum;
  h -> sighandler = handler;
  t -> handler = h;
}

void sendsig(pid_t pid, int signum){
  struct thread *parent = thread_current();
  struct thread *child;
  struct list_elem *e;

  for (e = list_begin (&parent->children); e != list_end (&parent->children);
       e = list_next (e)){
    child = list_entry(e, struct thread, child_elem);
    if(child->tid == pid) break;
  }
  if(child == NULL) return -1;

  struct handler_reg *reg = child  -> handler;
  if(signum == reg->signum) {
      printf("Signum: %d, Action: %d", reg->signum, &reg->sighandler);
  }

}

void sched_yield(void){
  thread_yield();
}