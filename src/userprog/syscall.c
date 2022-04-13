#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
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
  for(int i=0; i<4; i++){
    if(!is_user_vaddr(addr+i) || addr+i == NULL || 
      !pagedir_get_page(thread_current() -> pagedir, addr+i)) {
      //pagedir_clear_page(addr);
      exit(-1);
    }
  }
}

static void
syscall_handler (struct intr_frame *f) 
{
  valid_address(f->esp);

  uint32_t syscall_num = *(uint32_t *)f->esp;
  // printf ("--- system call! syscall_num: %d\n", syscall_num);
  // printf("--- %s (%d)\n", thread_name(), thread_tid());
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
      f->eax = exec((char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_WAIT:
      valid_address(f->esp + 4);
      f->eax = wait((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_CREATE:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      f->eax = create((char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_REMOVE:
      valid_address(f->esp + 4);
      f->eax = ((char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_OPEN:
      valid_address(f->esp + 4);
      f->eax = open((char *)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_FILESIZE:
      valid_address(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;

    case SYS_READ:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      valid_address(f->esp + 12);
      f->eax = read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), 
            (unsigned int)*(uint32_t *)(f->esp + 12));
      break;

    case SYS_WRITE:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      valid_address(f->esp + 12);
      f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), 
            (unsigned int)*(uint32_t *)(f->esp + 12));
      break;

    case SYS_SEEK:
      valid_address(f->esp + 4);
      valid_address(f->esp + 8);
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;

    case SYS_TELL:
      valid_address(f->esp + 4);
      f->eax = tell((int)*(uint32_t *)(f->esp + 4));
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
  struct thread *t = thread_current();
  for(int i=0; i<128; i++) {
    if(t->signals[i] == 1){
      struct list_elem *e;
      for(e = list_begin(&t->handlers); e != list_end(&t->handlers); e = list_next(e)){
        struct handler_reg *r = list_entry(e, struct handler_reg, handler_elem);
        if(r->signum == i) printf("Signum: %d, Action: 0x%x\n", i, r->sighandler);
      }
    }
  }

  t->exit_status = status;
  for(int i=3; i<128; i++) {
    if(t->fd[i] != NULL){
      close(i);
    }
  }
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_exit();
}

pid_t exec(const char *cmd_line){
  tid_t tid;
  
  valid_address(cmd_line);
  tid = process_execute(cmd_line);
  return tid;
}

int wait(pid_t pid){
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size){
  valid_address(file);
  lock_acquire(&file_lock);
  bool success = false;

  if(strlen(file) == 0 || strlen(file) >= 14) {
    lock_release(&file_lock);
    return success;
  }
  success = filesys_create(file,initial_size);
  lock_release(&file_lock);
  return success;
}

bool remove(const char *file){
  return filesys_remove(file);
}

int open(const char *file){
  struct file *f;
  struct thread *t = thread_current();

  valid_address(file);
  lock_acquire(&file_lock);

  f = filesys_open(file);
  if(f == NULL) {
    lock_release(&file_lock);
    return -1;
  }
  
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
      close(t -> fd[i]);
      t -> fd[i] = NULL;
    }
  }
  lock_release(&file_lock);
  return -1;
}

int filesize(int fd){
  if (fd < 2) exit(-1);
  struct file *f;
  f = thread_current() -> fd[fd];
  return file_length(f);
}

int read(int fd, void *buffer, unsigned size) {
  if(fd < 0 || fd == 1 || fd >= 128) exit(-1);
  valid_address(buffer);

  int i;
  if(fd == 0) {
    input_getc();
    for (i=0; i<size; i++) {
      if(((char *) buffer)[i] == '\0') {
        //return i;
        break;
      }
    }
  }
  else{
    struct file *f = thread_current() -> fd[fd];
    lock_acquire(&file_lock);
    i = file_read(f,buffer,size);
    lock_release(&file_lock);
    //return i;
  }
  return i;
}

int write(int fd, const void *buffer, unsigned size) {
  if(fd < 0 || fd == 0 || fd >= 128) exit(-1);
  valid_address(buffer);

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
  if (fd < 0 || fd >= 128) exit(-1);

  struct file *f;
  struct thread *t = thread_current();

  f = t -> fd[fd];
  if(f == NULL) exit(-1);

  file_close(f);
  t -> fd[fd] = NULL;
}

void sigaction(int signum, void *handler){
  struct thread *t = thread_current();
  struct handler_reg *h = malloc(sizeof (struct handler_reg));
  h -> signum = signum;
  h -> sighandler = handler;
  list_push_back(&t->handlers, &h->handler_elem);
}

void sendsig(pid_t pid, int signum){
  struct thread *parent = thread_current();
  struct thread *child = NULL;
  struct list_elem *e, *r;

  for (e = list_begin (&parent->children); e != list_end (&parent->children);
       e = list_next (e)){
    child = list_entry(e, struct thread, child_elem);

    if(child->tid == pid) {
      child->signals[signum] = 1;
    }
  }
}

void sched_yield(void){
  thread_yield();
}