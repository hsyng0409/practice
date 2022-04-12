#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <list.h>

typedef int pid_t;

void syscall_init (void);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);

bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct handler_reg{
    int signum;
    void *sighandler;
    struct list_elem handler_elem;
};
void sigaction(int signum, void *handler);
void sendsig(pid_t pid, int signum);
void sched_yield(void);


#endif /* userprog/syscall.h */
