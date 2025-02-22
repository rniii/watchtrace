#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  pid_t pid;
  bool in_syscall;
} proc;

pid_t child;
size_t nprocs = 0;
proc *procmap = 0;

int ptstrncpy(pid_t pid, char *dst, long long src, size_t nbytes);
int ptresolvefd(pid_t pid, char *dst, int fd);

proc *getproc(pid_t pid) {
  for (int i = 0; i < nprocs; i++)
    if (pid == procmap[i].pid)
      return &procmap[i];

  printf("[pid %i] +++ attached\n", pid);

  procmap = reallocarray(procmap, ++nprocs, sizeof(proc));
  procmap[nprocs - 1].pid = pid;
  procmap[nprocs - 1].in_syscall = false;

  return &procmap[nprocs - 1];
}

void handle_access(proc *proc, int dir, size_t name, int mode, int ret) {
  if (mode & W_OK)
    return;

  char buf[PATH_MAX];
  ptstrncpy(proc->pid, buf, name, PATH_MAX);

  printf("[pid %i] access '%s' in %d = %d\n", proc->pid, buf, dir, ret);
  if (ret < 0)
    printf("[pid %i] %s\n", proc->pid, strerror(-ret));
}

void handle_open(proc *proc, int dir, size_t name, int flags, int ret) {
  if (flags & (O_RDWR | O_WRONLY))
    return;

  char buf[PATH_MAX];
  ptstrncpy(proc->pid, buf, name, PATH_MAX);

  printf("[pid %i] open '%s' in %d = %d\n", proc->pid, buf, dir, ret);
  if (ret < 0)
    printf("[pid %i] %s\n", proc->pid, strerror(-ret));
}

void handle_close(proc *proc, int fd) {
  printf("[pid %i] close %d\n", proc->pid, fd);
}

void handle_syscall(pid_t pid) {
  proc *proc = getproc(pid);

  if ((proc->in_syscall = !proc->in_syscall))
    return;

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, 0, &regs);

  // this bit is arch-dependent, syscall(2)
  switch (regs.orig_rax) {
  case SYS_open:
    handle_open(proc, AT_FDCWD, regs.rdi, regs.rsi, regs.rax);
    break;
  case SYS_openat:
    handle_open(proc, regs.rdi, regs.rsi, regs.rdx, regs.rax);
    break;
  case SYS_access:
    handle_access(proc, AT_FDCWD, regs.rdi, regs.rsi, regs.rax);
    break;
  case SYS_faccessat:
    handle_access(proc, regs.rdi, regs.rsi, regs.rdx, regs.rax);
    break;
  case SYS_close:
    handle_close(proc, regs.rdi);
    break;
  }
}

void handle_exit(pid_t pid) {
  if (pid == child)
    exit(0);

  printf("[pid %i] exit\n", pid);

  int i = 0;
  while (procmap[i++].pid != pid)
    ;

  memmove(procmap + i - 1, procmap + i, nprocs - i);
}

void launch(char *argv[]) {
  if ((child = fork())) {
    wait(0);

    ptrace(PTRACE_SETOPTIONS, child, 0,
      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE);
    ptrace(PTRACE_CONT, child, 0, 0);

    return;
  }

  // yuri
  ptrace(PTRACE_TRACEME, 0);
  kill(getpid(), SIGSTOP);
  execvp(argv[0], argv);
}

// memcpy a string from a child pid's memory, null-terminated
int ptstrncpy(pid_t pid, char *dst, long long src, size_t nbytes) {
  for (int i = 0; i < nbytes; ) {
    *(long long *)(&dst[i]) = ptrace(PTRACE_PEEKDATA, pid, src + i, 0);

    for (int j = 0; j < sizeof(long long); i++, j++) {
      if (dst[i + j] == 0)
        return 0;
    }
  }

  return -1;
}

int main(int argc, char *argv[]) {
  launch(&argv[1]);

  while (1) {
    int status;
    int pid = wait(&status);

    if (WIFEXITED(status)) {
      handle_exit(pid);
      continue;
    }

    if (WIFSTOPPED(status))
      switch (WSTOPSIG(status)) {
      case SIGTRAP | 0x80:
        handle_syscall(pid);
        break;
      }

    ptrace(PTRACE_SYSCALL, pid, 0, 0);
  }
}
