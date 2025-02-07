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

#define BYTEC sizeof(long long /* maaan */)

pid_t child;

int ptstrncpy(pid_t pid, char *dst, long long src, size_t nbytes);
int ptresolvefd(pid_t pid, char *dst, int fd);

void handle_access(pid_t pid, int dir, long long name, int writable, int fd) {
  if (writable)
    return;

  char buf[PATH_MAX];
  ptstrncpy(pid, buf, name, PATH_MAX);

  printf("[pid %i] access '%s' in %d = %d\n", pid, buf, dir, fd);
  if (fd < 0)
    printf("[pid %i] %s\n", pid, strerror(-fd));
}

void handle_close(pid_t pid, int fd, int ret) {
  if (ret == 0)
    printf("[pid %i] close %d\n", pid, fd);
}

bool in_syscall = false;

void handle_syscall(pid_t pid) {
  if ((in_syscall = !in_syscall))
    return;

  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, pid, 0, &regs);

  // this bit is arch-dependent, syscall(2)
  switch (regs.orig_rax) {
  case SYS_access:
    handle_access(pid, AT_FDCWD, regs.rdi, regs.rsi & W_OK, regs.rax);
    break;
  case SYS_faccessat:
    handle_access(pid, regs.rdi, regs.rsi, regs.rdx & W_OK, regs.rax);
    break;
  case SYS_open:
    handle_access(pid, AT_FDCWD, regs.rdi, regs.rsi & (O_WRONLY | O_RDWR), regs.rax);
    break;
  case SYS_openat:
    handle_access(pid, regs.rdi, regs.rsi, regs.rdx & (O_WRONLY | O_RDWR), regs.rax);
    break;
  case SYS_close:
    handle_close(pid, regs.rdi, regs.rax);
    break;
  }
}

void launch(char *argv[]) {
  if ((child = fork())) {
    wait(0);

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD |
      PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
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
  for (int i = 0; i < nbytes; i += BYTEC) {
    *(long long *)(&dst[i]) = ptrace(PTRACE_PEEKDATA, pid, src + i, 0);

    if (strnlen(dst + i, BYTEC) < BYTEC)
      return 0;
  }

  return -1;
}

int main(int argc, char *argv[]) {
  launch(&argv[1]);

  while (1) {
    int status;
    int pid = wait(&status);

    if (WIFEXITED(status)) {
      if (pid == child)
        exit(0);
      continue;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
      handle_syscall(pid);

    ptrace(PTRACE_SYSCALL, pid, 0, 0);
  }
}
