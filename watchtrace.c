#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define BYTEC sizeof(long long /* maaan */)

void remote_strcpy(pid_t pid, char *dst, long long addr, int nbytes) {
  for (int i = 0; i < nbytes; i += BYTEC) {
    *(long long *)(&dst[i]) = ptrace(PTRACE_PEEKDATA, pid, addr + i, 0);

    if (strnlen(dst + i, BYTEC) < BYTEC)
      return;
  }
}

void handle_access(pid_t pid, long long dir, long long name, int writable) {
  if (writable) return;

  char buf[PATH_MAX];
  remote_strcpy(pid, buf, name, PATH_MAX);

  printf("access '%s'\n", buf);
}

int main(int argc, char *argv[]) {
  int child = fork();

  if (child == 0) {
    ptrace(PTRACE_TRACEME, 0);
    raise(SIGSTOP);
    execvp(argv[1], &argv[1]);
  }

  wait(0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD |
    PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
  ptrace(PTRACE_CONT, child, 0, 0);

  while (1) {
    int status;
    int pid = wait(&status);
    if (WIFEXITED(status)) {
      if (pid == child) exit(0);
      continue;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, pid, 0, &regs);

      switch (regs.orig_rax) {
        case SYS_access:
          handle_access(pid, AT_FDCWD, regs.rdi, regs.rsi & W_OK); break;
        case SYS_faccessat:
          handle_access(pid, regs.rdi, regs.rsi, regs.rdx & W_OK); break;
        case SYS_open:
          handle_access(pid, AT_FDCWD, regs.rdi, regs.rsi & (O_WRONLY | O_RDWR)); break;
        case SYS_openat:
          handle_access(pid, regs.rdi, regs.rsi, regs.rsi & (O_WRONLY | O_RDWR)); break;
      }
    }

    ptrace(PTRACE_SYSCALL, pid, 0, 0);
  }
}
