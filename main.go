package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	pathlib "path"
	"syscall"
	"unsafe"
)

const AtCwd = math.MaxUint32 - 99

type procCtx struct {
	inSys  bool
	cwd    string
	fildes []string
}

var child int
var procs = make(map[int]*procCtx)

func handleNewProc(pid int) (proc *procCtx) {
	proc = new(procCtx)
	proc.cwd, _ = os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	proc.fildes = []string{"/dev/stdin", "/dev/stdout", "/dev/stderr"}

	procs[pid] = proc
	return
}

func handleExit(pid int, status syscall.WaitStatus) {
	if pid == child {
		os.Exit(status.ExitStatus())
	}

	delete(procs, pid)
}

func handleNewFile(proc *procCtx, fd int, path string) {
	for len(proc.fildes) <= fd {
		proc.fildes = append(proc.fildes, "")
	}

	proc.fildes[fd] = path
}

func handleSysEnd(pid int, proc *procCtx, regs *syscall.PtraceRegs) {
	var (
		buf [syscall.PathMax]byte

		dir, path string
	)

	switch regs.Orig_rax {
	case syscall.SYS_OPEN:
		panic("open")
	case syscall.SYS_OPENAT:
		if int32(regs.Rax) < 0 {
			return
		}

		syscall.PtracePeekData(pid, uintptr(regs.Rsi), buf[:])
		path = unsafe.String(&buf[0], bytes.IndexByte(buf[:], 0))

		if !pathlib.IsAbs(path) && path != "" {
			fmt.Println(path, regs.Rax)
			if regs.Rdi == uint64(AtCwd) {
				dir = proc.cwd
			} else {
				dir = proc.fildes[regs.Rdi]
			}

			path = pathlib.Join(dir, path)
		}

		handleNewFile(proc, int(regs.Rax), path)
	case syscall.SYS_ACCESS:
		syscall.PtracePeekData(pid, uintptr(regs.Rdi), buf[:])
		path = unsafe.String(&buf[0], bytes.IndexByte(buf[:], 0))
	case syscall.SYS_FACCESSAT:
		panic("faccessat")
	}
}

func handleSys(pid int, regs *syscall.PtraceRegs) {
	proc, ok := procs[pid]
	if !ok {
		proc = handleNewProc(pid)
	}
	if proc.inSys = !proc.inSys; proc.inSys {
		return
	}

	handleSysEnd(pid, proc, regs)
}

func launchProc(args []string) (err error) {
	var (
		path string

		attr = syscall.ProcAttr{
			Files: []uintptr{0, 1, 2},
			Env:   os.Environ(),
			Sys:   &syscall.SysProcAttr{Ptrace: true},
		}
		opts = syscall.PTRACE_O_TRACEFORK |
			syscall.PTRACE_O_TRACEVFORK |
			syscall.PTRACE_O_TRACECLONE |
			syscall.PTRACE_O_TRACESYSGOOD
	)

	if path, err = exec.LookPath(args[0]); err != nil {
		return
	}
	if child, err = syscall.ForkExec(path, args, &attr); err != nil {
		return
	}
	if _, err = syscall.Wait4(child, nil, 0, nil); err != nil {
		return
	}
	if err = syscall.PtraceSetOptions(child, opts); err != nil {
		return
	}
	syscall.PtraceSyscall(child, 0)

	return
}

func trace() (err error) {
	var (
		pid int

		status syscall.WaitStatus
		regs   syscall.PtraceRegs
	)

	for {
		if pid, err = syscall.Wait4(0, &status, 0, nil); err != nil {
			return
		}

		if status.Exited() {
			handleExit(pid, status)
			continue
		}

		if status.Stopped() && status.StopSignal() == syscall.SIGTRAP|0x80 {
			syscall.PtraceGetRegs(pid, &regs)
			handleSys(pid, &regs)
		}

		syscall.PtraceSyscall(pid, 0)
	}
}

func main() {
	i := 1
loop:
	for i < len(os.Args) {
		arg := os.Args[i]
		switch arg {
		case "--":
			break loop
		case "-h", "--help":
			fmt.Println("usage: watchtrace [options] [command...]")
			os.Exit(0)
		default:
			if arg[0] == '-' {
				panic(fmt.Sprintf("unknown option: %s", arg))
			}
			break loop
		}
		i += 1
	}

	if err := launchProc(os.Args[i:]); err != nil {
		panic(err)
	}

	if err := trace(); err != nil {
		panic(err)
	}
}
