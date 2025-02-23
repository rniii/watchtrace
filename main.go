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
	proc.fildes = make([]string, 3)

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

type fmode int

const (
	rd   fmode = 4
	wr   fmode = 2
	rdwr fmode = rd | wr
)

func handleSysEnd(pid int, proc *procCtx, regs *syscall.PtraceRegs) {
	var (
		buf  [syscall.PathMax]byte
		path string
		mode fmode
	)

	switch regs.Orig_rax {
	case syscall.SYS_OPEN:
		panic("open")
	case syscall.SYS_OPENAT:
		if int32(regs.Rax) < 0 {
			return
		}

		switch {
		case regs.Rdx&syscall.O_WRONLY != 0:
			mode = wr
		case regs.Rdx&syscall.O_RDWR != 0:
			mode = rdwr
		default:
			mode = rd
		}

		path = peekPath(pid, uintptr(regs.Rsi), buf[:])

		if !pathlib.IsAbs(path) && path != "" {
			switch {
			case int(regs.Rdi) == AtCwd:
				path = pathlib.Join(proc.cwd, path)
			case int(regs.Rdi) < len(proc.fildes):
				path = pathlib.Join(proc.fildes[regs.Rdi], path)
			default:
				return
			}
		}

		handleNewFile(proc, int(regs.Rax), path)
	case syscall.SYS_ACCESS:
		mode = fmode(regs.Rsi)&6
		if mode == 0 {
			mode = rd
		}

		path = peekPath(pid, uintptr(regs.Rdi), buf[:])
	case syscall.SYS_FACCESSAT:
		panic("faccessat")
	}

	if path != "" {
		fmt.Println(mode, path)
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

func peekPath(pid int, addr uintptr, dst []byte) string {
	syscall.PtracePeekData(pid, addr, dst)
	return unsafe.String(&dst[0], bytes.IndexByte(dst, 0))
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

	return nil
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
