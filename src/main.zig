pub fn main() !void {
    const child = c.fork();

    if (child == 0) {
        ptrace(c.PTRACE_TRACEME, 0, 0, 0);
        _ = c.raise(c.SIGSTOP);
        _ = c.execvp(std.os.argv[1], std.os.argv[1..].ptr);
        unreachable;
    }

    var pid: c.pid_t = undefined;
    var buf: [4096]u8 = undefined;
    var regs: c.user_regs_struct = undefined;
    var status: c_int = undefined;
    var in_syscall = false;

    _ = c.wait(null);

    const opts = c.PTRACE_O_TRACEFORK |
        c.PTRACE_O_TRACEVFORK |
        c.PTRACE_O_TRACECLONE;

    ptrace(c.PTRACE_SETOPTIONS, child, 0, opts);
    ptrace(c.PTRACE_CONT, child, 0, 0);

    while (true) {
        pid = c.wait(&status);
        if (pid == 0 or (c.WIFEXITED(status) and pid == child))
            break;
        if (c.WIFSIGNALED(status) and c.WSTOPSIG(status) != c.SIGTRAP)
            continue;

        ptrace(c.PTRACE_GETREGS, pid, 0, @intFromPtr(&regs));

        if (!in_syscall) switch (regs.orig_rax) {
            c.SYS_openat => std.debug.print("[pid {}] openat '{s}' = {}\n", .{
                pid, peekString(pid, regs.rsi, &buf), regs.rax,
            }),
            else => {},
        };

        ptrace(c.PTRACE_SYSCALL, pid, 0, 0);
        in_syscall = !in_syscall;
    }
}

fn peekString(pid: c_int, addr: usize, buf: []u8) []u8 {
    var i: usize = 0;
    while (true) : (i += @sizeOf(usize)) {
        const word = buf[i .. i + @sizeOf(usize)];
        ptrace(c.PTRACE_PEEKDATA, pid, addr + i, @intFromPtr(word.ptr));

        if (std.mem.indexOfScalar(u8, word, 0)) |j|
            return buf[0 .. i + j];
    }
}

fn ptrace(comptime op: c_int, pid: c.pid_t, addr: usize, data: usize) void {
    const result = linux.syscall4(.ptrace, op, @intCast(pid), addr, data);
    if (@as(isize, @bitCast(result)) < 0) {
        c.perror("ptrace");
        unreachable;
    }
}

const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
    @cInclude("sys/ptrace.h");
    @cInclude("sys/reg.h");
    @cInclude("sys/syscall.h");
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
});
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const assert = std.debug.assert;
