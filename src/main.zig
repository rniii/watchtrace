pub fn main() !void {
    const pid = c.fork();

    if (pid == 0) {
        ptrace(c.PTRACE_TRACEME, 0, null, null);
        _ = c.execvp(std.os.argv[1], std.os.argv[1..].ptr);
        unreachable;
    }

    var buf: [4096]u8 = undefined;
    var regs: c.user_regs_struct = undefined;
    var in_syscall = false;

    while (!c.WIFEXITED(wait())) {
        ptrace(c.PTRACE_GETREGS, pid, null, &regs);

        if (!in_syscall) switch (regs.orig_rax) {
            c.SYS_openat => std.debug.print("openat '{s}' = {}\n", .{ peekString(pid, regs.rsi, &buf), regs.rax }),
            else => {},
        };

        ptrace(c.PTRACE_SYSCALL, pid, null, null);
        in_syscall = !in_syscall;
    }
}

fn peekString(pid: c_int, addr: usize, buf: []u8) []u8 {
    var i: usize = 0;
    while (true) : (i += @sizeOf(usize)) {
        const word = buf[i .. i + @sizeOf(usize)];
        ptrace(c.PTRACE_PEEKDATA, pid, @ptrFromInt(addr + i), (word.ptr));

        if (std.mem.indexOfScalar(u8, word, 0)) |j|
            return buf[0 .. i + j];
    }
}

fn ptrace(comptime op: c_int, pid: c.pid_t, addr: ?*anyopaque, data: ?*anyopaque) void {
    const res = linux.syscall4(
        .ptrace,
        op,
        @intCast(pid),
        @intFromPtr(addr),
        @intFromPtr(data),
    );
    std.debug.assert(res == 0);
}

fn wait() c_int {
    var status: c_int = undefined;
    _ = c.wait(&status);
    return status;
}

const c = @cImport({
    @cInclude("fcntl.h");
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
const SYS = linux.SYS;
