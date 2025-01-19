pub fn main() !void {
    const child = c.fork();

    if (child == 0) {
        ptrace(c.PTRACE_TRACEME, 0, 0, 0);
        _ = c.raise(c.SIGSTOP);
        _ = c.execvp(std.os.argv[1], std.os.argv[1..].ptr);
        unreachable;
    }

    _ = c.wait(null);

    ptrace(c.PTRACE_SETOPTIONS, child, 0, c.PTRACE_O_TRACESYSGOOD |
        c.PTRACE_O_TRACEFORK |
        c.PTRACE_O_TRACEVFORK |
        c.PTRACE_O_TRACECLONE);
    ptrace(c.PTRACE_CONT, child, 0, 0);

    while (true) {
        var status: c_int = undefined;
        const pid = c.wait(&status);

        if (c.WIFEXITED(status)) if (pid == child)
            break
        else
            continue;

        if (c.WIFSTOPPED(status) and c.WSTOPSIG(status) == c.SIGTRAP | 0x80) {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            var regs: c.user_regs_struct = undefined;
            ptrace(c.PTRACE_GETREGS, pid, 0, @intFromPtr(&regs));

            switch (@as(linux.SYS, @enumFromInt(regs.orig_rax))) {
                .access => if (regs.rsi & c.W_OK == 0)
                    std.debug.print("access     {s}\n", .{
                        peekString(pid, regs.rdi, &buf),
                    }),
                .open => if (regs.rsi & c.O_WRONLY == 0 and regs.rsi & c.O_RDWR == 0)
                    std.debug.print("open       {s}\n", .{
                        peekString(pid, regs.rdi, &buf),
                    }),
                .faccessat => if (regs.rdx & c.W_OK == 0)
                    std.debug.print("faccessat  {s}\n", .{
                        resolvePath(pid, @bitCast(@as(u32, @truncate(regs.rdi))), regs.rsi, &buf),
                    }),
                .openat => if (regs.rdx & c.O_WRONLY == 0 and regs.rdx & c.O_RDWR == 0)
                    std.debug.print("openat     {s}\n", .{
                        resolvePath(pid, @bitCast(@as(u32, @truncate(regs.rdi))), regs.rsi, &buf),
                    }),
                else => {},
            }
        }

        ptrace(c.PTRACE_SYSCALL, pid, 0, 0);
    }
}

fn resolvePath(pid: c_int, dirfd: c_int, path_addr: usize, buf: []u8) []u8 {
    const parent = if (dirfd == c.AT_FDCWD)
        std.fmt.bufPrintZ(buf, "/proc/{}/cwd", .{pid}) catch unreachable
    else
        std.fmt.bufPrintZ(buf, "/proc/{}/fd/{}", .{ pid, dirfd }) catch unreachable;

    const resolved = std.posix.readlinkZ(parent, buf) catch unreachable;

    const path = peekString(pid, path_addr, buf[resolved.len + 1 ..]);
    if (path.len > 0 and path[0] == '/')
        return path;

    buf[resolved.len] = '/';
    return buf[0 .. resolved.len + path.len + 1];
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
