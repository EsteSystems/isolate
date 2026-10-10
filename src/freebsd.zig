//! FreeBSD-specific isolation implementation
//!
//! This module provides FreeBSD jail-based process isolation using native
//! Zig implementations where possible, with C interop for jail syscalls.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const caps = @import("caps.zig");
const syscheck = @import("syscheck.zig");
const registry = @import("registry.zig");

// Only compile on FreeBSD
comptime {
    if (builtin.os.tag != .freebsd) {
        @compileError("freebsd.zig can only be compiled on FreeBSD");
    }
}

// ============================================================================
// C Imports for FreeBSD APIs
// ============================================================================

const c = @cImport({
    // Release builds define _FORTIFY_SOURCE, and the fortified libc wrappers do
    // not survive translate-c; they add nothing for calls made from Zig.
    @cUndef("_FORTIFY_SOURCE");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("sys/param.h");
    @cInclude("sys/jail.h");
    @cInclude("sys/mount.h");
    @cInclude("sys/uio.h");
    @cInclude("sys/wait.h");
    @cInclude("jail.h"); // For jailparam functions
    @cInclude("pwd.h");
    @cInclude("grp.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("dirent.h");
    @cInclude("fts.h");
    @cInclude("signal.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub const PATH_MAX = c.PATH_MAX;

/// Root-owned directory that holds the per-instance directories. Only root
/// can create entries in /var/run, so nobody else can plant a path or a
/// symlink here for root to follow.
const runtime_dir = registry.REGISTRY_DIR;

/// The per-instance directory that contains the jail root (`<dir>/root`)
fn instanceDir(jail_path: []const u8) []const u8 {
    return std.fs.path.dirname(jail_path) orelse jail_path;
}

/// The instance directory for a jail path read back from the registry, or
/// null unless the path has exactly the shape createIsolation produces:
/// <runtime_dir>/inst-XXXXXX/root. Teardown deletes this directory as root,
/// so nothing else is ever accepted.
fn trustedInstanceDir(jail_path: []const u8) ?[]const u8 {
    const prefix = runtime_dir ++ "/inst-";
    const suffix = "/root";
    if (jail_path.len != prefix.len + 6 + suffix.len) return null;
    if (!std.mem.startsWith(u8, jail_path, prefix)) return null;
    if (!std.mem.endsWith(u8, jail_path, suffix)) return null;
    for (jail_path[prefix.len..][0..6]) |ch| {
        if (!std.ascii.isAlphanumeric(ch)) return null;
    }
    return jail_path[0 .. jail_path.len - suffix.len];
}

/// Whether `username` is one isolate creates itself: app-<digits>
fn isEphemeralUsername(username: []const u8) bool {
    const prefix = "app-";
    if (username.len <= prefix.len or !std.mem.startsWith(u8, username, prefix)) return false;
    for (username[prefix.len..]) |ch| {
        if (!std.ascii.isDigit(ch)) return false;
    }
    return true;
}

// stat(2) against std.c.Stat; std.c.stat is missing its extern in Zig 0.16
extern "c" fn stat(path: [*:0]const u8, buf: *std.c.Stat) c_int;

// libc's environment pointer. FreeBSD has no clearenv(3); its setenv(3)
// notices when `environ` has been replaced and continues from the new
// array, so pointing it at an empty one clears the environment.
extern var environ: [*c][*c]u8;
var empty_environ = [_:null]?[*:0]u8{};

/// Unbuffered, streaming stdout writer (see stdoutWriter in main.zig)
fn stdoutWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stdout().writerStreaming(io, &.{});
}

// ============================================================================
// Error Types
// ============================================================================

pub const JailError = error{
    JailCreateFailed,
    JailAttachFailed,
    JailRemoveFailed,
    JailParamFailed,
    UserCreateFailed,
    UserDeleteFailed,
    UserNotFound,
    MountFailed,
    UnmountFailed,
    FilesystemSetupFailed,
    ResourceLimitFailed,
    ForkFailed,
    ExecFailed,
    PermissionDenied,
    OutOfMemory,
    InvalidPath,
};

// ============================================================================
// Jail State - Global state for cleanup
// ============================================================================

var jail_state = struct {
    jail_id: i32 = -1,
    ephemeral_username: [64]u8 = [_]u8{0} ** 64,
    jail_root_path: [PATH_MAX]u8 = [_]u8{0} ** PATH_MAX,

    pub fn setJailId(self: *@This(), jid: i32) void {
        self.jail_id = jid;
    }

    pub fn setUsername(self: *@This(), name: []const u8) void {
        const len = @min(name.len, self.ephemeral_username.len - 1);
        @memcpy(self.ephemeral_username[0..len], name[0..len]);
        self.ephemeral_username[len] = 0;
    }

    pub fn setJailPath(self: *@This(), path: []const u8) void {
        const len = @min(path.len, self.jail_root_path.len - 1);
        @memcpy(self.jail_root_path[0..len], path[0..len]);
        self.jail_root_path[len] = 0;
    }

    pub fn getUsername(self: *const @This()) []const u8 {
        const len = std.mem.findScalar(u8, &self.ephemeral_username, 0) orelse self.ephemeral_username.len;
        return self.ephemeral_username[0..len];
    }

    pub fn getJailPath(self: *const @This()) []const u8 {
        const len = std.mem.findScalar(u8, &self.jail_root_path, 0) orelse self.jail_root_path.len;
        return self.jail_root_path[0..len];
    }

}{};

// Jail state accessors, used by the parent process once the child has
// reported its state over the pipe
pub fn freebsd_get_jail_id() c_int {
    return jail_state.jail_id;
}

pub fn freebsd_set_jail_id(jid: c_int) void {
    jail_state.setJailId(jid);
}

pub fn freebsd_get_username() [*c]const u8 {
    return &jail_state.ephemeral_username;
}

pub fn freebsd_set_username(name: [*c]const u8) void {
    if (name != null) {
        const slice = std.mem.span(name);
        jail_state.setUsername(slice);
    }
}

pub fn freebsd_get_jail_path() [*c]const u8 {
    return &jail_state.jail_root_path;
}

pub fn freebsd_set_jail_path(path: [*c]const u8) void {
    if (path != null) {
        const slice = std.mem.span(path);
        jail_state.setJailPath(slice);
    }
}

// ============================================================================
// Filesystem Operations
// ============================================================================

/// Create a directory and all parent directories (like mkdir -p)
pub fn mkdirp(path: []const u8) !void {
    // Use Zig's standard library for this
    var path_buf: [PATH_MAX]u8 = undefined;
    if (path.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    // Create parent directories
    var i: usize = 1;
    while (i < path.len) : (i += 1) {
        if (path_buf[i] == '/') {
            path_buf[i] = 0;
            const result = std.c.mkdir(@ptrCast(&path_buf), 0o755);
            if (result != 0 and std.c._errno().* != c.EEXIST) {
                return error.FilesystemSetupFailed;
            }
            path_buf[i] = '/';
        }
    }

    // Create final directory
    const result = std.c.mkdir(@ptrCast(&path_buf), 0o755);
    if (result != 0 and std.c._errno().* != c.EEXIST) {
        return error.FilesystemSetupFailed;
    }
}

/// Copy a file from src to dst
pub fn copyFile(src: []const u8, dst: []const u8) !void {
    var src_buf: [PATH_MAX]u8 = undefined;
    var dst_buf: [PATH_MAX]u8 = undefined;

    if (src.len >= PATH_MAX or dst.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(src_buf[0..src.len], src);
    src_buf[src.len] = 0;
    @memcpy(dst_buf[0..dst.len], dst);
    dst_buf[dst.len] = 0;

    const src_fd = c.open(&src_buf, c.O_RDONLY);
    if (src_fd < 0) return error.FilesystemSetupFailed;
    defer _ = c.close(src_fd);

    var st: std.c.Stat = undefined;
    if (std.c.fstat(src_fd, &st) < 0) return error.FilesystemSetupFailed;

    const dst_fd = c.open(&dst_buf, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, @as(c_uint, st.mode));
    if (dst_fd < 0) return error.FilesystemSetupFailed;
    defer _ = c.close(dst_fd);

    var buf: [8192]u8 = undefined;
    while (true) {
        const nread = c.read(src_fd, &buf, buf.len);
        if (nread < 0) return error.FilesystemSetupFailed;
        if (nread == 0) break;

        var written: isize = 0;
        while (written < nread) {
            const n = c.write(dst_fd, @ptrCast(&buf[@intCast(written)]), @intCast(nread - written));
            if (n < 0) return error.FilesystemSetupFailed;
            written += n;
        }
    }
}

/// Recursively remove a directory tree. Never descends into another
/// filesystem (FTS_XDEV): a mount that is still in place under `path` - a
/// nullfs mount of a host directory, the workspace, devfs - keeps its
/// contents; only the mount point directory itself is attempted (and fails
/// with EBUSY). Returns an error if anything could not be removed.
pub fn rmrf(path: []const u8) !void {
    var path_buf: [PATH_MAX]u8 = undefined;
    if (path.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    var paths: [2][*c]u8 = .{ &path_buf, null };

    // No FTS_NOSTAT: with it, fts reports regular files as FTS_NSOK and
    // needs stat data it does not have for FTS_XDEV
    const fts = c.fts_open(@ptrCast(&paths), c.FTS_PHYSICAL | c.FTS_NOCHDIR | c.FTS_XDEV, null);
    if (fts == null) return error.FilesystemSetupFailed;
    defer _ = c.fts_close(fts);

    var failed = false;
    while (c.fts_read(fts)) |ent| {
        switch (ent.*.fts_info) {
            c.FTS_D => {
                // Directory - will be processed again as FTS_DP
            },
            c.FTS_DP => {
                // Directory after children processed - remove it
                if (c.rmdir(ent.*.fts_accpath) != 0) failed = true;
            },
            c.FTS_F, c.FTS_SL, c.FTS_SLNONE, c.FTS_DEFAULT, c.FTS_NSOK => {
                // File or symlink - remove it
                if (c.unlink(ent.*.fts_accpath) != 0) failed = true;
            },
            else => {},
        }
    }

    if (failed) return error.FilesystemSetupFailed;
}

// ============================================================================
// Mount Operations
// ============================================================================

/// Mount a nullfs filesystem
pub fn mountNullfs(source: []const u8, target: []const u8, readonly: bool) !void {
    var source_buf: [PATH_MAX]u8 = undefined;
    var target_buf: [PATH_MAX]u8 = undefined;

    if (source.len >= PATH_MAX or target.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(source_buf[0..source.len], source);
    source_buf[source.len] = 0;
    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;

    var fstype: [8]u8 = "nullfs\x00\x00".*;

    var iov: [6]c.struct_iovec = undefined;

    // fstype
    iov[0].iov_base = @constCast(@ptrCast("fstype"));
    iov[0].iov_len = 7; // "fstype" + null
    iov[1].iov_base = &fstype;
    iov[1].iov_len = 7; // "nullfs" + null

    // fspath (target)
    iov[2].iov_base = @constCast(@ptrCast("fspath"));
    iov[2].iov_len = 7; // "fspath" + null
    iov[3].iov_base = &target_buf;
    iov[3].iov_len = target.len + 1;

    // target (source)
    iov[4].iov_base = @constCast(@ptrCast("target"));
    iov[4].iov_len = 7; // "target" + null
    iov[5].iov_base = &source_buf;
    iov[5].iov_len = source.len + 1;

    const flags: c_int = if (readonly) c.MNT_RDONLY else 0;

    if (c.nmount(&iov, 6, flags) != 0) {
        return error.MountFailed;
    }
}

/// Mount devfs
pub fn mountDevfs(target: []const u8) !void {
    var target_buf: [PATH_MAX]u8 = undefined;
    if (target.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(target_buf[0..target.len], target);
    target_buf[target.len] = 0;

    var fstype: [8]u8 = "devfs\x00\x00\x00".*;

    var iov: [4]c.struct_iovec = undefined;

    // fstype
    iov[0].iov_base = @constCast(@ptrCast("fstype"));
    iov[0].iov_len = 7;
    iov[1].iov_base = &fstype;
    iov[1].iov_len = 6; // "devfs" + null

    // fspath
    iov[2].iov_base = @constCast(@ptrCast("fspath"));
    iov[2].iov_len = 7;
    iov[3].iov_base = &target_buf;
    iov[3].iov_len = target.len + 1;

    if (c.nmount(&iov, 4, 0) != 0) {
        return error.MountFailed;
    }
}

/// Unmount a filesystem (best effort)
pub fn unmount(path: []const u8) void {
    var path_buf: [PATH_MAX]u8 = undefined;
    if (path.len >= PATH_MAX) return;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    // Try normal unmount first
    if (c.unmount(&path_buf, 0) != 0) {
        // Try force unmount
        _ = c.unmount(&path_buf, c.MNT_FORCE);
    }
}

/// Whether `path` is `root` itself or somewhere below it
fn isPathUnder(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    return path.len == root.len or path[root.len] == '/';
}

/// Unmount every filesystem mounted at or below `root`, deepest first, so
/// that nested mounts come off before the mounts they sit on. Uses the
/// kernel's mount table rather than a fixed list of expected mount points:
/// every `filesystem:` rule in the capability file adds a mount, and a
/// mount that was missed here would otherwise have its host contents
/// deleted by the following rmrf. Stops when nothing under `root` is
/// mounted or when a mount cannot be removed even with MNT_FORCE.
fn unmountAllUnder(root: []const u8) void {
    var last_buf: [PATH_MAX]u8 = undefined;
    var last: []const u8 = "";

    while (true) {
        var mounts: [*c]c.struct_statfs = null;
        const count = c.getmntinfo(&mounts, c.MNT_NOWAIT);
        if (count <= 0) return;

        // Pick the deepest mount point under root
        var deepest: ?[]const u8 = null;
        for (mounts[0..@intCast(count)]) |*m| {
            const mnt = std.mem.sliceTo(&m.f_mntonname, 0);
            if (!isPathUnder(mnt, root)) continue;
            if (deepest == null or mnt.len > deepest.?.len) deepest = mnt;
        }
        const target = deepest orelse return;

        // No progress since the last attempt: give up rather than spin
        if (std.mem.eql(u8, target, last)) return;
        if (target.len >= last_buf.len) return;
        @memcpy(last_buf[0..target.len], target);
        last = last_buf[0..target.len];

        unmount(target);
    }
}

/// Tear down a per-instance directory: unmount everything mounted below
/// it, then remove the tree (without crossing into anything still mounted).
pub fn cleanupInstanceDir(inst_dir: []const u8) !void {
    unmountAllUnder(inst_dir);
    try rmrf(inst_dir);
}

// ============================================================================
// User Management
// ============================================================================

/// Safe command execution using fork/exec
fn safeExec(path: []const u8, argv: []const ?[*:0]const u8) !void {
    var path_buf: [PATH_MAX]u8 = undefined;
    if (path.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;

    if (pid == 0) {
        // Child process - redirect stdout/stderr to /dev/null
        const devnull = c.open("/dev/null", c.O_WRONLY);
        if (devnull >= 0) {
            _ = c.dup2(devnull, c.STDOUT_FILENO);
            _ = c.dup2(devnull, c.STDERR_FILENO);
            _ = c.close(devnull);
        }

        _ = c.execv(&path_buf, @ptrCast(argv.ptr));
        c._exit(127);
    }

    // Parent - wait for child
    var status: c_int = undefined;
    _ = c.waitpid(pid, &status, 0);

    if (c.WIFEXITED(status) and c.WEXITSTATUS(status) == 0) {
        return;
    }
    return error.ExecFailed;
}

/// The comment (gecos) field of every user isolate creates. Together with
/// the app-<digits> name it identifies a user as one of ours.
const ephemeral_user_comment = "Isolate ephemeral user";

/// Create an ephemeral user
pub fn createUser(username: []const u8) !struct { uid: u32, gid: u32 } {
    var name_buf: [64]u8 = undefined;
    if (username.len >= name_buf.len) return error.InvalidPath;

    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    // Check if user already exists
    const pw = c.getpwnam(&name_buf);
    if (pw != null) {
        return .{
            .uid = pw.*.pw_uid,
            .gid = pw.*.pw_gid,
        };
    }

    // Create user with pw command
    const argv: [11]?[*:0]const u8 = .{
        "/usr/sbin/pw",
        "useradd",
        "-n",
        @ptrCast(&name_buf),
        "-s",
        "/usr/sbin/nologin",
        "-d",
        "/tmp",
        "-c",
        ephemeral_user_comment,
        null,
    };

    safeExec("/usr/sbin/pw", &argv) catch return error.UserCreateFailed;

    // Verify user was created
    const pw2 = c.getpwnam(&name_buf);
    if (pw2 == null) return error.UserCreateFailed;

    return .{
        .uid = pw2.*.pw_uid,
        .gid = pw2.*.pw_gid,
    };
}

/// Delete an ephemeral user
pub fn deleteUser(username: []const u8) void {
    var name_buf: [64]u8 = undefined;
    if (username.len >= name_buf.len) return;

    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const argv: [5]?[*:0]const u8 = .{
        "/usr/sbin/pw",
        "userdel",
        "-n",
        @ptrCast(&name_buf),
        null,
    };

    safeExec("/usr/sbin/pw", &argv) catch {};
}

/// Look up user by name
pub fn lookupUser(username: []const u8) !struct { uid: u32, gid: u32 } {
    var name_buf: [64]u8 = undefined;
    if (username.len >= name_buf.len) return error.InvalidPath;

    @memcpy(name_buf[0..username.len], username);
    name_buf[username.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;

    return .{
        .uid = pw.*.pw_uid,
        .gid = pw.*.pw_gid,
    };
}

// ============================================================================
// Resource Limits (rctl)
// ============================================================================

// rctl syscall wrappers - not available in standard headers
extern fn rctl_add_rule(inbufp: [*]const u8, inbuflen: usize, outbufp: [*]u8, outbuflen: usize) c_int;
extern fn rctl_remove_rule(inbufp: [*]const u8, inbuflen: usize, outbufp: [*]u8, outbuflen: usize) c_int;
extern fn rctl_get_rules(inbufp: [*]const u8, inbuflen: usize, outbufp: [*]u8, outbuflen: usize) c_int;

/// Prefix of every jail name isolate creates (isolate-<pid of the jailed process>)
const jail_name_prefix = "isolate-";

/// Remove every rctl rule attached to the named jail. Rules are keyed by
/// jail name and outlive the jail, so without this they pile up and - since
/// the name is derived from a PID - would apply to a later jail that
/// happens to get the same name.
pub fn removeResourceLimits(jail_name: []const u8) void {
    var filter_buf: [128]u8 = undefined;
    var out_buf: [16]u8 = undefined;
    const filter = std.fmt.bufPrintZ(&filter_buf, "jail:{s}", .{jail_name}) catch return;
    _ = rctl_remove_rule(filter.ptr, filter.len + 1, &out_buf, out_buf.len);
}

/// Same, for the jail of the instance whose jailed process had this PID
pub fn removeResourceLimitsForPid(pid: i32) void {
    var name_buf: [64]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, jail_name_prefix ++ "{d}", .{pid}) catch return;
    removeResourceLimits(name);
}

var rules_buf: [256 * 1024]u8 = undefined;

/// Remove the rctl rules of isolate jails that no longer exist. Returns
/// the number of jails whose rules were removed.
pub fn purgeStaleLimits() u32 {
    if (rctl_get_rules("::", 3, &rules_buf, rules_buf.len) != 0) return 0;
    const rules = std.mem.sliceTo(&rules_buf, 0);

    var purged: u32 = 0;
    var last_buf: [64]u8 = undefined;
    var last: []const u8 = "";

    var it = std.mem.splitScalar(u8, rules, ',');
    while (it.next()) |rule| {
        const prefix = "jail:" ++ jail_name_prefix;
        if (!std.mem.startsWith(u8, rule, prefix)) continue;
        const rest = rule["jail:".len..];
        const name = rest[0 .. std.mem.findScalar(u8, rest, ':') orelse continue];
        if (name.len >= last_buf.len or std.mem.eql(u8, name, last)) continue;

        var name_z: [64]u8 = undefined;
        @memcpy(name_z[0..name.len], name);
        name_z[name.len] = 0;
        if (c.jail_getid(&name_z) >= 0) continue; // jail still exists

        removeResourceLimits(name);
        @memcpy(last_buf[0..name.len], name);
        last = last_buf[0..name.len];
        purged += 1;
    }
    return purged;
}

// Cached system capabilities (detected once)
var cached_sys_caps: ?syscheck.SystemCapabilities = null;

fn getSystemCapabilities() syscheck.SystemCapabilities {
    if (cached_sys_caps) |caps_val| {
        return caps_val;
    }
    cached_sys_caps = syscheck.detect();
    return cached_sys_caps.?;
}

/// Add the rctl rules for the limits in the capability file. If a limit is
/// requested and cannot be applied, that is an error: the program must not
/// start unlimited.
pub fn setResourceLimits(io: std.Io, jail_name: []const u8, limits: caps.ResourceLimits) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var rule_buf: [256]u8 = undefined;
    var out_buf: [256]u8 = undefined;

    // Check if any limits are actually requested
    const has_limits = limits.memory_bytes != null or
        limits.max_processes != null or
        limits.max_files != null;

    if (!has_limits) {
        return;
    }

    // Check if racct is enabled
    const sys_caps = getSystemCapabilities();
    if (!sys_caps.racct_enabled) {
        syscheck.warnIfRacctDisabled(sys_caps, stdout) catch {};
        return error.ResourceLimitFailed;
    }

    if (limits.memory_bytes) |mem| {
        // The limit is on resident memory, and the action is sigkill:
        // memoryuse:deny denies nothing (the kernel only tries to page the
        // excess out, and the process keeps allocating). The kernel samples
        // usage about once a second, so a process can overshoot briefly
        // before it is killed.
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:memoryuse:sigkill={d}\x00", .{ jail_name, mem })) |formatted| {
            stdout.print("Setting memory limit: {d} bytes (process is killed above it)\n", .{mem}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Error: Failed to set memory limit (rctl error)\n", .{}) catch {};
                return error.ResourceLimitFailed;
            }
        } else |_| return error.ResourceLimitFailed;
    }

    if (limits.max_processes) |procs| {
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:maxproc:deny={d}\x00", .{ jail_name, procs })) |formatted| {
            stdout.print("Setting process limit: {d}\n", .{procs}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Error: Failed to set process limit (rctl error)\n", .{}) catch {};
                return error.ResourceLimitFailed;
            }
        } else |_| return error.ResourceLimitFailed;
    }

    if (limits.max_files) |files| {
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:openfiles:deny={d}\x00", .{ jail_name, files })) |formatted| {
            stdout.print("Setting file descriptor limit: {d}\n", .{files}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Error: Failed to set file limit (rctl error)\n", .{}) catch {};
                return error.ResourceLimitFailed;
            }
        } else |_| return error.ResourceLimitFailed;
    }
}

// ============================================================================
// Jail Management
// ============================================================================

/// Create a FreeBSD jail
pub fn createJail(io: std.Io, jail_name: []const u8, jail_path: []const u8, network_config: caps.NetworkConfig, sysv_ipc: bool) !i32 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    var name_buf: [64]u8 = undefined;
    var path_buf: [PATH_MAX]u8 = undefined;

    if (jail_name.len >= name_buf.len or jail_path.len >= PATH_MAX) {
        return error.InvalidPath;
    }

    @memcpy(name_buf[0..jail_name.len], jail_name);
    name_buf[jail_name.len] = 0;
    @memcpy(path_buf[0..jail_path.len], jail_path);
    path_buf[jail_path.len] = 0;

    // Check VNET availability if requested
    const use_vnet = switch (network_config.mode) {
        .vnet => blk: {
            const sys_caps = getSystemCapabilities();
            if (!sys_caps.vnet_available) {
                // Never fall back to the host's network: that would give the
                // program more than its capability file asks for
                syscheck.warnIfVnetUnavailable(sys_caps, stdout) catch {};
                return error.JailCreateFailed;
            }
            break :blk true;
        },
        else => false,
    };

    // Set up jail parameters - need more params for VNET
    var params: [12]c.struct_jailparam = undefined;
    var param_count: usize = 0;

    _ = c.jailparam_init(&params[param_count], "name");
    _ = c.jailparam_import(&params[param_count], &name_buf);
    param_count += 1;

    _ = c.jailparam_init(&params[param_count], "path");
    _ = c.jailparam_import(&params[param_count], &path_buf);
    param_count += 1;

    _ = c.jailparam_init(&params[param_count], "persist");
    _ = c.jailparam_import(&params[param_count], null);
    param_count += 1;

    _ = c.jailparam_init(&params[param_count], "allow.raw_sockets");
    _ = c.jailparam_import(&params[param_count], "false");
    param_count += 1;

    _ = c.jailparam_init(&params[param_count], "allow.socket_af");
    _ = c.jailparam_import(&params[param_count], "true");
    param_count += 1;

    // Network configuration based on mode
    if (use_vnet) {
        stdout.print("Creating VNET jail (isolated network stack)\n", .{}) catch {};
        _ = c.jailparam_init(&params[param_count], "vnet");
        _ = c.jailparam_import(&params[param_count], "new");
        param_count += 1;
    } else if (network_config.mode == .none) {
        stdout.print("Creating jail with no network access\n", .{}) catch {};
        _ = c.jailparam_init(&params[param_count], "ip4");
        _ = c.jailparam_import(&params[param_count], "disable");
        param_count += 1;
        _ = c.jailparam_init(&params[param_count], "ip6");
        _ = c.jailparam_import(&params[param_count], "disable");
        param_count += 1;
    } else {
        // inherit mode (default)
        _ = c.jailparam_init(&params[param_count], "ip4");
        _ = c.jailparam_import(&params[param_count], "inherit");
        param_count += 1;
        _ = c.jailparam_init(&params[param_count], "ip6");
        _ = c.jailparam_import(&params[param_count], "inherit");
        param_count += 1;
    }

    // The host's System V IPC objects are never shared with the jail
    _ = c.jailparam_init(&params[param_count], "allow.sysvipc");
    _ = c.jailparam_import(&params[param_count], "false");
    param_count += 1;

    // On request the jail gets System V shared memory, semaphores and
    // message queues of its own: a private namespace that the kernel
    // destroys with the jail. Without it those system calls fail.
    if (sysv_ipc) {
        stdout.print("Giving the jail its own System V IPC namespace\n", .{}) catch {};
        for ([_][:0]const u8{ "sysvshm", "sysvsem", "sysvmsg" }) |param| {
            _ = c.jailparam_init(&params[param_count], param.ptr);
            _ = c.jailparam_import(&params[param_count], "new");
            param_count += 1;
        }
    }

    stdout.print("Creating jail: {s} at {s}\n", .{ jail_name, jail_path }) catch {};

    const jid = c.jailparam_set(&params, @intCast(param_count), c.JAIL_CREATE);

    c.jailparam_free(&params, @intCast(param_count));

    if (jid < 0) {
        return error.JailCreateFailed;
    }

    stdout.print("Created jail {s} with JID {d}\n", .{ jail_name, jid }) catch {};
    jail_state.setJailId(jid);

    // Move interface into jail if VNET mode with interface specified
    if (use_vnet) {
        if (network_config.interface) |iface| {
            stdout.print("Moving interface {s} into jail\n", .{iface}) catch {};
            moveInterfaceToJail(jid, iface) catch {
                stdout.print("Error: Failed to move interface {s} into the jail (does it exist?)\n", .{iface}) catch {};
                return error.JailParamFailed;
            };

            // Configure IP address if specified
            if (network_config.ip_address) |ip| {
                stdout.print("Configuring IP address {s} on {s}\n", .{ ip, iface }) catch {};
                configureJailInterface(jid, iface, ip) catch {
                    stdout.print("Error: Failed to configure address {s} on {s}\n", .{ ip, iface }) catch {};
                    return error.JailParamFailed;
                };
            } else {
                stdout.print("Note: No network_ip set; {s} is in the jail but has no address\n", .{iface}) catch {};
            }
        } else {
            stdout.print("Note: VNET jail created but no interface specified (use --vnet <interface>)\n", .{}) catch {};
        }

        // A new network stack starts with an unconfigured loopback
        configureJailInterface(jid, "lo0", "127.0.0.1/8") catch {
            stdout.print("Error: Failed to configure loopback in jail\n", .{}) catch {};
            return error.JailParamFailed;
        };
    }

    return jid;
}

/// Move a network interface into a jail
fn moveInterfaceToJail(jid: i32, ifname: []const u8) !void {
    var ifname_buf: [64]u8 = undefined;
    var jid_buf: [16]u8 = undefined;

    if (ifname.len >= ifname_buf.len) return error.InvalidPath;

    @memcpy(ifname_buf[0..ifname.len], ifname);
    ifname_buf[ifname.len] = 0;

    const jid_str = std.fmt.bufPrint(&jid_buf, "{d}", .{jid}) catch return error.InvalidPath;
    jid_buf[jid_str.len] = 0;

    const argv: [5]?[*:0]const u8 = .{
        "/sbin/ifconfig",
        @ptrCast(&ifname_buf),
        "vnet",
        @ptrCast(&jid_buf),
        null,
    };

    safeExec("/sbin/ifconfig", &argv) catch return error.JailParamFailed;
}

/// Configure an interface that lives in a jail's network stack. Runs the
/// host's ifconfig with -j rather than executing anything inside the jail,
/// whose filesystem has no /sbin/ifconfig unless a rule happens to mount it.
fn configureJailInterface(jid: i32, ifname: []const u8, ip: []const u8) !void {
    var jid_buf: [16]u8 = undefined;
    var ifname_buf: [64]u8 = undefined;
    var ip_buf: [64]u8 = undefined;

    if (ifname.len >= ifname_buf.len or ip.len >= ip_buf.len) return error.InvalidPath;

    const jid_str = std.fmt.bufPrint(&jid_buf, "{d}", .{jid}) catch return error.InvalidPath;
    jid_buf[jid_str.len] = 0;

    @memcpy(ifname_buf[0..ifname.len], ifname);
    ifname_buf[ifname.len] = 0;

    @memcpy(ip_buf[0..ip.len], ip);
    ip_buf[ip.len] = 0;

    // ifconfig -j <jid> <ifname> inet <ip> up
    const argv: [8]?[*:0]const u8 = .{
        "/sbin/ifconfig",
        "-j",
        @ptrCast(&jid_buf),
        @ptrCast(&ifname_buf),
        "inet",
        @ptrCast(&ip_buf),
        "up",
        null,
    };

    safeExec("/sbin/ifconfig", &argv) catch return error.JailParamFailed;
}

/// Attach to a jail
pub fn attachToJail(io: std.Io, jid: i32) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print("Attaching to jail JID {d}\n", .{jid}) catch {};

    if (c.jail_attach(jid) != 0) {
        return error.JailAttachFailed;
    }
}

/// Run a command and return what it wrote to standard output
fn execCapture(path: [:0]const u8, argv: []const ?[*:0]const u8, out: []u8) ![]u8 {
    var fds: [2]c_int = undefined;
    if (c.pipe(&fds) != 0) return error.ForkFailed;

    const pid = c.fork();
    if (pid < 0) {
        _ = c.close(fds[0]);
        _ = c.close(fds[1]);
        return error.ForkFailed;
    }

    if (pid == 0) {
        _ = c.close(fds[0]);
        _ = c.dup2(fds[1], c.STDOUT_FILENO);
        _ = c.close(fds[1]);
        const devnull = c.open("/dev/null", c.O_WRONLY);
        if (devnull >= 0) _ = c.dup2(devnull, c.STDERR_FILENO);
        _ = c.execv(path.ptr, @ptrCast(argv.ptr));
        c._exit(127);
    }

    _ = c.close(fds[1]);
    var len: usize = 0;
    while (len < out.len) {
        const n = c.read(fds[0], out[len..].ptr, out.len - len);
        if (n <= 0) break;
        len += @intCast(n);
    }
    _ = c.close(fds[0]);

    var status: c_int = undefined;
    _ = c.waitpid(pid, &status, 0);
    if (!(c.WIFEXITED(status) and c.WEXITSTATUS(status) == 0)) return error.ExecFailed;
    return out[0..len];
}

/// Whether jail `jid` has a network stack of its own
fn jailHasOwnVnet(jid: i32) bool {
    var jid_val: c_int = jid;
    var vnet: c_int = 0;
    var iov = [_]c.struct_iovec{
        .{ .iov_base = @ptrCast(@constCast("jid")), .iov_len = 4 },
        .{ .iov_base = @ptrCast(&jid_val), .iov_len = @sizeOf(c_int) },
        .{ .iov_base = @ptrCast(@constCast("vnet")), .iov_len = 5 },
        .{ .iov_base = @ptrCast(&vnet), .iov_len = @sizeOf(c_int) },
    };
    if (c.jail_get(&iov, iov.len, 0) < 0) return false;
    return vnet == c.JAIL_SYS_NEW;
}

/// Move every interface of a VNET jail, other than its loopback, back to the
/// host. This has to happen before the jail is removed: a removed jail whose
/// network stack still holds kernel state (a TCP connection in TIME_WAIT is
/// enough) stays "dying" for a long time, and an interface inside it cannot
/// be reclaimed until it is finally gone.
fn reclaimInterfaces(jid: i32) void {
    if (!jailHasOwnVnet(jid)) return;

    var jid_buf: [16]u8 = undefined;
    const jid_z = std.fmt.bufPrintZ(&jid_buf, "{d}", .{jid}) catch return;

    var out_buf: [4096]u8 = undefined;
    const list_argv: [5]?[*:0]const u8 = .{ "/sbin/ifconfig", "-j", jid_z.ptr, "-l", null };
    const listing = execCapture("/sbin/ifconfig", &list_argv, &out_buf) catch return;

    var names = std.mem.tokenizeAny(u8, listing, " \t\r\n");
    while (names.next()) |ifname| {
        if (std.mem.startsWith(u8, ifname, "lo")) continue;
        var if_buf: [64]u8 = undefined;
        const if_z = std.fmt.bufPrintZ(&if_buf, "{s}", .{ifname}) catch continue;
        const argv: [5]?[*:0]const u8 = .{ "/sbin/ifconfig", if_z.ptr, "-vnet", jid_z.ptr, null };
        safeExec("/sbin/ifconfig", &argv) catch {};
    }
}

/// Remove a jail, killing everything in it. A VNET jail's interfaces are
/// returned to the host first.
pub fn removeJail(jid: i32) void {
    if (jid >= 0) {
        reclaimInterfaces(jid);
        _ = c.jail_remove(jid);
    }
}

/// Whether jail `jid` exists and is the one isolate created for the jailed
/// process `pid` (its name is isolate-<pid>). Jail ids and PIDs read back
/// from the registry are only acted on when they still describe that jail.
pub fn jailBelongsTo(jid: i32, pid: i32) bool {
    if (jid < 0) return false;
    const name_ptr = c.jail_getname(jid);
    if (name_ptr == null) return false;
    defer c.free(name_ptr);

    var expected_buf: [64]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buf, jail_name_prefix ++ "{d}", .{pid}) catch return false;
    return std.mem.eql(u8, std.mem.span(name_ptr), expected);
}

// Defined in freebsd_proc.c, which can include <sys/user.h>
extern fn isolate_parent_pid(pid: c_int) c_int;

extern "c" fn time(tloc: ?*i64) i64;

/// The parent of process `pid`, or null if there is no such process
fn parentPid(pid: i32) ?i32 {
    const parent = isolate_parent_pid(pid);
    return if (parent < 0) null else parent;
}

/// Whether the jailed process `pid` exists and still has the `isolate run`
/// process that started it as its parent. A process whose manager has died
/// is reparented to init (pid 1). This also covers a run that is still
/// setting up: the process creating the user, directory and jail is `pid`
/// itself, with its manager alive.
fn hasLiveManager(pid: i32) bool {
    const parent = parentPid(pid) orelse return false;
    return parent > 1;
}

/// The pid in a name of the form <prefix><digits>, or null
fn pidFromName(name: []const u8, prefix: []const u8) ?i32 {
    if (name.len <= prefix.len or !std.mem.startsWith(u8, name, prefix)) return null;
    return std.fmt.parseInt(i32, name[prefix.len..], 10) catch null;
}

/// Iterates over every jail on the host
const JailIterator = struct {
    lastjid: c_int = 0,
    name_buf: [256]u8 = undefined,
    path_buf: [PATH_MAX]u8 = undefined,

    fn next(self: *JailIterator) ?c_int {
        @memset(&self.name_buf, 0);
        @memset(&self.path_buf, 0);
        var iov = [_]c.struct_iovec{
            .{ .iov_base = @ptrCast(@constCast("lastjid")), .iov_len = 8 },
            .{ .iov_base = @ptrCast(&self.lastjid), .iov_len = @sizeOf(c_int) },
            .{ .iov_base = @ptrCast(@constCast("name")), .iov_len = 5 },
            .{ .iov_base = @ptrCast(&self.name_buf), .iov_len = self.name_buf.len },
            .{ .iov_base = @ptrCast(@constCast("path")), .iov_len = 5 },
            .{ .iov_base = @ptrCast(&self.path_buf), .iov_len = self.path_buf.len },
        };
        const jid = c.jail_get(&iov, iov.len, 0);
        if (jid < 0) return null;
        self.lastjid = jid;
        return jid;
    }

    fn name(self: *const JailIterator) []const u8 {
        return std.mem.sliceTo(&self.name_buf, 0);
    }

    fn path(self: *const JailIterator) []const u8 {
        return std.mem.sliceTo(&self.path_buf, 0);
    }
};

/// Remove jails isolate created that no registry entry accounts for: for
/// example after an `isolate run` was killed before it registered, or after
/// an entry was lost. `managed_jids` are the jails of registered instances.
/// A jail whose process still has a live manager is left alone. Returns the
/// number removed.
pub fn removeStrayJails(io: std.Io, managed_jids: []const i32) u32 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    var removed: u32 = 0;
    var it = JailIterator{};
    while (it.next()) |jid| {
        const pid = pidFromName(it.name(), jail_name_prefix) orelse continue;
        if (std.mem.findScalar(i32, managed_jids, jid) != null) continue;
        if (hasLiveManager(pid)) continue;

        stdout.print("Removing unregistered jail {s} (JID {d})\n", .{ it.name(), jid }) catch {};
        removeJail(jid);
        removeResourceLimits(it.name());
        removed += 1;
    }
    return removed;
}

/// Whether some jail has `<inst_dir>/root` as its root
pub fn instanceDirHasJail(inst_dir: []const u8) bool {
    var it = JailIterator{};
    while (it.next()) |_| {
        const root = it.path();
        if (root.len == inst_dir.len + "/root".len and
            std.mem.startsWith(u8, root, inst_dir) and
            std.mem.endsWith(u8, root, "/root")) return true;
    }
    return false;
}

/// Seconds since `path` was last modified, or null if it cannot be examined
pub fn pathAgeSeconds(path: []const u8) ?i64 {
    var buf: [PATH_MAX]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&buf, "{s}", .{path}) catch return null;
    var st: std.c.Stat = undefined;
    if (stat(path_z.ptr, &st) != 0) return null;
    return time(null) - st.mtim.sec;
}

/// Delete ephemeral users isolate created that nothing uses any more: after
/// a reboot, for instance, every such user is still in the password
/// database while the registry is empty. A user is ours if it is named
/// app-<digits> and carries isolate's comment. It is kept if a registered
/// instance uses it, if process <digits> exists, or if jail
/// isolate-<digits> exists. Returns the number deleted.
pub fn removeStrayUsers(io: std.Io, allocator: Allocator, managed_usernames: []const []const u8) u32 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    // Collect first: the database must not change while it is being read
    var candidates: std.ArrayList([]const u8) = .empty;
    defer {
        for (candidates.items) |name| allocator.free(name);
        candidates.deinit(allocator);
    }

    c.setpwent();
    while (true) {
        const pw = c.getpwent();
        if (pw == null) break;
        const name = std.mem.span(pw.*.pw_name);
        if (!isEphemeralUsername(name)) continue;
        if (!std.mem.eql(u8, std.mem.span(pw.*.pw_gecos), ephemeral_user_comment)) continue;
        const copy = allocator.dupe(u8, name) catch break;
        candidates.append(allocator, copy) catch {
            allocator.free(copy);
            break;
        };
    }
    c.endpwent();

    var removed: u32 = 0;
    outer: for (candidates.items) |name| {
        for (managed_usernames) |managed| {
            if (std.mem.eql(u8, managed, name)) continue :outer;
        }
        const pid = pidFromName(name, "app-") orelse continue;
        if (parentPid(pid) != null) continue; // the process exists

        var jail_name_buf: [64]u8 = undefined;
        const jail_name = std.fmt.bufPrintZ(&jail_name_buf, jail_name_prefix ++ "{d}", .{pid}) catch continue;
        if (c.jail_getid(jail_name.ptr) >= 0) continue;

        stdout.print("Removing unused ephemeral user {s}\n", .{name}) catch {};
        deleteUser(name);
        removed += 1;
    }
    return removed;
}

/// Tear down what an instance left behind when the isolate process that
/// managed it is gone: the jail (which kills anything still running in
/// it), its resource limits, the instance directory, and the ephemeral user.
pub fn teardownInstance(io: std.Io, pid: i32, jail_id: i32, jail_path: []const u8, username: []const u8) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    // Everything below acts as root on values read from a registry entry.
    // Each is checked against what isolate itself would have created, so a
    // stale or forged entry cannot point teardown at anything else.
    if (jailBelongsTo(jail_id, pid)) {
        stdout.print("Removing jail JID {d}\n", .{jail_id}) catch {};
        removeJail(jail_id);
    }
    removeResourceLimitsForPid(pid);

    if (trustedInstanceDir(jail_path)) |inst_dir| {
        stdout.print("Removing instance directory {s}\n", .{inst_dir}) catch {};
        cleanupInstanceDir(inst_dir) catch {
            stdout.print("Warning: Could not fully remove {s}\n", .{inst_dir}) catch {};
        };
    } else if (jail_path.len > 0) {
        stdout.print("Warning: Not removing {s}: not an isolate instance directory\n", .{jail_path}) catch {};
    }

    if (isEphemeralUsername(username)) {
        stdout.print("Removing ephemeral user {s}\n", .{username}) catch {};
        deleteUser(username);
    }
}

/// Switch to a specific user (drop privileges)
pub fn switchToUser(io: std.Io, uid: u32, gid: u32, username: []const u8) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print("Switching to user {s} (UID {d}, GID {d})\n", .{ username, uid, gid }) catch {};

    // Drop root's supplementary groups (wheel, operator, ...) first:
    // setgid/setuid alone leave them in place, and they would carry into
    // the jailed process
    const groups = [_]c.gid_t{gid};
    if (c.setgroups(1, &groups) != 0) {
        return error.PermissionDenied;
    }

    // Set GID first (must be done before dropping privileges)
    if (c.setgid(gid) != 0) {
        return error.PermissionDenied;
    }

    // Set UID (drops privileges)
    if (c.setuid(uid) != 0) {
        return error.PermissionDenied;
    }
}

// ============================================================================
// Environment Setup
// ============================================================================

pub fn setupEnvironment(io: std.Io, capability: *const caps.Capabilities, username: []const u8) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    // Start from an empty environment if requested, so that nothing from
    // the invoking root shell (doas/sudo) reaches the application
    if (capability.env_clear) {
        stdout.print("Clearing environment variables\n", .{}) catch {};
        environ = @ptrCast(&empty_environ);
    }

    // Set essential variables
    var user_buf: [64]u8 = undefined;
    if (username.len < user_buf.len) {
        @memcpy(user_buf[0..username.len], username);
        user_buf[username.len] = 0;
        _ = c.setenv("USER", &user_buf, 1);
    }

    _ = c.setenv("HOME", "/tmp", 1);
    _ = c.setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
    _ = c.setenv("LD_LIBRARY_PATH", "/usr/local/lib:/usr/lib:/lib", 1);
    _ = c.setenv("SHELL", "/usr/sbin/nologin", 1);

    // Apply environment variables from capabilities
    for (capability.env_vars.items) |env| {
        var name_buf: [256]u8 = undefined;
        var value_buf: [1024]u8 = undefined;

        if (env.name.len < name_buf.len and env.value.len < value_buf.len) {
            @memcpy(name_buf[0..env.name.len], env.name);
            name_buf[env.name.len] = 0;
            @memcpy(value_buf[0..env.value.len], env.value);
            value_buf[env.value.len] = 0;

            stdout.print("Setting environment: {s}={s}\n", .{ env.name, env.value }) catch {};
            _ = c.setenv(&name_buf, &value_buf, 1);
        }
    }
}

// ============================================================================
// Filesystem Isolation Setup
// ============================================================================

/// Write a file with the given contents and mode
fn writeFile(path: [:0]const u8, contents: []const u8, mode: c_uint) !void {
    const fd = c.open(path.ptr, c.O_WRONLY | c.O_CREAT | c.O_TRUNC, mode);
    if (fd < 0) return error.FilesystemSetupFailed;
    defer _ = c.close(fd);

    var written: usize = 0;
    while (written < contents.len) {
        const n = c.write(fd, contents[written..].ptr, contents.len - written);
        if (n <= 0) return error.FilesystemSetupFailed;
        written += @intCast(n);
    }
}

/// Create etc/master.passwd, etc/passwd, etc/pwd.db, etc/spwd.db and
/// etc/group in the jail, holding root and the program's user and nothing
/// else. The databases are built by pwd_mkdb(8) from master.passwd.
fn writeUserDatabase(jail_path: []const u8, username: []const u8, uid: u32, gid: u32) !void {
    var etc_buf: [PATH_MAX]u8 = undefined;
    const etc = std.fmt.bufPrintZ(&etc_buf, "{s}/etc", .{jail_path}) catch return error.InvalidPath;

    var master_buf: [PATH_MAX]u8 = undefined;
    const master = std.fmt.bufPrintZ(&master_buf, "{s}/master.passwd", .{etc}) catch return error.InvalidPath;

    // name:password:uid:gid:class:change:expire:gecos:home:shell
    var contents_buf: [512]u8 = undefined;
    const contents = std.fmt.bufPrint(&contents_buf,
        \\root:*:0:0::0:0:System Administrator:/root:/usr/sbin/nologin
        \\{s}:*:{d}:{d}::0:0:Isolated Application:/tmp:/usr/sbin/nologin
        \\
    , .{ username, uid, gid }) catch return error.InvalidPath;
    try writeFile(master, contents, 0o600);

    // -p also writes the plain-text passwd file; -d names the directory
    const argv: [6]?[*:0]const u8 = .{ "/usr/sbin/pwd_mkdb", "-p", "-d", etc.ptr, master.ptr, null };
    try safeExec("/usr/sbin/pwd_mkdb", &argv);

    var group_buf: [PATH_MAX]u8 = undefined;
    const group = std.fmt.bufPrintZ(&group_buf, "{s}/group", .{etc}) catch return error.InvalidPath;
    var group_contents_buf: [256]u8 = undefined;
    const group_contents = std.fmt.bufPrint(&group_contents_buf,
        \\wheel:*:0:root
        \\{s}:*:{d}:
        \\
    , .{ username, gid }) catch return error.InvalidPath;
    try writeFile(group, group_contents, 0o644);
}

/// The device nodes left visible in a jail's /dev
const visible_devices = [_][:0]const u8{
    "null",   "zero",   "full", "random", "urandom",
    "stdin",  "stdout", "stderr",
    "fd",     "fd/*",   "pts",  "pts/*",
};

/// Hide every node of a freshly mounted devfs, then unhide the short list
/// above. Without this the jail's /dev lists every device on the host.
fn restrictDevfs(dev_path: []const u8) !void {
    var path_buf: [PATH_MAX]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_buf, "{s}", .{dev_path}) catch return error.InvalidPath;

    const hide: [7]?[*:0]const u8 = .{ "/sbin/devfs", "-m", path_z.ptr, "rule", "apply", "hide", null };
    try safeExec("/sbin/devfs", &hide);

    for (visible_devices) |node| {
        const unhide: [9]?[*:0]const u8 = .{ "/sbin/devfs", "-m", path_z.ptr, "rule", "apply", "path", node.ptr, "unhide", null };
        try safeExec("/sbin/devfs", &unhide);
    }
}

/// Mount the host directory or file named by a filesystem rule at the same
/// path inside the jail. Any failure is an error.
fn mountRule(io: std.Io, jail_path: []const u8, rule: caps.FileRule) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    var src_buf: [PATH_MAX]u8 = undefined;
    const src_z = std.fmt.bufPrintZ(&src_buf, "{s}", .{rule.path}) catch return error.InvalidPath;

    var st: std.c.Stat = undefined;
    if (stat(src_z.ptr, &st) != 0) {
        stdout.print("Error: {s} (filesystem rule) does not exist on the host\n", .{rule.path}) catch {};
        return error.MountFailed;
    }

    var target_buf: [PATH_MAX]u8 = undefined;
    const target = std.fmt.bufPrintZ(&target_buf, "{s}{s}", .{ jail_path, rule.path }) catch return error.InvalidPath;

    if (std.c.S.ISDIR(st.mode)) {
        mkdirp(target) catch return error.FilesystemSetupFailed;
    } else if (std.c.S.ISREG(st.mode)) {
        // nullfs mounts a file onto a file: create an empty one to mount on
        mkdirp(std.fs.path.dirname(target) orelse return error.InvalidPath) catch return error.FilesystemSetupFailed;
        const fd = c.open(target.ptr, c.O_WRONLY | c.O_CREAT, @as(c_uint, 0o644));
        if (fd < 0) return error.FilesystemSetupFailed;
        _ = c.close(fd);
    } else {
        stdout.print("Error: {s} (filesystem rule) is neither a directory nor a regular file\n", .{rule.path}) catch {};
        return error.MountFailed;
    }

    const rdonly = !rule.permissions.write;
    stdout.print("Mounting {s} -> {s} ({s})\n", .{ rule.path, target, if (rdonly) "ro" else "rw" }) catch {};
    mountNullfs(rule.path, target, rdonly) catch {
        stdout.print("Error: Failed to mount {s}\n", .{rule.path}) catch {};
        return error.MountFailed;
    };
}

pub fn setupFilesystemIsolation(
    io: std.Io,
    capability: *const caps.Capabilities,
    jail_path: []const u8,
    target_binary: []const u8,
    target_uid: u32,
    target_gid: u32,
    username: []const u8,
) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var path_buf: [PATH_MAX]u8 = undefined;

    stdout.print("Setting up filesystem isolation in {s}\n", .{jail_path}) catch {};

    // Create basic directory structure
    const dirs = [_][]const u8{
        "/bin", "/lib", "/usr/lib", "/usr/local/lib",
        "/dev", "/tmp", "/libexec", "/etc",
        "/var/log", "/var/tmp", "/var/run",
    };

    for (dirs) |dir| {
        if (std.fmt.bufPrint(&path_buf, "{s}{s}", .{ jail_path, dir })) |formatted| {
            mkdirp(formatted) catch {};
        } else |_| {}
    }

    // Set permissions on tmp directories
    {
        const formatted = std.fmt.bufPrint(&path_buf, "{s}/tmp", .{jail_path}) catch return error.InvalidPath;
        var buf: [PATH_MAX]u8 = undefined;
        @memcpy(buf[0..formatted.len], formatted);
        buf[formatted.len] = 0;
        _ = std.c.chmod(@ptrCast(&buf), 0o1777);
    }

    // Mount workspace if specified
    if (capability.workspace_path) |ws| {
        stdout.print("Setting up workspace: {s} -> /workspace\n", .{ws}) catch {};
        const ws_path = std.fmt.bufPrint(&path_buf, "{s}/workspace", .{jail_path}) catch return error.InvalidPath;
        mkdirp(ws_path) catch return error.FilesystemSetupFailed;
        mountNullfs(ws, ws_path, false) catch |err| {
            stdout.print("Failed to mount workspace: {}\n", .{err}) catch {};
            return error.FilesystemSetupFailed;
        };
        stdout.print("Workspace mounted successfully\n", .{}) catch {};
    }

    // Copy target binary into jail
    const binary_name = if (std.mem.lastIndexOfScalar(u8, target_binary, '/')) |idx|
        target_binary[idx + 1 ..]
    else
        target_binary;

    const dst_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ jail_path, binary_name }) catch return error.InvalidPath;
    copyFile(target_binary, dst_path) catch return error.FilesystemSetupFailed;

    // Make binary executable
    {
        var buf: [PATH_MAX]u8 = undefined;
        @memcpy(buf[0..dst_path.len], dst_path);
        buf[dst_path.len] = 0;
        _ = std.c.chmod(@ptrCast(&buf), 0o755);
    }

    // The jail's user database: root and the program's user. FreeBSD's libc
    // does not read /etc/passwd; getpwuid() and friends read the hashed
    // /etc/pwd.db, so that is generated too. Without it a program cannot
    // look up its own user, and some (PostgreSQL) refuse to start.
    writeUserDatabase(jail_path, username, target_uid, target_gid) catch {
        stdout.print("Error: Failed to create the user database in the jail\n", .{}) catch {};
        return error.FilesystemSetupFailed;
    };
    stdout.print("Created user database in jail (uid={d}, gid={d})\n", .{ target_uid, target_gid }) catch {};

    // Mount devfs and reduce it to what an unprivileged program needs
    stdout.print("Mounting system directories...\n", .{}) catch {};
    {
        const dev_path = std.fmt.bufPrint(&path_buf, "{s}/dev", .{jail_path}) catch return error.InvalidPath;
        mountDevfs(dev_path) catch {
            stdout.print("Error: Failed to mount devfs\n", .{}) catch {};
            return error.MountFailed;
        };
        restrictDevfs(dev_path) catch {
            stdout.print("Error: Failed to restrict the device nodes in the jail's /dev\n", .{}) catch {};
            return error.MountFailed;
        };
    }

    // Process capability filesystem rules. A rule that cannot be mounted
    // stops the run: the program must never start with less, or other,
    // access than its capability file states.
    stdout.print("Processing capability filesystem rules...\n", .{}) catch {};
    for (capability.file_rules.items) |rule| {
        // Security: a /tmp rule mounts an instance-specific directory, never
        // the host's /tmp. This prevents cross-instance information leakage.
        if (std.mem.eql(u8, rule.path, "/tmp")) {
            var instance_tmp_buf: [PATH_MAX]u8 = undefined;
            const instance_tmp = std.fmt.bufPrintZ(&instance_tmp_buf, "{s}/tmp", .{instanceDir(jail_path)}) catch return error.InvalidPath;

            stdout.print("Creating isolated tmp: {s}\n", .{instance_tmp}) catch {};
            mkdirp(instance_tmp) catch {
                stdout.print("Error: Failed to create instance tmp directory\n", .{}) catch {};
                return error.FilesystemSetupFailed;
            };
            _ = std.c.chmod(instance_tmp.ptr, 0o1777);

            const mount_path = std.fmt.bufPrint(&path_buf, "{s}/tmp", .{jail_path}) catch return error.InvalidPath;
            mkdirp(mount_path) catch return error.FilesystemSetupFailed;

            stdout.print("Mounting {s} -> {s} (rw, isolated)\n", .{ instance_tmp, mount_path }) catch {};
            mountNullfs(instance_tmp, mount_path, false) catch {
                stdout.print("Error: Failed to mount isolated tmp\n", .{}) catch {};
                return error.MountFailed;
            };
            continue;
        }

        try mountRule(io, jail_path, rule);
    }

    // Set permissions on tmp again after mounts
    {
        const tmp_path = std.fmt.bufPrint(&path_buf, "{s}/tmp", .{jail_path}) catch return error.InvalidPath;
        var buf: [PATH_MAX]u8 = undefined;
        @memcpy(buf[0..tmp_path.len], tmp_path);
        buf[tmp_path.len] = 0;
        _ = std.c.chmod(@ptrCast(&buf), 0o1777);
    }

    stdout.print("Jail filesystem setup complete\n", .{}) catch {};
}

// ============================================================================
// Cleanup
// ============================================================================

pub fn cleanupIsolation(io: std.Io) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    const jid = jail_state.jail_id;
    if (jid >= 0) {
        stdout.print("Cleaning up jail JID {d}\n", .{jid}) catch {};
        removeJail(jid);
        jail_state.jail_id = -1;
    }

    // Cleanup jail filesystem: the whole per-instance directory (jail
    // root, isolated tmp), after unmounting everything below it
    const jail_path = jail_state.getJailPath();
    if (jail_path.len > 0) {
        const inst_dir = instanceDir(jail_path);
        stdout.print("Cleaning up instance directory: {s}\n", .{inst_dir}) catch {};
        cleanupInstanceDir(inst_dir) catch {
            stdout.print("Warning: Could not fully remove {s} ('isolate clean' will retry)\n", .{inst_dir}) catch {};
        };
        jail_state.jail_root_path[0] = 0;
    }

    // Cleanup ephemeral user
    const username = jail_state.getUsername();
    if (username.len > 0) {
        stdout.print("Cleaning up ephemeral user: {s}\n", .{username}) catch {};
        deleteUser(username);
        jail_state.ephemeral_username[0] = 0;
    }
}

// ============================================================================
// Main Isolation Entry Point
// ============================================================================

pub fn createIsolation(io: std.Io, capability: *const caps.Capabilities, target_binary: []const u8) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var jail_name_buf: [64]u8 = undefined;
    var username_buf: [64]u8 = undefined;

    stdout.print("Creating FreeBSD isolation context...\n", .{}) catch {};

    // Generate unique jail name
    const pid = c.getpid();
    const jail_name = std.fmt.bufPrint(&jail_name_buf, jail_name_prefix ++ "{d}", .{pid}) catch return error.InvalidPath;

    // Rules left over from an earlier jail that had the same name (a reused
    // PID after a crash) must not apply to this one
    removeResourceLimits(jail_name);

    // Determine username and create user
    var target_uid: u32 = 0;
    var target_gid: u32 = 0;
    var username: []const u8 = undefined;

    if (capability.create_user and std.mem.eql(u8, capability.username, "auto")) {
        username = std.fmt.bufPrint(&username_buf, "app-{d}", .{pid}) catch return error.InvalidPath;
        jail_state.setUsername(username);

        const user_info = try createUser(username);
        target_uid = user_info.uid;
        target_gid = user_info.gid;
        stdout.print("Created user {s} with UID {d}, GID {d}\n", .{ username, target_uid, target_gid }) catch {};
    } else {
        username = capability.username;
        const user_info = lookupUser(username) catch |err| {
            stdout.print("Error: User {s} does not exist\n", .{username}) catch {};
            return err;
        };
        if (user_info.uid == 0) {
            stdout.print("Error: Refusing to run as {s} (uid 0). The program must run unprivileged.\n", .{username}) catch {};
            return error.PermissionDenied;
        }
        target_uid = user_info.uid;
        target_gid = user_info.gid;
        stdout.print("Using existing user {s} (UID {d}, GID {d})\n", .{ username, target_uid, target_gid }) catch {};
    }

    // Create the per-instance directory under the root-owned runtime
    // directory with an unpredictable name. It must never live under /tmp:
    // any local user can pre-create /tmp paths and plant symlinks there for
    // the chmod/mount/copy below to follow as root.
    mkdirp(runtime_dir) catch return error.FilesystemSetupFailed;

    var inst_buf: [PATH_MAX]u8 = undefined;
    const inst_template = std.fmt.bufPrintZ(&inst_buf, "{s}/inst-XXXXXX", .{runtime_dir}) catch return error.InvalidPath;
    if (c.mkdtemp(inst_template.ptr) == null) return error.FilesystemSetupFailed;
    // mkdtemp creates the directory 0700; the jail root must be traversable
    // by the application user
    _ = std.c.chmod(inst_template.ptr, 0o755);

    // Create jail filesystem
    var jail_path_buf: [PATH_MAX]u8 = undefined;
    const jail_path_tmp = std.fmt.bufPrint(&jail_path_buf, "{s}/root", .{inst_template}) catch return error.InvalidPath;
    jail_state.setJailPath(jail_path_tmp);
    const jail_path = jail_state.getJailPath();

    stdout.print("Creating jail filesystem: {s}\n", .{jail_path}) catch {};

    mkdirp(jail_path) catch {
        cleanupIsolation(io);
        return error.FilesystemSetupFailed;
    };

    // Set up filesystem isolation
    setupFilesystemIsolation(io, capability, jail_path, target_binary, target_uid, target_gid, username) catch {
        cleanupIsolation(io);
        return error.FilesystemSetupFailed;
    };

    // Create jail
    const jid = createJail(io, jail_name, jail_path, capability.network_config, capability.sysv_ipc) catch {
        cleanupIsolation(io);
        return error.JailCreateFailed;
    };

    // Set resource limits
    setResourceLimits(io, jail_name, capability.limits) catch {
        cleanupIsolation(io);
        removeResourceLimits(jail_name);
        return error.ResourceLimitFailed;
    };

    // Attach to jail
    attachToJail(io, jid) catch {
        cleanupIsolation(io);
        return error.JailAttachFailed;
    };

    // Switch to target user
    switchToUser(io, target_uid, target_gid, username) catch {
        cleanupIsolation(io);
        return error.PermissionDenied;
    };

    // Set up environment
    setupEnvironment(io, capability, username);

    stdout.print("FreeBSD isolation context created successfully\n", .{}) catch {};
    stdout.print("Running in jail {s} as user {s}\n", .{ jail_name, username }) catch {};
    stdout.print("Jail filesystem: {s}\n", .{jail_path}) catch {};
}

// ============================================================================
// Tests
// ============================================================================

test "mkdirp creates nested directories" {
    const test_path = "/tmp/isolate-test-zig/a/b/c";
    mkdirp(test_path) catch |err| {
        std.debug.print("mkdirp failed: {}\n", .{err});
        return err;
    };

    // Verify directory exists
    var path_buf: [PATH_MAX]u8 = undefined;
    @memcpy(path_buf[0..test_path.len], test_path);
    path_buf[test_path.len] = 0;

    var st: std.c.Stat = undefined;
    try std.testing.expect(stat(@ptrCast(&path_buf), &st) == 0);

    // Cleanup
    rmrf("/tmp/isolate-test-zig") catch {};
}

test "copyFile copies file correctly" {
    // Create test file
    const src = "/tmp/isolate-test-src.txt";
    const dst = "/tmp/isolate-test-dst.txt";
    const content = "Hello, World!";

    // Write source file using C
    var src_buf: [PATH_MAX]u8 = undefined;
    @memcpy(src_buf[0..src.len], src);
    src_buf[src.len] = 0;

    const f = c.fopen(&src_buf, "w");
    if (f != null) {
        _ = c.fputs(content, f);
        _ = c.fclose(f);
    }

    // Copy
    copyFile(src, dst) catch |err| {
        std.debug.print("copyFile failed: {}\n", .{err});
        return err;
    };

    // Verify
    var dst_buf: [PATH_MAX]u8 = undefined;
    @memcpy(dst_buf[0..dst.len], dst);
    dst_buf[dst.len] = 0;

    var st: std.c.Stat = undefined;
    try std.testing.expect(stat(@ptrCast(&dst_buf), &st) == 0);

    // Cleanup
    _ = c.unlink(&src_buf);
    _ = c.unlink(&dst_buf);
}

test "trustedInstanceDir accepts only isolate's own layout" {
    const ok = runtime_dir ++ "/inst-aB3dE9/root";
    try std.testing.expectEqualStrings(runtime_dir ++ "/inst-aB3dE9", trustedInstanceDir(ok).?);

    const bad = [_][]const u8{
        "",
        "/root/victim/root",
        "/etc/root",
        runtime_dir ++ "/root",
        runtime_dir ++ "/inst-aB3dE9",
        runtime_dir ++ "/inst-aB3dE9/tmp",
        runtime_dir ++ "/inst-aB3dE/root",
        runtime_dir ++ "/inst-../../x/root",
        runtime_dir ++ "/inst-aB3dE9/root/",
        "/tmp" ++ runtime_dir ++ "/inst-aB3dE9/root",
    };
    for (bad) |path| {
        try std.testing.expect(trustedInstanceDir(path) == null);
    }
}

test "pidFromName" {
    try std.testing.expectEqual(@as(?i32, 2947), pidFromName("isolate-2947", jail_name_prefix));
    try std.testing.expectEqual(@as(?i32, 12), pidFromName("app-12", "app-"));
    try std.testing.expect(pidFromName("isolate-", jail_name_prefix) == null);
    try std.testing.expect(pidFromName("isolate-12x", jail_name_prefix) == null);
    try std.testing.expect(pidFromName("webjail", jail_name_prefix) == null);
}

test "parentPid of this process is its parent; of a missing pid, null" {
    try std.testing.expectEqual(@as(?i32, c.getppid()), parentPid(c.getpid()));
    try std.testing.expect(parentPid(99999999) == null);
}

test "isEphemeralUsername" {
    try std.testing.expect(isEphemeralUsername("app-2947"));
    try std.testing.expect(!isEphemeralUsername("app-"));
    try std.testing.expect(!isEphemeralUsername("app-12x"));
    try std.testing.expect(!isEphemeralUsername("root"));
    try std.testing.expect(!isEphemeralUsername("application"));
}

test "isPathUnder" {
    try std.testing.expect(isPathUnder("/var/run/isolate/inst-abc", "/var/run/isolate/inst-abc"));
    try std.testing.expect(isPathUnder("/var/run/isolate/inst-abc/root/lib", "/var/run/isolate/inst-abc"));
    try std.testing.expect(!isPathUnder("/var/run/isolate/inst-abcdef", "/var/run/isolate/inst-abc"));
    try std.testing.expect(!isPathUnder("/var/run", "/var/run/isolate/inst-abc"));
}

test "jail_state management" {
    jail_state.setJailId(42);
    try std.testing.expectEqual(@as(i32, 42), jail_state.jail_id);

    jail_state.setUsername("testuser");
    try std.testing.expectEqualStrings("testuser", jail_state.getUsername());

    jail_state.setJailPath("/tmp/test-jail");
    try std.testing.expectEqualStrings("/tmp/test-jail", jail_state.getJailPath());

    // Reset
    jail_state.jail_id = -1;
    jail_state.ephemeral_username = [_]u8{0} ** 64;
    jail_state.jail_root_path = [_]u8{0} ** PATH_MAX;
}
