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

// stat(2) against std.c.Stat; std.c.stat is missing its extern in Zig 0.16
extern "c" fn stat(path: [*:0]const u8, buf: *std.c.Stat) c_int;

/// Unbuffered stdout writer. Unbuffered so that nothing is left behind in a
/// buffer across fork()/execv()/_exit() in the isolation path.
fn stdoutWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stdout().writer(io, &.{});
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
    instance_tmp_path: [PATH_MAX]u8 = [_]u8{0} ** PATH_MAX,

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

    pub fn setInstanceTmpPath(self: *@This(), path: []const u8) void {
        const len = @min(path.len, self.instance_tmp_path.len - 1);
        @memcpy(self.instance_tmp_path[0..len], path[0..len]);
        self.instance_tmp_path[len] = 0;
    }

    pub fn getUsername(self: *const @This()) []const u8 {
        const len = std.mem.findScalar(u8, &self.ephemeral_username, 0) orelse self.ephemeral_username.len;
        return self.ephemeral_username[0..len];
    }

    pub fn getJailPath(self: *const @This()) []const u8 {
        const len = std.mem.findScalar(u8, &self.jail_root_path, 0) orelse self.jail_root_path.len;
        return self.jail_root_path[0..len];
    }

    pub fn getInstanceTmpPath(self: *const @This()) []const u8 {
        const len = std.mem.findScalar(u8, &self.instance_tmp_path, 0) orelse self.instance_tmp_path.len;
        return self.instance_tmp_path[0..len];
    }
}{};

// Export functions for C interop (IPC between parent/child)
pub export fn freebsd_get_jail_id() c_int {
    return jail_state.jail_id;
}

pub export fn freebsd_set_jail_id(jid: c_int) void {
    jail_state.setJailId(jid);
}

pub export fn freebsd_get_username() [*c]const u8 {
    return &jail_state.ephemeral_username;
}

pub export fn freebsd_set_username(name: [*c]const u8) void {
    if (name != null) {
        const slice = std.mem.span(name);
        jail_state.setUsername(slice);
    }
}

pub export fn freebsd_get_jail_path() [*c]const u8 {
    return &jail_state.jail_root_path;
}

pub export fn freebsd_set_jail_path(path: [*c]const u8) void {
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

/// Recursively remove a directory tree
pub fn rmrf(path: []const u8) !void {
    var path_buf: [PATH_MAX]u8 = undefined;
    if (path.len >= PATH_MAX) return error.InvalidPath;

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    var paths: [2][*c]u8 = .{ &path_buf, null };

    const fts = c.fts_open(@ptrCast(&paths), c.FTS_PHYSICAL | c.FTS_NOCHDIR | c.FTS_NOSTAT, null);
    if (fts == null) return error.FilesystemSetupFailed;
    defer _ = c.fts_close(fts);

    while (c.fts_read(fts)) |ent| {
        switch (ent.*.fts_info) {
            c.FTS_D => {
                // Directory - will be processed again as FTS_DP
            },
            c.FTS_DP => {
                // Directory after children processed - remove it
                _ = c.rmdir(ent.*.fts_accpath);
            },
            c.FTS_F, c.FTS_SL, c.FTS_SLNONE, c.FTS_DEFAULT => {
                // File or symlink - remove it
                _ = c.unlink(ent.*.fts_accpath);
            },
            else => {},
        }
    }
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
        "Isolate ephemeral user",
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

// rctl syscall wrapper - not available in standard headers
extern fn rctl_add_rule(inbufp: [*]const u8, inbuflen: usize, outbufp: [*]u8, outbuflen: usize) c_int;

// Cached system capabilities (detected once)
var cached_sys_caps: ?syscheck.SystemCapabilities = null;

fn getSystemCapabilities() syscheck.SystemCapabilities {
    if (cached_sys_caps) |caps_val| {
        return caps_val;
    }
    cached_sys_caps = syscheck.detect();
    return cached_sys_caps.?;
}

pub fn setResourceLimits(io: std.Io, jail_name: []const u8, limits: caps.ResourceLimits) void {
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
        return;
    }

    if (limits.memory_bytes) |mem| {
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:memoryuse:deny={d}\x00", .{ jail_name, mem })) |formatted| {
            stdout.print("Setting memory limit: {d} bytes\n", .{mem}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Warning: Failed to set memory limit (rctl error)\n", .{}) catch {};
            }
        } else |_| {}
    }

    if (limits.max_processes) |procs| {
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:maxproc:deny={d}\x00", .{ jail_name, procs })) |formatted| {
            stdout.print("Setting process limit: {d}\n", .{procs}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Warning: Failed to set process limit (rctl error)\n", .{}) catch {};
            }
        } else |_| {}
    }

    if (limits.max_files) |files| {
        if (std.fmt.bufPrint(&rule_buf, "jail:{s}:openfiles:deny={d}\x00", .{ jail_name, files })) |formatted| {
            stdout.print("Setting file descriptor limit: {d}\n", .{files}) catch {};
            const ret = rctl_add_rule(&rule_buf, formatted.len, &out_buf, out_buf.len);
            if (ret != 0) {
                stdout.print("Warning: Failed to set file limit (rctl error)\n", .{}) catch {};
            }
        } else |_| {}
    }
}

// ============================================================================
// Jail Management
// ============================================================================

/// Create a FreeBSD jail
pub fn createJail(io: std.Io, jail_name: []const u8, jail_path: []const u8, network_config: caps.NetworkConfig) !i32 {
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
                syscheck.warnIfVnetUnavailable(sys_caps, stdout) catch {};
                break :blk false; // Fall back to inherit
            }
            break :blk true;
        },
        else => false,
    };

    // Set up jail parameters - need more params for VNET
    var params: [9]c.struct_jailparam = undefined;
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

    _ = c.jailparam_init(&params[param_count], "allow.sysvipc");
    _ = c.jailparam_import(&params[param_count], "false");
    param_count += 1;

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
            moveInterfaceToJail(jid, iface) catch |err| {
                stdout.print("Warning: Failed to move interface {s} into jail: {}\n", .{ iface, err }) catch {};
                // Don't fail jail creation, just warn
            };

            // Configure IP address if specified
            if (network_config.ip_address) |ip| {
                stdout.print("Configuring IP address {s} on {s}\n", .{ ip, iface }) catch {};
                configureJailInterface(jid, iface, ip) catch |err| {
                    stdout.print("Warning: Failed to configure IP {s}: {}\n", .{ ip, err }) catch {};
                };
                // Also configure loopback
                configureJailInterface(jid, "lo0", "127.0.0.1/8") catch {};
            }
        } else {
            stdout.print("Note: VNET jail created but no interface specified (use --vnet <interface>)\n", .{}) catch {};
        }
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

/// Configure an interface inside a jail using jexec
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

    // Use jexec to run ifconfig inside the jail
    // jexec <jid> /sbin/ifconfig <ifname> inet <ip> up
    const argv: [8]?[*:0]const u8 = .{
        "/usr/sbin/jexec",
        @ptrCast(&jid_buf),
        "/sbin/ifconfig",
        @ptrCast(&ifname_buf),
        "inet",
        @ptrCast(&ip_buf),
        "up",
        null,
    };

    safeExec("/usr/sbin/jexec", &argv) catch return error.JailParamFailed;
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

/// Remove a jail
pub fn removeJail(jid: i32) void {
    if (jid >= 0) {
        _ = c.jail_remove(jid);
    }
}

/// Switch to a specific user (drop privileges)
pub fn switchToUser(io: std.Io, uid: u32, gid: u32, username: []const u8) !void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print("Switching to user {s} (UID {d}, GID {d})\n", .{ username, uid, gid }) catch {};

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

    // Clear environment if requested
    if (capability.env_clear) {
        stdout.print("Clearing environment variables\n", .{}) catch {};
        // In Zig we can't easily clear environ, so we'll set essential vars
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

    // Create minimal passwd file
    {
        const passwd_path = std.fmt.bufPrint(&path_buf, "{s}/etc/passwd", .{jail_path}) catch return error.InvalidPath;
        var passwd_buf: [PATH_MAX]u8 = undefined;
        @memcpy(passwd_buf[0..passwd_path.len], passwd_path);
        passwd_buf[passwd_path.len] = 0;

        const file = c.fopen(&passwd_buf, "w");
        if (file != null) {
            var user_buf: [64]u8 = undefined;
            @memcpy(user_buf[0..username.len], username);
            user_buf[username.len] = 0;

            _ = c.fprintf(file, "root:*:0:0:System Administrator:/root:/usr/sbin/nologin\n");
            _ = c.fprintf(file, "%s:*:%u:%u:Isolated Application:/tmp:/usr/sbin/nologin\n", &user_buf, target_uid, target_gid);
            _ = c.fclose(file);
            stdout.print("Created minimal passwd file in jail (uid={d}, gid={d})\n", .{ target_uid, target_gid }) catch {};
        }
    }

    // Create minimal group file
    {
        const group_path = std.fmt.bufPrint(&path_buf, "{s}/etc/group", .{jail_path}) catch return error.InvalidPath;
        var group_buf: [PATH_MAX]u8 = undefined;
        @memcpy(group_buf[0..group_path.len], group_path);
        group_buf[group_path.len] = 0;

        const file = c.fopen(&group_buf, "w");
        if (file != null) {
            var user_buf: [64]u8 = undefined;
            @memcpy(user_buf[0..username.len], username);
            user_buf[username.len] = 0;

            _ = c.fprintf(file, "wheel:*:0:root\n");
            _ = c.fprintf(file, "%s:*:%u:\n", &user_buf, target_gid);
            _ = c.fclose(file);
            stdout.print("Created minimal group file in jail\n", .{}) catch {};
        }
    }

    // Mount devfs
    stdout.print("Mounting system directories...\n", .{}) catch {};
    {
        const dev_path = std.fmt.bufPrint(&path_buf, "{s}/dev", .{jail_path}) catch return error.InvalidPath;
        mountDevfs(dev_path) catch {
            stdout.print("Warning: Failed to mount devfs\n", .{}) catch {};
        };
    }

    // Process capability filesystem rules
    stdout.print("Processing capability filesystem rules...\n", .{}) catch {};
    for (capability.file_rules.items) |rule| {
        if (rule.permissions.read) {
            // Security: Intercept /tmp mounts to use instance-specific directory
            // This prevents cross-instance information leakage
            if (std.mem.eql(u8, rule.path, "/tmp")) {
                // Create the instance-specific tmp directory inside the
                // per-instance directory, next to the jail root
                var instance_tmp_buf: [PATH_MAX]u8 = undefined;
                const instance_tmp = std.fmt.bufPrint(&instance_tmp_buf, "{s}/tmp", .{instanceDir(jail_path)}) catch continue;

                stdout.print("Creating isolated tmp: {s}\n", .{instance_tmp}) catch {};
                mkdirp(instance_tmp) catch {
                    stdout.print("Warning: Failed to create instance tmp directory\n", .{}) catch {};
                    continue;
                };

                // Set permissions on instance tmp (sticky bit + world writable)
                {
                    var tmp_buf: [PATH_MAX]u8 = undefined;
                    @memcpy(tmp_buf[0..instance_tmp.len], instance_tmp);
                    tmp_buf[instance_tmp.len] = 0;
                    _ = std.c.chmod(@ptrCast(&tmp_buf), 0o1777);
                }

                // Store path for cleanup
                jail_state.setInstanceTmpPath(instance_tmp);

                // Mount instance-specific tmp as /tmp in jail
                const mount_path = std.fmt.bufPrint(&path_buf, "{s}/tmp", .{jail_path}) catch continue;
                mkdirp(mount_path) catch continue;

                stdout.print("Mounting {s} -> {s} (rw, isolated)\n", .{ instance_tmp, mount_path }) catch {};
                mountNullfs(instance_tmp, mount_path, false) catch {
                    stdout.print("Warning: Failed to mount isolated tmp\n", .{}) catch {};
                };
                continue;
            }

            // Check if source path exists and is a directory
            var src_buf: [PATH_MAX]u8 = undefined;
            @memcpy(src_buf[0..rule.path.len], rule.path);
            src_buf[rule.path.len] = 0;

            var st: std.c.Stat = undefined;
            if (stat(@ptrCast(&src_buf), &st) == 0 and std.c.S.ISDIR(st.mode)) {
                const mount_path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ jail_path, rule.path }) catch continue;

                mkdirp(mount_path) catch continue;

                const rdonly = !rule.permissions.write;
                stdout.print("Mounting {s} -> {s} ({s})\n", .{
                    rule.path,
                    mount_path,
                    if (rdonly) "ro" else "rw",
                }) catch {};

                mountNullfs(rule.path, mount_path, rdonly) catch {
                    stdout.print("Warning: Failed to mount {s}\n", .{rule.path}) catch {};
                };
            }
        }
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
    var path_buf: [PATH_MAX]u8 = undefined;

    const jid = jail_state.jail_id;
    if (jid >= 0) {
        stdout.print("Cleaning up jail JID {d}\n", .{jid}) catch {};
        removeJail(jid);
        jail_state.jail_id = -1;
    }

    // Cleanup jail filesystem
    const jail_path = jail_state.getJailPath();
    if (jail_path.len > 0) {
        stdout.print("Cleaning up jail filesystem: {s}\n", .{jail_path}) catch {};

        // Unmount filesystems (best effort)
        const mount_points = [_][]const u8{
            "/tmp", "/workspace", "/dev", "/bin", "/lib",
            "/libexec", "/usr/lib", "/usr/local/lib",
        };

        for (mount_points) |mp| {
            if (std.fmt.bufPrint(&path_buf, "{s}{s}", .{ jail_path, mp })) |formatted| {
                unmount(formatted);
            } else |_| {}
        }

        // Remove jail directory tree
        rmrf(jail_path) catch {};

        jail_state.jail_root_path[0] = 0;
    }

    // Cleanup instance-specific tmp directory
    const instance_tmp = jail_state.getInstanceTmpPath();
    if (instance_tmp.len > 0) {
        stdout.print("Cleaning up instance tmp: {s}\n", .{instance_tmp}) catch {};
        rmrf(instance_tmp) catch {};
        jail_state.instance_tmp_path[0] = 0;
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
    const jail_name = std.fmt.bufPrint(&jail_name_buf, "isolate-{d}", .{pid}) catch return error.InvalidPath;

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
        const user_info = try lookupUser(username);
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

    mkdirp(jail_path) catch return error.FilesystemSetupFailed;

    // Set up filesystem isolation
    setupFilesystemIsolation(io, capability, jail_path, target_binary, target_uid, target_gid, username) catch {
        cleanupIsolation(io);
        return error.FilesystemSetupFailed;
    };

    // Create jail
    const jid = createJail(io, jail_name, jail_path, capability.network_config) catch {
        cleanupIsolation(io);
        return error.JailCreateFailed;
    };

    // Set resource limits
    setResourceLimits(io, jail_name, capability.limits);

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

test "jail_state management" {
    jail_state.setJailId(42);
    try std.testing.expectEqual(@as(i32, 42), jail_state.jail_id);

    jail_state.setUsername("testuser");
    try std.testing.expectEqualStrings("testuser", jail_state.getUsername());

    jail_state.setJailPath("/tmp/test-jail");
    try std.testing.expectEqualStrings("/tmp/test-jail", jail_state.getJailPath());

    jail_state.setInstanceTmpPath("/tmp/isolate-test-tmp");
    try std.testing.expectEqualStrings("/tmp/isolate-test-tmp", jail_state.getInstanceTmpPath());

    // Reset
    jail_state.jail_id = -1;
    jail_state.ephemeral_username = [_]u8{0} ** 64;
    jail_state.jail_root_path = [_]u8{0} ** PATH_MAX;
    jail_state.instance_tmp_path = [_]u8{0} ** PATH_MAX;
}
