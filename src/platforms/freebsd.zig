//! FreeBSD-specific isolation implementation
//!
//! This module implements process isolation using FreeBSD jails.
//! Currently wraps the existing C implementation, will be migrated
//! to pure Zig in Phase 3.

const std = @import("std");
const builtin = @import("builtin");

// Only compile on FreeBSD
comptime {
    if (builtin.os.tag != .freebsd) {
        @compileError("freebsd.zig can only be compiled on FreeBSD");
    }
}

const c = @cImport({
    @cInclude("sys/param.h");
    @cInclude("sys/jail.h");
    @cInclude("sys/mount.h");
    @cInclude("jail.h");
    @cInclude("unistd.h");
    @cInclude("pwd.h");
});

/// Platform capabilities for FreeBSD
pub const capabilities = @import("../platform.zig").PlatformCapabilities{
    .process_isolation = true, // jails
    .user_isolation = true, // ephemeral users via pw
    .filesystem_isolation = true, // nullfs mounts
    .network_isolation = false, // TODO: vnet jails
    .resource_limits = true, // rctl
    .syscall_filtering = false, // TODO: capsicum
    .requires_root = true,
    .unprivileged_mode = false,
};

/// FreeBSD-specific context data
pub const Context = struct {
    /// Jail ID
    jid: c_int = -1,

    /// Jail name
    name: [64]u8 = [_]u8{0} ** 64,

    /// Whether we created an ephemeral user
    ephemeral_user: bool = false,

    /// Jail parameters used for creation
    params: ?*anyopaque = null,
};

/// Jail configuration options
pub const JailConfig = struct {
    /// Jail name (auto-generated if null)
    name: ?[]const u8 = null,

    /// Jail root path
    path: []const u8,

    /// Hostname inside jail
    hostname: ?[]const u8 = null,

    /// IP inheritance mode
    ip_mode: IpMode = .inherit,

    /// Allow raw sockets
    allow_raw_sockets: bool = false,

    /// Allow System V IPC
    allow_sysvipc: bool = false,

    /// Persist jail after last process exits
    persist: bool = true,

    pub const IpMode = enum {
        inherit, // Inherit host IP
        new, // New IP (requires vnet)
        none, // No network
    };
};

/// Create a new isolation context
pub fn createContext(caps: anytype) !@import("../platform.zig").IsolationContext {
    _ = caps;
    // TODO: Implement pure Zig jail creation
    // For now, this is handled by the C code via c_api
    return error.SystemError;
}

/// Destroy an isolation context
pub fn destroyContext(ctx: *@import("../platform.zig").IsolationContext) void {
    const freebsd_ctx = &ctx.platform_data.freebsd;

    // Remove jail if it exists
    if (freebsd_ctx.jid >= 0) {
        _ = c.jail_remove(freebsd_ctx.jid);
        freebsd_ctx.jid = -1;
    }

    // Cleanup ephemeral user if created
    if (freebsd_ctx.ephemeral_user and ctx.username[0] != 0) {
        cleanupEphemeralUser(&ctx.username);
    }

    // Cleanup jail filesystem
    if (ctx.root_path[0] != 0) {
        cleanupJailFilesystem(&ctx.root_path);
    }
}

/// Attach current process to isolation context
pub fn attachContext(ctx: *@import("../platform.zig").IsolationContext) !void {
    const freebsd_ctx = &ctx.platform_data.freebsd;

    if (freebsd_ctx.jid < 0) {
        return error.InvalidConfiguration;
    }

    if (c.jail_attach(freebsd_ctx.jid) != 0) {
        return error.AttachFailed;
    }
}

/// Create an ephemeral user for isolation
pub fn createEphemeralUser(username: []const u8) !struct { uid: c.uid_t, gid: c.gid_t } {
    // Check if user already exists
    const pw = c.getpwnam(@ptrCast(username.ptr));
    if (pw != null) {
        return .{
            .uid = pw.*.pw_uid,
            .gid = pw.*.pw_gid,
        };
    }

    // Create user using pw command
    // TODO: Replace with direct user database manipulation
    var child = std.process.Child.init(&.{
        "pw",
        "useradd",
        "-n",
        @ptrCast(username.ptr),
        "-s",
        "/usr/sbin/nologin",
        "-d",
        "/tmp",
        "-c",
        "Isolate ephemeral user",
    }, std.heap.page_allocator);

    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;

    const term = child.spawnAndWait() catch return error.UserCreationFailed;
    if (term.Exited != 0) {
        return error.UserCreationFailed;
    }

    // Get created user's UID/GID
    const new_pw = c.getpwnam(@ptrCast(username.ptr));
    if (new_pw == null) {
        return error.UserCreationFailed;
    }

    return .{
        .uid = new_pw.*.pw_uid,
        .gid = new_pw.*.pw_gid,
    };
}

/// Cleanup an ephemeral user
fn cleanupEphemeralUser(username: *const [64]u8) void {
    var child = std.process.Child.init(&.{
        "pw",
        "userdel",
        "-n",
        @ptrCast(username),
    }, std.heap.page_allocator);

    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;

    _ = child.spawnAndWait() catch {};
}

/// Cleanup jail filesystem
fn cleanupJailFilesystem(path: *const [std.fs.max_path_bytes]u8) void {
    // Unmount filesystems (best effort)
    const unmount_paths = [_][]const u8{
        "/dev",
        "/bin",
        "/lib",
        "/libexec",
        "/usr/lib",
        "/usr/local/lib",
        "/workspace",
    };

    for (unmount_paths) |subpath| {
        var full_path: [std.fs.max_path_bytes]u8 = undefined;
        const path_slice = std.mem.sliceTo(path, 0);
        const len = std.fmt.bufPrint(&full_path, "{s}{s}", .{ path_slice, subpath }) catch continue;
        _ = c.unmount(@ptrCast(full_path[0..len.len].ptr), 0);
    }

    // Remove jail directory
    const path_slice = std.mem.sliceTo(path, 0);
    std.fs.deleteTreeAbsolute(path_slice) catch {};
}

/// Create jail with specified configuration
pub fn createJail(config: JailConfig) !c_int {
    var params: [8]c.struct_jailparam = undefined;
    var param_count: usize = 0;

    // Initialize parameters
    inline for (.{
        .{ "path", config.path },
        .{ "persist", null },
        .{ "allow.raw_sockets", if (config.allow_raw_sockets) "true" else "false" },
        .{ "allow.socket_af", "true" },
        .{ "ip4", @tagName(config.ip_mode) },
        .{ "ip6", @tagName(config.ip_mode) },
        .{ "allow.sysvipc", if (config.allow_sysvipc) "true" else "false" },
    }) |param| {
        if (c.jailparam_init(&params[param_count], param[0]) != 0) {
            return error.JailCreationFailed;
        }
        if (c.jailparam_import(&params[param_count], param[1]) != 0) {
            return error.JailCreationFailed;
        }
        param_count += 1;
    }

    // Set name if provided
    if (config.name) |name| {
        if (c.jailparam_init(&params[param_count], "name") != 0) {
            return error.JailCreationFailed;
        }
        if (c.jailparam_import(&params[param_count], @ptrCast(name.ptr)) != 0) {
            return error.JailCreationFailed;
        }
        param_count += 1;
    }

    // Create the jail
    const jid = c.jailparam_set(&params, @intCast(param_count), c.JAIL_CREATE);

    // Free parameters
    c.jailparam_free(&params, @intCast(param_count));

    if (jid < 0) {
        return error.JailCreationFailed;
    }

    return jid;
}

/// Apply resource limits using rctl
pub fn applyResourceLimits(jail_name: []const u8, limits: anytype) !void {
    const rctl = @cImport({
        @cInclude("sys/rctl.h");
    });

    var rule_buf: [256]u8 = undefined;

    // Memory limit
    if (limits.memory_bytes > 0) {
        const rule = std.fmt.bufPrint(&rule_buf, "jail:{s}:memoryuse:deny={d}", .{
            jail_name,
            limits.memory_bytes,
        }) catch return error.InvalidConfiguration;

        var outbuf: [256]u8 = undefined;
        if (rctl.rctl_add_rule(@ptrCast(rule.ptr), rule.len + 1, &outbuf, outbuf.len) != 0) {
            // Non-fatal - rctl may not be enabled
            std.log.warn("Failed to set memory limit (rctl may not be enabled)", .{});
        }
    }

    // Process limit
    if (limits.max_processes > 0) {
        const rule = std.fmt.bufPrint(&rule_buf, "jail:{s}:maxproc:deny={d}", .{
            jail_name,
            limits.max_processes,
        }) catch return error.InvalidConfiguration;

        var outbuf: [256]u8 = undefined;
        _ = rctl.rctl_add_rule(@ptrCast(rule.ptr), rule.len + 1, &outbuf, outbuf.len);
    }

    // File descriptor limit
    if (limits.max_files > 0) {
        const rule = std.fmt.bufPrint(&rule_buf, "jail:{s}:openfiles:deny={d}", .{
            jail_name,
            limits.max_files,
        }) catch return error.InvalidConfiguration;

        var outbuf: [256]u8 = undefined;
        _ = rctl.rctl_add_rule(@ptrCast(rule.ptr), rule.len + 1, &outbuf, outbuf.len);
    }
}

// Tests
test "capabilities" {
    try std.testing.expect(capabilities.process_isolation);
    try std.testing.expect(capabilities.user_isolation);
    try std.testing.expect(capabilities.requires_root);
}
