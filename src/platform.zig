//! Platform abstraction layer for isolation
//!
//! This module provides a unified interface for platform-specific isolation
//! mechanisms. It routes to the appropriate implementation based on the
//! target operating system.

const std = @import("std");
const builtin = @import("builtin");

// Platform-specific implementations
pub const freebsd = @import("platforms/freebsd.zig");
pub const linux = @import("platforms/linux.zig");

/// Supported platforms
pub const Platform = enum {
    freebsd,
    linux,
    unsupported,

    /// Get the current platform
    pub fn current() Platform {
        return switch (builtin.os.tag) {
            .freebsd => .freebsd,
            .linux => .linux,
            else => .unsupported,
        };
    }

    /// Get platform name as string
    pub fn name(self: Platform) []const u8 {
        return switch (self) {
            .freebsd => "FreeBSD",
            .linux => "Linux",
            .unsupported => "Unsupported",
        };
    }
};

/// Platform capabilities - what isolation features are available
pub const PlatformCapabilities = struct {
    /// Process isolation (jails, namespaces)
    process_isolation: bool = false,

    /// User isolation (ephemeral users, user namespaces)
    user_isolation: bool = false,

    /// Filesystem isolation (chroot, mount namespaces)
    filesystem_isolation: bool = false,

    /// Network isolation (vnet, network namespaces)
    network_isolation: bool = false,

    /// Resource limits (rctl, cgroups)
    resource_limits: bool = false,

    /// Syscall filtering (capsicum, seccomp)
    syscall_filtering: bool = false,

    /// Requires root privileges
    requires_root: bool = true,

    /// Can run unprivileged (user namespaces)
    unprivileged_mode: bool = false,
};

/// Get capabilities for the current platform
pub fn getCapabilities() PlatformCapabilities {
    return switch (Platform.current()) {
        .freebsd => freebsd.capabilities,
        .linux => linux.capabilities,
        .unsupported => PlatformCapabilities{},
    };
}

/// Isolation context - represents an active isolation environment
pub const IsolationContext = struct {
    /// Platform-specific context data
    platform_data: PlatformData,

    /// Whether context is active
    active: bool = false,

    /// Jail/container ID (platform-specific meaning)
    id: i32 = -1,

    /// Associated username (for ephemeral user cleanup)
    username: [64]u8 = [_]u8{0} ** 64,

    /// Root path of isolated environment
    root_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,

    const PlatformData = union(Platform) {
        freebsd: freebsd.Context,
        linux: linux.Context,
        unsupported: void,
    };

    /// Create a new isolation context
    pub fn create(caps: anytype) !IsolationContext {
        return switch (Platform.current()) {
            .freebsd => freebsd.createContext(caps),
            .linux => linux.createContext(caps),
            .unsupported => error.UnsupportedPlatform,
        };
    }

    /// Cleanup and destroy the isolation context
    pub fn destroy(self: *IsolationContext) void {
        if (!self.active) return;

        switch (Platform.current()) {
            .freebsd => freebsd.destroyContext(self),
            .linux => linux.destroyContext(self),
            .unsupported => {},
        }

        self.active = false;
        self.id = -1;
    }

    /// Attach current process to isolation context
    pub fn attach(self: *IsolationContext) !void {
        return switch (Platform.current()) {
            .freebsd => freebsd.attachContext(self),
            .linux => linux.attachContext(self),
            .unsupported => error.UnsupportedPlatform,
        };
    }
};

/// Errors that can occur during isolation
pub const IsolationError = error{
    UnsupportedPlatform,
    PermissionDenied,
    ResourceExhausted,
    InvalidConfiguration,
    JailCreationFailed,
    NamespaceCreationFailed,
    MountFailed,
    UserCreationFailed,
    AttachFailed,
    CleanupFailed,
    SystemError,
};

/// Check if current platform is supported
pub fn isSupported() bool {
    return Platform.current() != .unsupported;
}

/// Check if running with sufficient privileges
pub fn hasPrivileges() bool {
    const caps = getCapabilities();
    if (caps.unprivileged_mode) {
        return true;
    }
    return std.os.linux.geteuid() == 0;
}

// Tests
test "platform detection" {
    const platform = Platform.current();
    try std.testing.expect(platform == .freebsd or platform == .linux or platform == .unsupported);
}

test "platform name" {
    const platform = Platform.current();
    const name = platform.name();
    try std.testing.expect(name.len > 0);
}

test "capabilities struct" {
    const caps = getCapabilities();
    // On FreeBSD, we should have jail support
    if (Platform.current() == .freebsd) {
        try std.testing.expect(caps.process_isolation);
    }
}
