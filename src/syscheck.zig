//! System capability detection for isolate
//!
//! This module detects kernel features required for full isolation functionality.
//! It provides clear diagnostics and actionable guidance when features are missing.

const std = @import("std");
const builtin = @import("builtin");

// Only compile on FreeBSD
comptime {
    if (builtin.os.tag != .freebsd) {
        @compileError("syscheck.zig can only be compiled on FreeBSD");
    }
}

const c = @cImport({
    // Release builds define _FORTIFY_SOURCE, and the fortified libc wrappers do
    // not survive translate-c; they add nothing for calls made from Zig.
    @cUndef("_FORTIFY_SOURCE");
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("sys/types.h");
    @cInclude("sys/sysctl.h");
});

/// System capabilities detected at runtime
pub const SystemCapabilities = struct {
    /// racct/rctl is enabled (kern.racct.enable=1)
    racct_enabled: bool,

    /// VIMAGE/VNET is available (kern.features.vimage)
    vnet_available: bool,

    /// Jails are supported (always true on FreeBSD)
    jails_available: bool,

    /// Running as root
    is_root: bool,

    /// FreeBSD version
    osreldate: u32,
};

/// Check if a sysctl exists and return its integer value
fn getSysctlInt(name: [:0]const u8) ?i32 {
    var value: c_int = 0;
    var size: usize = @sizeOf(c_int);

    const result = c.sysctlbyname(
        name.ptr,
        &value,
        &size,
        null,
        0,
    );

    if (result == 0) {
        return value;
    }
    return null;
}

/// Detect system capabilities
pub fn detect() SystemCapabilities {
    return .{
        .racct_enabled = blk: {
            // kern.racct.enable: 0 = disabled, 1 = enabled
            const val = getSysctlInt("kern.racct.enable");
            break :blk val != null and val.? == 1;
        },

        .vnet_available = blk: {
            // kern.features.vimage: exists and non-zero if VNET available
            const val = getSysctlInt("kern.features.vimage");
            break :blk val != null and val.? != 0;
        },

        .jails_available = blk: {
            // security.jail.jailed: 0 if we can create jails (not jailed ourselves)
            // If we're inside a jail, we can't create nested jails (usually)
            const val = getSysctlInt("security.jail.jailed");
            break :blk val == null or val.? == 0;
        },

        .is_root = blk: {
            // Use C geteuid since we're on FreeBSD
            const c_unistd = @cImport({
                // Release builds define _FORTIFY_SOURCE, and the fortified libc wrappers do
                // not survive translate-c; they add nothing for calls made from Zig.
                @cUndef("_FORTIFY_SOURCE");
                @cDefine("_FORTIFY_SOURCE", "0");
                @cInclude("unistd.h");
            });
            break :blk c_unistd.geteuid() == 0;
        },

        .osreldate = blk: {
            const val = getSysctlInt("kern.osreldate");
            break :blk if (val) |v| @intCast(@as(u32, @bitCast(v))) else 0;
        },
    };
}

/// Print system capabilities check results
pub fn printCheck(caps: SystemCapabilities, writer: *std.Io.Writer) !void {
    try writer.print("isolate System Check\n", .{});
    try writer.print("====================\n\n", .{});

    // OS info
    const major = caps.osreldate / 100000;
    const minor = (caps.osreldate / 1000) % 100;
    try writer.print("FreeBSD {d}.{d}\n\n", .{ major, minor });

    try writer.print("Kernel Features:\n", .{});

    // Jails
    if (caps.jails_available) {
        try writer.print("  [OK] FreeBSD jails        Supported\n", .{});
    } else {
        try writer.print("  [!!] FreeBSD jails        Running inside jail - nested jails may be limited\n", .{});
    }

    // racct/rctl
    if (caps.racct_enabled) {
        try writer.print("  [OK] racct/rctl           Enabled - resource limits available\n", .{});
    } else {
        try writer.print("  [!!] racct/rctl           NOT ENABLED - files with limits will be refused\n", .{});
    }

    // VNET
    if (caps.vnet_available) {
        try writer.print("  [OK] VNET/VIMAGE          Available - network isolation supported\n", .{});
    } else {
        try writer.print("  [!!] VNET/VIMAGE          NOT AVAILABLE - network_mode: vnet will be refused\n", .{});
    }

    // Always available on FreeBSD
    try writer.print("  [OK] nullfs               Supported\n", .{});
    try writer.print("  [OK] devfs                Supported\n", .{});

    try writer.print("\n", .{});

    // Privileges
    try writer.print("Privileges:\n", .{});
    if (caps.is_root) {
        try writer.print("  [OK] Running as root      Full isolation available\n", .{});
    } else {
        try writer.print("  [!!] Not running as root  Use 'doas isolate' for full isolation\n", .{});
    }

    // Print remediation steps if needed
    const needs_help = !caps.racct_enabled or !caps.vnet_available;
    if (needs_help) {
        try writer.print("\n", .{});
        try writer.print("To enable missing features:\n", .{});
        try writer.print("---------------------------\n", .{});

        if (!caps.racct_enabled) {
            try writer.print("\nracct/rctl (resource limits):\n", .{});
            try writer.print("  Add to /boot/loader.conf:\n", .{});
            try writer.print("    kern.racct.enable=1\n", .{});
            try writer.print("  Then reboot.\n", .{});
        }

        if (!caps.vnet_available) {
            try writer.print("\nVNET (network isolation):\n", .{});
            try writer.print("  Requires kernel compiled with:\n", .{});
            try writer.print("    options VIMAGE\n", .{});
            try writer.print("  FreeBSD GENERIC kernel includes this since 13.0.\n", .{});
            try writer.print("  If missing, rebuild kernel or use a different kernel config.\n", .{});
        }
    }

    try writer.print("\n", .{});

    // Summary
    if (caps.racct_enabled and caps.vnet_available and caps.jails_available) {
        try writer.print("Status: All features available. Full isolation supported.\n", .{});
    } else {
        try writer.print("Status: Some features unavailable. isolate will work with reduced functionality.\n", .{});
    }
}

/// Print warning if racct is not enabled (for use before setting resource limits)
pub fn warnIfRacctDisabled(caps: SystemCapabilities, writer: *std.Io.Writer) !void {
    if (!caps.racct_enabled) {
        try writer.print(
            \\
            \\Error: Resource limits requested but racct is not enabled.
            \\
            \\Resource limits (memory, processes, files) require racct/rctl support.
            \\To enable, add to /boot/loader.conf:
            \\
            \\    kern.racct.enable=1
            \\
            \\Then reboot. Not starting: the limits in the capability file cannot be applied.
            \\
            \\
        , .{});
    }
}

/// Print warning if VNET is not available (for use when --vnet is requested)
pub fn warnIfVnetUnavailable(caps: SystemCapabilities, writer: *std.Io.Writer) !void {
    if (!caps.vnet_available) {
        try writer.print(
            \\
            \\Error: VNET requested but VIMAGE is not available in this kernel.
            \\
            \\Network isolation requires a kernel compiled with 'options VIMAGE'.
            \\FreeBSD GENERIC kernel includes this since 13.0.
            \\
            \\Not starting: the capability file asks for a network stack of its own.
            \\
            \\
        , .{});
    }
}

/// Check if resource limits are requested in capabilities
pub fn hasResourceLimits(limits: anytype) bool {
    return limits.memory_bytes != null or
        limits.max_processes != null or
        limits.max_files != null;
}

// ============================================================================
// Tests
// ============================================================================

test "detect returns valid struct" {
    const caps = detect();
    // Just verify it doesn't crash and returns something
    _ = caps.racct_enabled;
    _ = caps.vnet_available;
    _ = caps.jails_available;
    _ = caps.is_root;
    _ = caps.osreldate;
}

test "getSysctlInt returns null for nonexistent" {
    const val = getSysctlInt("kern.nonexistent.sysctl.value");
    try std.testing.expect(val == null);
}
