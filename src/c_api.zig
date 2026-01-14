//! C API bindings for system calls
//!
//! This module provides Zig-friendly access to libc functions needed for
//! process management (fork, exec, pipe, etc.) and other system operations.

const std = @import("std");
const builtin = @import("builtin");

// Import system headers for libc functions
pub const c = @cImport({
    @cInclude("sys/types.h");
    @cInclude("sys/param.h");
    @cInclude("sys/wait.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("unistd.h");
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("fcntl.h");

    if (builtin.os.tag == .freebsd) {
        @cInclude("sys/jail.h");
    }
});

// Re-export common constants
pub const PATH_MAX = if (@hasDecl(c, "PATH_MAX")) c.PATH_MAX else 1024;

// Tests
test "c_api system headers work" {
    // Verify we can access basic libc functions
    try std.testing.expect(c.SIGTERM > 0);
    try std.testing.expect(c.SIGINT > 0);
}

test "PATH_MAX is reasonable" {
    try std.testing.expect(PATH_MAX >= 256);
    try std.testing.expect(PATH_MAX <= 65536);
}
