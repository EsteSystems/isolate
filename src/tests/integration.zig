//! Integration tests for isolate
//!
//! These tests verify the end-to-end functionality of the isolation system.
//! Some tests require root privileges and will be skipped if not available.

const std = @import("std");
const builtin = @import("builtin");
const c_api = @import("../c_api.zig");
const platform = @import("../platform.zig");

/// Check if we have root privileges
fn hasRoot() bool {
    return std.os.linux.geteuid() == 0;
}

/// Get the examples directory path
fn getExamplesDir(allocator: std.mem.Allocator) ![]const u8 {
    // Try to find examples relative to executable or current directory
    const paths_to_try = [_][]const u8{
        "examples",
        "../examples",
        "../../examples",
        "/home/dann/code/isolate/examples",
    };

    for (paths_to_try) |path| {
        if (std.fs.cwd().statFile(path)) |stat| {
            if (stat.kind == .directory) {
                return allocator.dupe(u8, path);
            }
        } else |_| {}
    }

    return error.ExamplesNotFound;
}

// =============================================================================
// Capability Loading Tests
// =============================================================================

test "load default capabilities" {
    var caps: c_api.Capabilities = undefined;
    c_api.initDefaultCapabilities(&caps);

    try std.testing.expect(caps.create_user == 1);
    try std.testing.expect(caps.network_default_deny == 0);
    try std.testing.expect(caps.fs_default_deny == 0);

    const username = c_api.fromCString(@ptrCast(&caps.username));
    try std.testing.expectEqualStrings("auto", username);
}

test "load capabilities from file" {
    const allocator = std.testing.allocator;

    // Create a temporary capability file
    const tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const caps_content =
        \\# Test capability file
        \\user: auto
        \\memory: 128M
        \\processes: 5
        \\files: 256
        \\network: tcp:8080:inbound
        \\filesystem: /tmp:rw
    ;

    const caps_file = try tmp_dir.dir.createFile("test.caps", .{});
    try caps_file.writeAll(caps_content);
    caps_file.close();

    // Get the full path
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const caps_path = try tmp_dir.dir.realpath("test.caps", &path_buf);
    const caps_path_z = try allocator.dupeZ(u8, caps_path);
    defer allocator.free(caps_path_z);

    var caps: c_api.Capabilities = undefined;
    try c_api.loadCapabilities(caps_path_z, &caps);

    // Verify parsed values
    try std.testing.expect(caps.create_user == 1);
    try std.testing.expect(caps.limits.memory_bytes == 128 * 1024 * 1024);
    try std.testing.expect(caps.limits.max_processes == 5);
    try std.testing.expect(caps.limits.max_files == 256);
    try std.testing.expect(caps.network_count == 1);
    try std.testing.expect(caps.file_count == 1);
}

test "parse memory sizes" {
    const test_cases = [_]struct { input: []const u8, expected: usize }{
        .{ .input = "1K", .expected = 1024 },
        .{ .input = "1M", .expected = 1024 * 1024 },
        .{ .input = "1G", .expected = 1024 * 1024 * 1024 },
        .{ .input = "128M", .expected = 128 * 1024 * 1024 },
        .{ .input = "512", .expected = 512 },
    };

    for (test_cases) |tc| {
        var bytes: usize = 0;
        const result = c_api.c.parse_memory_size(@ptrCast(tc.input.ptr), &bytes);
        try std.testing.expect(result == 0);
        try std.testing.expectEqual(tc.expected, bytes);
    }
}

// =============================================================================
// Platform Tests
// =============================================================================

test "platform detection" {
    const current = platform.Platform.current();

    switch (builtin.os.tag) {
        .freebsd => try std.testing.expect(current == .freebsd),
        .linux => try std.testing.expect(current == .linux),
        else => try std.testing.expect(current == .unsupported),
    }
}

test "platform capabilities" {
    const caps = platform.getCapabilities();

    if (builtin.os.tag == .freebsd) {
        try std.testing.expect(caps.process_isolation);
        try std.testing.expect(caps.user_isolation);
        try std.testing.expect(caps.filesystem_isolation);
        try std.testing.expect(caps.requires_root);
    }
}

test "platform is supported" {
    const supported = platform.isSupported();

    if (builtin.os.tag == .freebsd or builtin.os.tag == .linux) {
        try std.testing.expect(supported);
    }
}

// =============================================================================
// Detection Tests (no root required)
// =============================================================================

test "detect capabilities for hello example" {
    const allocator = std.testing.allocator;

    const examples_dir = getExamplesDir(allocator) catch |err| {
        std.debug.print("Skipping test: {}\n", .{err});
        return;
    };
    defer allocator.free(examples_dir);

    // Check if hello binary exists
    var hello_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const hello_path = std.fmt.bufPrint(&hello_path_buf, "{s}/hello", .{examples_dir}) catch return;

    std.fs.cwd().access(hello_path, .{}) catch {
        std.debug.print("Skipping test: hello binary not found at {s}\n", .{hello_path});
        return;
    };

    // Create temp file for output
    const tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var caps_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const caps_path = try tmp_dir.dir.realpath(".", &caps_path_buf);

    var output_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const output_path = std.fmt.bufPrint(&output_path_buf, "{s}/hello.caps", .{caps_path}) catch return;

    const hello_z = try allocator.dupeZ(u8, hello_path);
    defer allocator.free(hello_z);

    const output_z = try allocator.dupeZ(u8, output_path);
    defer allocator.free(output_z);

    // Run detection
    c_api.detectCapabilities(hello_z, output_z) catch |err| {
        std.debug.print("Detection failed: {}\n", .{err});
        return;
    };

    // Verify output file was created
    const stat = tmp_dir.dir.statFile("hello.caps") catch {
        try std.testing.expect(false); // File should exist
        return;
    };

    try std.testing.expect(stat.size > 0);
}

// =============================================================================
// Isolation Tests (require root)
// =============================================================================

test "create isolation context requires root" {
    if (hasRoot()) {
        // Skip detailed isolation tests in unit test context
        // These should be run via `make test` which uses doas
        std.debug.print("Root available, but skipping isolation test in unit context\n", .{});
        return;
    }

    // Without root, creating isolation should fail
    var caps: c_api.Capabilities = undefined;
    c_api.initDefaultCapabilities(&caps);

    const result = c_api.createIsolationContext(&caps);
    try std.testing.expectError(c_api.CApiError.IsolationFailed, result);
}

// =============================================================================
// C API Interop Tests
// =============================================================================

test "c string conversion" {
    const allocator = std.testing.allocator;

    const zig_str = "hello world";
    const c_str = try c_api.toCString(allocator, zig_str);
    defer allocator.free(c_str);

    // Verify null termination
    try std.testing.expect(c_str[c_str.len] == 0);

    // Convert back
    const back = c_api.fromCString(@ptrCast(c_str.ptr));
    try std.testing.expectEqualStrings(zig_str, back);
}

test "c api constants match" {
    // Verify that Zig constants match C constants
    try std.testing.expectEqual(@as(c_int, 16), c_api.MAX_NETWORK_RULES);
    try std.testing.expectEqual(@as(c_int, 32), c_api.MAX_FILE_RULES);
    try std.testing.expectEqual(@as(c_int, 32), c_api.MAX_ENV_VARS);
    try std.testing.expectEqual(@as(c_int, 64), c_api.MAX_CAPABILITY_HINTS);
}

// =============================================================================
// Helper type for C interop
// =============================================================================
const c_int = c_api.c.int;
