//! Instance Registry for tracking running isolated containers
//!
//! This module provides persistent tracking of running containers,
//! enabling list, stop, and clean operations.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

// kill(2) with signal 0 is used to probe whether a PID exists
extern "c" fn kill(pid: std.c.pid_t, sig: c_int) c_int;

/// Registry directory path
pub const REGISTRY_DIR = "/var/run/isolate";
pub const REGISTRY_DIR_FALLBACK = "/tmp/isolate-registry";

/// Instance state
pub const InstanceState = enum {
    running,
    stopped,
    orphaned, // Process gone but not cleaned up
};

/// Instance information stored in registry
pub const Instance = struct {
    name: []const u8,
    pid: i32,
    jail_id: i32,
    jail_path: []const u8,
    username: []const u8,
    binary_path: []const u8,
    start_time: i64,
    workspace_path: ?[]const u8,

    allocator: Allocator,

    pub fn deinit(self: *Instance) void {
        self.allocator.free(self.name);
        self.allocator.free(self.jail_path);
        self.allocator.free(self.username);
        self.allocator.free(self.binary_path);
        if (self.workspace_path) |wp| {
            self.allocator.free(wp);
        }
    }
};

/// Registry for managing instances
pub const Registry = struct {
    io: Io,
    allocator: Allocator,
    registry_dir: []const u8,

    const Self = @This();

    pub fn init(io: Io, allocator: Allocator) Self {
        // Try primary directory first, fall back to /tmp
        const dir = if (Io.Dir.accessAbsolute(io, REGISTRY_DIR, .{})) |_|
            REGISTRY_DIR
        else |_|
            REGISTRY_DIR_FALLBACK;

        return .{
            .io = io,
            .allocator = allocator,
            .registry_dir = dir,
        };
    }

    /// Ensure registry directory exists
    pub fn ensureDir(self: *Self) !void {
        Io.Dir.createDirAbsolute(self.io, self.registry_dir, .default_dir) catch |err| {
            if (err != error.PathAlreadyExists) {
                // Try fallback
                self.registry_dir = REGISTRY_DIR_FALLBACK;
                Io.Dir.createDirAbsolute(self.io, self.registry_dir, .default_dir) catch |err2| {
                    if (err2 != error.PathAlreadyExists) return err2;
                };
            }
        };
    }

    /// Register a new instance
    pub fn register(self: *Self, instance: Instance) !void {
        try self.ensureDir();

        var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}.json", .{ self.registry_dir, instance.name });

        const file = try Io.Dir.createFileAbsolute(self.io, path, .{});
        defer file.close(self.io);

        var write_buf: [1024]u8 = undefined;
        var file_writer = file.writer(self.io, &write_buf);
        const writer = &file_writer.interface;

        // Format workspace_path to a stack buffer to avoid memory leak
        var ws_buf: [512]u8 = undefined;
        const ws_str: []const u8 = if (instance.workspace_path) |wp|
            std.fmt.bufPrint(&ws_buf, "\"{s}\"", .{wp}) catch "null"
        else
            "null";

        try writer.print(
            \\{{
            \\  "name": "{s}",
            \\  "pid": {d},
            \\  "jail_id": {d},
            \\  "jail_path": "{s}",
            \\  "username": "{s}",
            \\  "binary_path": "{s}",
            \\  "start_time": {d},
            \\  "workspace_path": {s}
            \\}}
        , .{
            instance.name,
            instance.pid,
            instance.jail_id,
            instance.jail_path,
            instance.username,
            instance.binary_path,
            instance.start_time,
            ws_str,
        });

        try writer.flush();
    }

    /// Unregister an instance
    pub fn unregister(self: *Self, name: []const u8) void {
        var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.json", .{ self.registry_dir, name }) catch return;
        Io.Dir.deleteFileAbsolute(self.io, path) catch {};
    }

    /// List all registered instances. Caller owns the list and its entries.
    pub fn list(self: *Self) !std.ArrayList(InstanceInfo) {
        var instances: std.ArrayList(InstanceInfo) = .empty;

        var dir = Io.Dir.openDirAbsolute(self.io, self.registry_dir, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) return instances;
            return err;
        };
        defer dir.close(self.io);

        var iter = dir.iterate();
        while (try iter.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

            if (self.loadInstance(entry.name)) |info| {
                try instances.append(self.allocator, info);
            } else |_| {}
        }

        return instances;
    }

    /// Compact instance info for listing
    pub const InstanceInfo = struct {
        name: []const u8,
        pid: i32,
        jail_id: i32,
        jail_path: []const u8,
        binary_path: []const u8,
        state: InstanceState,
        start_time: i64,

        allocator: Allocator,

        pub fn deinit(self: *InstanceInfo) void {
            self.allocator.free(self.name);
            self.allocator.free(self.jail_path);
            self.allocator.free(self.binary_path);
        }
    };

    /// Load instance info from file
    fn loadInstance(self: *Self, filename: []const u8) !InstanceInfo {
        var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.registry_dir, filename });

        const file = try Io.Dir.openFileAbsolute(self.io, path, .{});
        defer file.close(self.io);

        var file_reader = file.reader(self.io, &.{});
        const content = try file_reader.interface.allocRemaining(self.allocator, .limited(4096));
        defer self.allocator.free(content);

        // Simple JSON parsing (just extract the fields we need)
        const name = try extractJsonString(self.allocator, content, "name");
        errdefer self.allocator.free(name);
        const pid = try extractJsonInt(content, "pid");
        const jail_id = try extractJsonInt(content, "jail_id");
        const jail_path = try extractJsonString(self.allocator, content, "jail_path");
        errdefer self.allocator.free(jail_path);
        const binary_path = try extractJsonString(self.allocator, content, "binary_path");
        errdefer self.allocator.free(binary_path);
        const start_time = try extractJsonInt(content, "start_time");

        // Check if process is still running
        const state = checkProcessState(pid, jail_id);

        return .{
            .name = name,
            .pid = @intCast(pid),
            .jail_id = @intCast(jail_id),
            .jail_path = jail_path,
            .binary_path = binary_path,
            .state = state,
            .start_time = start_time,
            .allocator = self.allocator,
        };
    }

    /// Get instance by name
    pub fn get(self: *Self, name: []const u8) !?InstanceInfo {
        var filename_buf: [256]u8 = undefined;
        const filename = try std.fmt.bufPrint(&filename_buf, "{s}.json", .{name});
        return self.loadInstance(filename) catch null;
    }

    /// Clean orphaned instances
    pub fn cleanOrphaned(self: *Self) !u32 {
        var cleaned: u32 = 0;
        var instances = try self.list();
        defer {
            for (instances.items) |*inst| {
                inst.deinit();
            }
            instances.deinit(self.allocator);
        }

        for (instances.items) |inst| {
            if (inst.state == .orphaned or inst.state == .stopped) {
                self.unregister(inst.name);
                cleaned += 1;
            }
        }

        return cleaned;
    }
};

/// Check if a process/jail is still running
fn checkProcessState(pid: i64, jail_id: i64) InstanceState {
    if (builtin.os.tag == .freebsd) {
        // Check if jail exists
        const c = @cImport({
            @cInclude("sys/param.h");
            @cInclude("sys/jail.h");
        });

        // Try to get jail info - if it fails, jail doesn't exist
        const jid: c_int = @intCast(jail_id);
        if (c.jail_attach(jid) == 0) {
            // We accidentally attached! This shouldn't happen in practice
            // since we're not root here, but handle it anyway
            return .running;
        }

        // Check if PID exists
        const kill_result = kill(@intCast(pid), 0);
        if (kill_result == 0) {
            return .running;
        } else if (std.c._errno().* == @intFromEnum(std.c.E.SRCH)) {
            return .orphaned;
        }

        return .stopped;
    } else {
        // For other platforms, just check PID
        const kill_result = kill(@intCast(pid), 0);
        if (kill_result == 0) {
            return .running;
        }
        return .orphaned;
    }
}

/// Simple JSON string extraction
fn extractJsonString(allocator: Allocator, json: []const u8, key: []const u8) ![]const u8 {
    var search_buf: [64]u8 = undefined;
    const search = try std.fmt.bufPrint(&search_buf, "\"{s}\": \"", .{key});

    const start_idx = std.mem.find(u8, json, search) orelse return error.KeyNotFound;
    const value_start = start_idx + search.len;
    const value_end = std.mem.findPos(u8, json, value_start, "\"") orelse return error.InvalidJson;

    return allocator.dupe(u8, json[value_start..value_end]);
}

/// Simple JSON int extraction
fn extractJsonInt(json: []const u8, key: []const u8) !i64 {
    var search_buf: [64]u8 = undefined;
    const search = try std.fmt.bufPrint(&search_buf, "\"{s}\": ", .{key});

    const start_idx = std.mem.find(u8, json, search) orelse return error.KeyNotFound;
    const value_start = start_idx + search.len;

    // Find end of number
    var value_end = value_start;
    while (value_end < json.len) : (value_end += 1) {
        const ch = json[value_end];
        if (ch != '-' and (ch < '0' or ch > '9')) break;
    }

    return std.fmt.parseInt(i64, json[value_start..value_end], 10);
}

// ============================================================================
// Tests
// ============================================================================

test "extractJsonString" {
    const json =
        \\{"name": "test-123", "pid": 456}
    ;
    const allocator = std.testing.allocator;

    const name = try extractJsonString(allocator, json, "name");
    defer allocator.free(name);

    try std.testing.expectEqualStrings("test-123", name);
}

test "extractJsonInt" {
    const json =
        \\{"name": "test", "pid": 12345, "jail_id": -1}
    ;

    const pid = try extractJsonInt(json, "pid");
    try std.testing.expectEqual(@as(i64, 12345), pid);

    const jail_id = try extractJsonInt(json, "jail_id");
    try std.testing.expectEqual(@as(i64, -1), jail_id);
}

test "Registry init" {
    const allocator = std.testing.allocator;
    const registry = Registry.init(std.testing.io, allocator);
    try std.testing.expect(registry.registry_dir.len > 0);
}
