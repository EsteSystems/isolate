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

/// Registry directory path. Only root can create entries in /var/run, and
/// that is the whole trust model of the registry: `stop` and `clean` act as
/// root on what the entries say (which jail to remove, which directory to
/// delete). There is deliberately no fallback to a directory other users can
/// write to.
pub const REGISTRY_DIR = "/var/run/isolate";

/// Instance names become registry file names (<name>.json) and appear in
/// paths: letters, digits, '.', '_' and '-' only, not starting with '.',
/// at most 64 bytes.
pub fn isValidInstanceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64 or name[0] == '.') return false;
    for (name) |ch| {
        switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    return true;
}

/// Write `s` as a JSON string literal
fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |ch| {
        switch (ch) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\t' => try writer.writeAll("\\t"),
            0...8, 11, 12, 14...0x1f => try writer.print("\\u{x:0>4}", .{ch}),
            else => try writer.writeByte(ch),
        }
    }
    try writer.writeByte('"');
}

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
    manager_pid: i32, // The isolate process that waits for pid and cleans up
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
        return .{
            .io = io,
            .allocator = allocator,
            .registry_dir = REGISTRY_DIR,
        };
    }

    /// Ensure registry directory exists (root only; 0755 so that
    /// `isolate list` works unprivileged)
    pub fn ensureDir(self: *Self) !void {
        Io.Dir.createDirAbsolute(self.io, self.registry_dir, @enumFromInt(0o755)) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }

    /// Whether an entry with this name exists
    pub fn exists(self: *Self, name: []const u8) bool {
        if (!isValidInstanceName(name)) return false;
        var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}.json", .{ self.registry_dir, name }) catch return false;
        Io.Dir.accessAbsolute(self.io, path, .{}) catch return false;
        return true;
    }

    /// Register a new instance. Fails with error.InstanceNameInUse if an
    /// entry of that name exists. The entry appears complete or not at all:
    /// it is written to a temporary file and hard-linked into place, which
    /// is atomic and refuses to replace an existing entry.
    pub fn register(self: *Self, instance: Instance) !void {
        if (!isValidInstanceName(instance.name)) return error.InvalidInstanceName;
        try self.ensureDir();

        var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}.json", .{ self.registry_dir, instance.name });

        // Not ending in .json, so list() never reads a half-written file
        var tmp_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const tmp_path = try std.fmt.bufPrintZ(&tmp_buf, "{s}/{s}.json.tmp.{d}", .{ self.registry_dir, instance.name, instance.manager_pid });

        try self.writeEntry(tmp_path, instance);
        defer Io.Dir.deleteFileAbsolute(self.io, tmp_path) catch {};

        if (std.c.link(tmp_path.ptr, path.ptr) != 0) {
            if (std.c._errno().* == @intFromEnum(std.c.E.EXIST)) return error.InstanceNameInUse;
            return error.RegistryWriteFailed;
        }
    }

    fn writeEntry(self: *Self, path: []const u8, instance: Instance) !void {
        const file = try Io.Dir.createFileAbsolute(self.io, path, .{});
        defer file.close(self.io);

        var write_buf: [1024]u8 = undefined;
        var file_writer = file.writer(self.io, &write_buf);
        const writer = &file_writer.interface;

        try writer.writeAll("{\n  \"name\": ");
        try writeJsonString(writer, instance.name);
        try writer.print(",\n  \"pid\": {d},\n  \"manager_pid\": {d},\n  \"jail_id\": {d},\n  \"jail_path\": ", .{ instance.pid, instance.manager_pid, instance.jail_id });
        try writeJsonString(writer, instance.jail_path);
        try writer.writeAll(",\n  \"username\": ");
        try writeJsonString(writer, instance.username);
        try writer.writeAll(",\n  \"binary_path\": ");
        try writeJsonString(writer, instance.binary_path);
        try writer.print(",\n  \"start_time\": {d},\n  \"workspace_path\": ", .{instance.start_time});
        if (instance.workspace_path) |wp| {
            try writeJsonString(writer, wp);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("\n}\n");

        try writer.flush();
    }

    /// Unregister an instance
    pub fn unregister(self: *Self, name: []const u8) void {
        if (!isValidInstanceName(name)) return;
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
        manager_pid: i32,
        jail_id: i32,
        jail_path: []const u8,
        username: []const u8,
        binary_path: []const u8,
        state: InstanceState,
        start_time: i64,

        allocator: Allocator,

        pub fn deinit(self: *InstanceInfo) void {
            self.allocator.free(self.name);
            self.allocator.free(self.jail_path);
            self.allocator.free(self.username);
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
        const manager_pid = extractJsonInt(content, "manager_pid") catch 0;
        const jail_id = try extractJsonInt(content, "jail_id");
        const jail_path = try extractJsonString(self.allocator, content, "jail_path");
        errdefer self.allocator.free(jail_path);
        const username = try extractJsonString(self.allocator, content, "username");
        errdefer self.allocator.free(username);
        const binary_path = try extractJsonString(self.allocator, content, "binary_path");
        errdefer self.allocator.free(binary_path);
        const start_time = try extractJsonInt(content, "start_time");

        // Check if process is still running
        const state = checkProcessState(pid, jail_id);

        return .{
            .name = name,
            .pid = @intCast(pid),
            .manager_pid = @intCast(manager_pid),
            .jail_id = @intCast(jail_id),
            .jail_path = jail_path,
            .username = username,
            .binary_path = binary_path,
            .state = state,
            .start_time = start_time,
            .allocator = self.allocator,
        };
    }

    /// Get instance by name
    pub fn get(self: *Self, name: []const u8) !?InstanceInfo {
        if (!isValidInstanceName(name)) return null;
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
            // Release builds define _FORTIFY_SOURCE, and the fortified libc wrappers do
            // not survive translate-c; they add nothing for calls made from Zig.
            @cUndef("_FORTIFY_SOURCE");
            @cDefine("_FORTIFY_SOURCE", "0");
            @cInclude("sys/param.h");
            @cInclude("sys/uio.h");
            @cInclude("sys/jail.h");
        });

        // Look the jail up by jid with jail_get(2), which only reads. The
        // previous jail_attach(2) probe succeeds when run as root (doas
        // isolate stop/clean) and moves this very process into the jail.
        var jid: c_int = @intCast(jail_id);
        var iov = [_]c.struct_iovec{
            .{ .iov_base = @ptrCast(@constCast("jid")), .iov_len = 4 },
            .{ .iov_base = @ptrCast(&jid), .iov_len = @sizeOf(c_int) },
        };
        if (c.jail_get(&iov, iov.len, 0) >= 0) {
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

/// Simple JSON string extraction (handles the escapes writeJsonString emits)
fn extractJsonString(allocator: Allocator, json: []const u8, key: []const u8) ![]const u8 {
    var search_buf: [64]u8 = undefined;
    const search = try std.fmt.bufPrint(&search_buf, "\"{s}\": \"", .{key});

    const start_idx = std.mem.find(u8, json, search) orelse return error.KeyNotFound;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i = start_idx + search.len;
    while (i < json.len) : (i += 1) {
        const ch = json[i];
        if (ch == '"') return out.toOwnedSlice(allocator);
        if (ch != '\\') {
            try out.append(allocator, ch);
            continue;
        }
        i += 1;
        if (i >= json.len) return error.InvalidJson;
        switch (json[i]) {
            '"', '\\', '/' => |e| try out.append(allocator, e),
            'n' => try out.append(allocator, '\n'),
            't' => try out.append(allocator, '\t'),
            'r' => try out.append(allocator, '\r'),
            'u' => {
                if (i + 4 >= json.len) return error.InvalidJson;
                const code = std.fmt.parseInt(u16, json[i + 1 .. i + 5], 16) catch return error.InvalidJson;
                if (code > 0xff) return error.InvalidJson;
                try out.append(allocator, @intCast(code));
                i += 4;
            },
            else => return error.InvalidJson,
        }
    }
    return error.InvalidJson;
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

test "extractJsonString unescapes" {
    const json =
        \\{"name": "a\"b\\c\u0001"}
    ;
    const allocator = std.testing.allocator;
    const name = try extractJsonString(allocator, json, "name");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("a\"b\\c\x01", name);
}

test "writeJsonString round trip" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"name\": ");
    try writeJsonString(&w, "x\"y\\z\n");
    try w.writeAll("}");
    const name = try extractJsonString(allocator, w.buffered(), "name");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("x\"y\\z\n", name);
}

test "isValidInstanceName" {
    try std.testing.expect(isValidInstanceName("myapp-abc123"));
    try std.testing.expect(isValidInstanceName("tenant_1.prod"));
    try std.testing.expect(!isValidInstanceName(""));
    try std.testing.expect(!isValidInstanceName(".hidden"));
    try std.testing.expect(!isValidInstanceName("../../etc/passwd"));
    try std.testing.expect(!isValidInstanceName("a/b"));
    try std.testing.expect(!isValidInstanceName("with space"));
    try std.testing.expect(!isValidInstanceName("x" ** 65));
}

test "register is exclusive and leaves no temporary file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var dir_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);

    var reg = Registry{ .io = io, .allocator = allocator, .registry_dir = dir_buf[0..dir_len] };

    const inst = Instance{
        .name = "unique-name",
        .pid = 100,
        .manager_pid = 99,
        .jail_id = 5,
        .jail_path = "/var/run/isolate/inst-aB3dE9/root",
        .username = "app-100",
        .binary_path = "/bin/x \"quoted\"",
        .start_time = 1,
        .workspace_path = null,
        .allocator = allocator,
    };

    try std.testing.expect(!reg.exists("unique-name"));
    try reg.register(inst);
    try std.testing.expect(reg.exists("unique-name"));

    // A second instance of the same name is refused, and the first entry
    // is untouched
    var other = inst;
    other.pid = 200;
    other.manager_pid = 199;
    try std.testing.expectError(error.InstanceNameInUse, reg.register(other));

    var info = (try reg.get("unique-name")).?;
    defer info.deinit();
    try std.testing.expectEqual(@as(i32, 100), info.pid);
    try std.testing.expectEqualStrings("/bin/x \"quoted\"", info.binary_path);

    // Only the entry itself is in the directory
    var count: usize = 0;
    var it = tmp.dir.iterate();
    while (try it.next(io)) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 1), count);

    reg.unregister("unique-name");
    try std.testing.expect(!reg.exists("unique-name"));
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
