//! Capability file parsing for isolate
//!
//! This module provides parsing and validation of capability files that define
//! isolation requirements for applications. It replaces the C implementation
//! with type-safe Zig code and improved error handling.
//!
//! Capability file format:
//! ```
//! # Comment
//! user: auto
//! memory: 128M
//! processes: 5
//! network: tcp:8080:inbound
//! filesystem: /tmp:rw
//! env: MY_VAR=value
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum limits for rule arrays
pub const MAX_NETWORK_RULES = 16;
pub const MAX_FILE_RULES = 32;
pub const MAX_ENV_VARS = 32;
pub const MAX_ENV_NAME = 255;
pub const MAX_ENV_VALUE = 1023;

/// Network traffic direction
pub const Direction = enum(u8) {
    both = 0,
    outbound = 1,
    inbound = 2,

    pub fn fromString(s: []const u8) ?Direction {
        if (std.mem.eql(u8, s, "outbound") or std.mem.eql(u8, s, "out")) {
            return .outbound;
        } else if (std.mem.eql(u8, s, "inbound") or std.mem.eql(u8, s, "in")) {
            return .inbound;
        } else if (std.mem.eql(u8, s, "both")) {
            return .both;
        }
        return null;
    }
};

/// File permission flags. A rule is a nullfs mount, which is either
/// read-only or read-write; there is nothing else a rule can express.
pub const Permission = packed struct {
    read: bool = false,
    write: bool = false,
    _padding: u6 = 0,

    pub const read_only = Permission{ .read = true };
    pub const read_write = Permission{ .read = true, .write = true };

    /// "r" or "rw" (in either order, any case). Anything else - a
    /// write-only rule, an "x", an unknown letter, nothing at all - is null:
    /// isolate could not apply it as written.
    pub fn fromString(s: []const u8) ?Permission {
        var perm = Permission{};
        if (s.len == 0) return null;
        for (s) |c| {
            switch (c) {
                'r', 'R' => {
                    if (perm.read) return null;
                    perm.read = true;
                },
                'w', 'W' => {
                    if (perm.write) return null;
                    perm.write = true;
                },
                else => return null,
            }
        }
        if (!perm.read) return null;
        return perm;
    }

    pub fn format(self: Permission, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.read) try writer.writeByte('r');
        if (self.write) try writer.writeByte('w');
    }
};

/// Network access rule
pub const NetworkRule = struct {
    protocol: Protocol,
    address: []const u8,
    port: ?u16,
    direction: Direction,

    pub const Protocol = enum {
        tcp,
        udp,
        unix,
        none,

        pub fn fromString(s: []const u8) ?Protocol {
            if (std.mem.eql(u8, s, "tcp")) return .tcp;
            if (std.mem.eql(u8, s, "udp")) return .udp;
            if (std.mem.eql(u8, s, "unix")) return .unix;
            if (std.mem.eql(u8, s, "none")) return .none;
            return null;
        }
    };

    pub fn format(self: NetworkRule, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}", .{@tagName(self.protocol)});
        if (self.address.len > 0) {
            try writer.print(":{s}", .{self.address});
        }
        if (self.port) |p| {
            try writer.print(":{d}", .{p});
        }
        if (self.direction != .both) {
            try writer.print(":{s}", .{@tagName(self.direction)});
        }
    }
};

/// File access rule
pub const FileRule = struct {
    path: []const u8,
    permissions: Permission,

    pub fn format(self: FileRule, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}:{f}", .{ self.path, self.permissions });
    }
};

/// Environment variable
pub const EnvVar = struct {
    name: []const u8,
    value: []const u8,
};

/// Resource limits
pub const ResourceLimits = struct {
    memory_bytes: ?usize = null,
    max_processes: ?u32 = null,
    max_files: ?u32 = null,
};

/// Network isolation mode
pub const NetworkMode = enum {
    inherit, // Share host network stack (default, current behavior)
    none, // No network access at all
    vnet, // VNET jail with isolated network stack

    pub fn fromString(s: []const u8) ?NetworkMode {
        if (std.mem.eql(u8, s, "inherit")) return .inherit;
        if (std.mem.eql(u8, s, "none")) return .none;
        if (std.mem.eql(u8, s, "vnet") or std.mem.startsWith(u8, s, "vnet:")) return .vnet;
        return null;
    }
};

/// Network isolation configuration
pub const NetworkConfig = struct {
    mode: NetworkMode = .inherit,
    interface: ?[]const u8 = null, // Interface name for vnet mode
    ip_address: ?[]const u8 = null, // IP address to configure on interface (e.g., "10.0.99.2/24")
};

/// Complete capability specification
pub const Capabilities = struct {
    allocator: Allocator,

    // User context
    username: []const u8,
    create_user: bool,

    // Workspace
    workspace_path: ?[]const u8 = null,

    // Network isolation mode
    network_config: NetworkConfig = .{},

    // Network access rules (for firewall-style rules, separate from isolation mode)
    network_rules: std.ArrayList(NetworkRule),

    // Filesystem access
    file_rules: std.ArrayList(FileRule),

    // Environment
    env_vars: std.ArrayList(EnvVar),
    env_clear: bool,

    // System V IPC (shared memory, semaphores, message queues), private to the jail
    sysv_ipc: bool = false,

    // Resource limits
    limits: ResourceLimits,

    const Self = @This();

    /// Initialize with default values
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .username = "auto",
            .create_user = true,
            .network_rules = .empty,
            .file_rules = .empty,
            .env_vars = .empty,
            .env_clear = false,
            .limits = .{},
        };
    }

    /// Free all allocated memory
    pub fn deinit(self: *Self) void {
        // Free duplicated strings
        for (self.network_rules.items) |rule| {
            if (rule.address.len > 0) {
                self.allocator.free(rule.address);
            }
        }
        self.network_rules.deinit(self.allocator);

        for (self.file_rules.items) |rule| {
            self.allocator.free(rule.path);
        }
        self.file_rules.deinit(self.allocator);

        for (self.env_vars.items) |env| {
            self.allocator.free(env.name);
            self.allocator.free(env.value);
        }
        self.env_vars.deinit(self.allocator);

        if (self.workspace_path) |wp| {
            self.allocator.free(wp);
        }

        // Free network interface if allocated
        if (self.network_config.interface) |iface| {
            self.allocator.free(iface);
        }

        // Free network IP if allocated
        if (self.network_config.ip_address) |ip| {
            self.allocator.free(ip);
        }

        // Free username if it was allocated (not the default "auto")
        if (!std.mem.eql(u8, self.username, "auto")) {
            self.allocator.free(self.username);
        }
    }

    /// Print capabilities for debugging
    pub fn print(self: *const Self, writer: *std.Io.Writer) !void {
        try writer.print("Capabilities:\n", .{});
        try writer.print("  User: {s}{s}\n", .{
            self.username,
            if (self.create_user) " (auto-create)" else "",
        });

        if (self.limits.memory_bytes) |mem| {
            try writer.print("  Memory: {} bytes\n", .{mem});
        }
        if (self.limits.max_processes) |procs| {
            try writer.print("  Processes: {}\n", .{procs});
        }
        if (self.limits.max_files) |files| {
            try writer.print("  Files: {}\n", .{files});
        }

        // Network isolation mode
        try writer.print("  Network mode: {s}", .{@tagName(self.network_config.mode)});
        if (self.network_config.interface) |iface| {
            try writer.print(" (interface: {s})", .{iface});
        }
        try writer.print("\n", .{});

        try writer.print("  Network rules: {}\n", .{self.network_rules.items.len});
        for (self.network_rules.items) |rule| {
            try writer.print("    {f}\n", .{rule});
        }

        if (self.sysv_ipc) {
            try writer.print("  System V IPC: private to the jail\n", .{});
        }

        try writer.print("  File rules: {}\n", .{self.file_rules.items.len});
        for (self.file_rules.items) |rule| {
            try writer.print("    {f}\n", .{rule});
        }

        if (self.env_vars.items.len > 0) {
            try writer.print("  Environment variables: {}\n", .{self.env_vars.items.len});
            for (self.env_vars.items) |env| {
                try writer.print("    {s}={s}\n", .{ env.name, env.value });
            }
        }
    }
};

/// Errors that can occur during parsing
pub const ParseError = error{
    InvalidSyntax,
    InvalidMemorySize,
    InvalidNetworkRule,
    InvalidFileRule,
    InvalidEnvVar,
    UnknownCapability,
    TooManyRules,
    FileNotFound,
    PermissionDenied,
    OutOfMemory,
    IoError,
};

/// Result of parsing: the capabilities, and every line that could not be
/// applied as written. A non-empty `problems` list means the file must not
/// be used; see docs/design/02-capability-file.md, CAP-2.
pub const ParseResult = struct {
    caps: Capabilities,
    problems: std.ArrayList(Problem),

    pub const Problem = struct {
        line: usize,
        message: []const u8,
    };

    pub fn deinit(self: *ParseResult) void {
        for (self.problems.items) |w| {
            self.caps.allocator.free(w.message);
        }
        self.problems.deinit(self.caps.allocator);
        self.caps.deinit();
    }
};

/// Parse a memory size string (e.g., "128M", "1G", "512K")
pub fn parseMemorySize(size_str: []const u8) ParseError!usize {
    if (size_str.len == 0) return ParseError.InvalidMemorySize;

    // Find where the numeric part ends
    var num_end: usize = 0;
    var has_dot = false;
    for (size_str, 0..) |c, i| {
        if (c == '.') {
            if (has_dot) return ParseError.InvalidMemorySize;
            has_dot = true;
            num_end = i + 1;
        } else if (c >= '0' and c <= '9') {
            num_end = i + 1;
        } else {
            break;
        }
    }

    if (num_end == 0) return ParseError.InvalidMemorySize;

    const num_part = size_str[0..num_end];
    const suffix = if (num_end < size_str.len) size_str[num_end..] else "";

    const value = std.fmt.parseFloat(f64, num_part) catch {
        return ParseError.InvalidMemorySize;
    };

    if (value < 0) return ParseError.InvalidMemorySize;

    const multiplier: usize = if (suffix.len == 0)
        1
    else switch (std.ascii.toUpper(suffix[0])) {
        'K' => 1024,
        'M' => 1024 * 1024,
        'G' => 1024 * 1024 * 1024,
        'B' => 1,
        else => return ParseError.InvalidMemorySize,
    };

    return @intFromFloat(value * @as(f64, @floatFromInt(multiplier)));
}

/// Parse a network rule string (e.g., "tcp:8080:inbound", "unix:/tmp/socket")
pub fn parseNetworkRule(allocator: Allocator, rule_str: []const u8) ParseError!NetworkRule {
    if (std.mem.eql(u8, rule_str, "none")) {
        return .{
            .protocol = .none,
            .address = "",
            .port = null,
            .direction = .both,
        };
    }

    var iter = std.mem.splitScalar(u8, rule_str, ':');

    // Parse protocol
    const proto_str = iter.next() orelse return ParseError.InvalidNetworkRule;
    const protocol = NetworkRule.Protocol.fromString(proto_str) orelse {
        return ParseError.InvalidNetworkRule;
    };

    var address: []const u8 = "";
    errdefer if (address.len > 0) allocator.free(address);
    var port: ?u16 = null;
    var direction: Direction = .both;

    if (protocol == .unix) {
        // Unix socket: unix:/path/to/socket
        if (iter.next()) |path| {
            address = try allocator.dupe(u8, path);
        }
    } else {
        // TCP/UDP: tcp:8080 or tcp:192.168.1.1:80:inbound
        if (iter.next()) |second| {
            // Check if it's a port number or address
            if (std.fmt.parseInt(u16, second, 10)) |p| {
                port = p;
                // Next could be direction
                if (iter.next()) |dir_str| {
                    direction = Direction.fromString(dir_str) orelse return ParseError.InvalidNetworkRule;
                }
            } else |_| {
                // It's an address
                address = try allocator.dupe(u8, second);
                // Next should be port
                if (iter.next()) |port_str| {
                    port = std.fmt.parseInt(u16, port_str, 10) catch return ParseError.InvalidNetworkRule;
                }
                // Next could be direction
                if (iter.next()) |dir_str| {
                    direction = Direction.fromString(dir_str) orelse return ParseError.InvalidNetworkRule;
                }
            }
        }
    }

    return .{
        .protocol = protocol,
        .address = address,
        .port = port,
        .direction = direction,
    };
}

/// Parse a file rule string (e.g., "/tmp:rw", "/etc/resolv.conf:r")
pub fn parseFileRule(allocator: Allocator, rule_str: []const u8) ParseError!FileRule {
    // Find the last colon that separates path from permissions
    const last_colon = std.mem.findScalarLast(u8, rule_str, ':');

    var path: []const u8 = undefined;
    var permissions: Permission = Permission.read_only;

    if (last_colon) |idx| {
        path = rule_str[0..idx];
        const perm_str = rule_str[idx + 1 ..];
        permissions = Permission.fromString(perm_str) orelse return ParseError.InvalidFileRule;
    } else {
        path = rule_str;
    }

    if (!isSafeMountPath(path)) return ParseError.InvalidFileRule;

    return .{
        .path = try allocator.dupe(u8, path),
        .permissions = permissions,
    };
}

/// Filesystem rules name host directories that are nullfs-mounted into the
/// jail at the same path. Only absolute, normalized paths below the root
/// are accepted: "/" would mount the whole host over the jail root, and
/// "." or ".." segments make a rule mean something other than it reads.
pub fn isSafeMountPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/') return false;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |segment| {
        if (segment.len == 0) return false;
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
    }
    return true;
}

/// true/1/yes or false/0/no; anything else is null
pub fn parseBool(value: []const u8) ?bool {
    if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1") or std.mem.eql(u8, value, "yes")) return true;
    if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0") or std.mem.eql(u8, value, "no")) return false;
    return null;
}

/// Parse an environment variable (e.g., "MY_VAR=value")
pub fn parseEnvVar(allocator: Allocator, env_str: []const u8) ParseError!EnvVar {
    const eq_idx = std.mem.findScalar(u8, env_str, '=') orelse {
        return ParseError.InvalidEnvVar;
    };

    const name = env_str[0..eq_idx];
    const value = env_str[eq_idx + 1 ..];

    if (name.len == 0 or name.len > MAX_ENV_NAME or value.len > MAX_ENV_VALUE) return ParseError.InvalidEnvVar;

    return .{
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, value),
    };
}

/// Load and parse a capability file
pub fn load(io: std.Io, allocator: Allocator, filename: []const u8) ParseError!ParseResult {
    const file = std.Io.Dir.cwd().openFile(io, filename, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound => ParseError.FileNotFound,
            error.AccessDenied => ParseError.PermissionDenied,
            else => ParseError.IoError,
        };
    };
    defer file.close(io);

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &read_buf);
    return loadFromReader(allocator, &file_reader.interface);
}

/// Load capabilities from any reader (useful for testing)
pub fn loadFromReader(allocator: Allocator, reader: *std.Io.Reader) ParseError!ParseResult {
    var caps = Capabilities.init(allocator);
    errdefer caps.deinit();

    var problems: std.ArrayList(ParseResult.Problem) = .empty;
    errdefer {
        for (problems.items) |w| {
            allocator.free(w.message);
        }
        problems.deinit(allocator);
    }

    var line_num: usize = 0;

    // Lines are bounded by the reader's buffer; a longer line is an error
    while (reader.takeDelimiter('\n') catch |err| switch (err) {
        error.StreamTooLong, error.ReadFailed => return ParseError.IoError,
    }) |line| {
        line_num += 1;

        // Trim whitespace
        const trimmed = std.mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Parse key: value
        const colon_idx = std.mem.findScalar(u8, trimmed, ':') orelse {
            const msg = try std.fmt.allocPrint(allocator, "Invalid syntax (expected 'key: value')", .{});
            try problems.append(allocator, .{ .line = line_num, .message = msg });
            continue;
        };

        const key = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
        // Strip inline comments from value
        var value_with_comment = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");
        const value = if (std.mem.findScalar(u8, value_with_comment, '#')) |hash_idx|
            std.mem.trim(u8, value_with_comment[0..hash_idx], " \t")
        else
            value_with_comment;

        // Parse capability based on key
        if (value.len == 0) {
            const msg = try std.fmt.allocPrint(allocator, "Missing value for {s}", .{key});
            try problems.append(allocator, .{ .line = line_num, .message = msg });
            continue;
        }

        if (std.mem.eql(u8, key, "user")) {
            if (!std.mem.eql(u8, caps.username, "auto")) allocator.free(caps.username);
            if (std.mem.eql(u8, value, "auto")) {
                caps.username = "auto";
                caps.create_user = true;
            } else {
                caps.username = try allocator.dupe(u8, value);
                caps.create_user = false;
            }
        } else if (std.mem.eql(u8, key, "memory")) {
            caps.limits.memory_bytes = parseMemorySize(value) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid memory size: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
        } else if (std.mem.eql(u8, key, "processes")) {
            caps.limits.max_processes = std.fmt.parseInt(u32, value, 10) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid process count: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
        } else if (std.mem.eql(u8, key, "files")) {
            caps.limits.max_files = std.fmt.parseInt(u32, value, 10) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid file count: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
        } else if (std.mem.eql(u8, key, "cpu")) {
            // rctl's pcpu limit is too coarse to honour a percentage, so
            // the key is refused rather than accepted and ignored
            const msg = try std.fmt.allocPrint(allocator, "cpu: CPU limits are not supported", .{});
            try problems.append(allocator, .{ .line = line_num, .message = msg });
        } else if (std.mem.eql(u8, key, "network")) {
            if (caps.network_rules.items.len >= MAX_NETWORK_RULES) {
                const msg = try std.fmt.allocPrint(allocator, "Too many network rules (max {})", .{MAX_NETWORK_RULES});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            }
            const rule = parseNetworkRule(allocator, value) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid network rule: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
            try caps.network_rules.append(allocator, rule);
        } else if (std.mem.eql(u8, key, "filesystem") or std.mem.eql(u8, key, "file")) {
            if (caps.file_rules.items.len >= MAX_FILE_RULES) {
                const msg = try std.fmt.allocPrint(allocator, "Too many file rules (max {})", .{MAX_FILE_RULES});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            }
            const rule = parseFileRule(allocator, value) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid file rule: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
            try caps.file_rules.append(allocator, rule);
        } else if (std.mem.eql(u8, key, "env")) {
            if (caps.env_vars.items.len >= MAX_ENV_VARS) {
                const msg = try std.fmt.allocPrint(allocator, "Too many env vars (max {})", .{MAX_ENV_VARS});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            }
            const env = parseEnvVar(allocator, value) catch {
                const msg = try std.fmt.allocPrint(allocator, "Invalid env var: {s}", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
            try caps.env_vars.append(allocator, env);
        } else if (std.mem.eql(u8, key, "env_clear") or std.mem.eql(u8, key, "sysv_ipc")) {
            const flag = parseBool(value) orelse {
                const msg = try std.fmt.allocPrint(allocator, "Invalid {s}: {s} (use true or false)", .{ key, value });
                try problems.append(allocator, .{ .line = line_num, .message = msg });
                continue;
            };
            if (std.mem.eql(u8, key, "env_clear")) {
                caps.env_clear = flag;
            } else {
                caps.sysv_ipc = flag;
            }
        } else if (std.mem.eql(u8, key, "network_mode")) {
            // Parse network isolation mode: inherit, none, or vnet:<interface>
            if (std.mem.eql(u8, value, "inherit")) {
                caps.network_config.mode = .inherit;
            } else if (std.mem.eql(u8, value, "none")) {
                caps.network_config.mode = .none;
            } else if (std.mem.startsWith(u8, value, "vnet:")) {
                caps.network_config.mode = .vnet;
                const iface = value[5..]; // Skip "vnet:"
                if (caps.network_config.interface) |old| allocator.free(old);
                caps.network_config.interface = null;
                if (iface.len > 0) {
                    caps.network_config.interface = try allocator.dupe(u8, iface);
                } else {
                    const msg = try std.fmt.allocPrint(allocator, "Invalid network_mode: vnet: needs an interface name", .{});
                    try problems.append(allocator, .{ .line = line_num, .message = msg });
                }
            } else if (std.mem.eql(u8, value, "vnet")) {
                caps.network_config.mode = .vnet;
                // No interface specified - will need --vnet CLI arg
            } else {
                const msg = try std.fmt.allocPrint(allocator, "Invalid network_mode: {s} (use inherit, none, or vnet:<interface>)", .{value});
                try problems.append(allocator, .{ .line = line_num, .message = msg });
            }
        } else if (std.mem.eql(u8, key, "network_ip")) {
            // IP address to configure on VNET interface (e.g., "10.0.99.2/24")
            if (caps.network_config.ip_address) |old| allocator.free(old);
            caps.network_config.ip_address = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "workspace")) {
            if (caps.workspace_path) |old| allocator.free(old);
            caps.workspace_path = try allocator.dupe(u8, value);
        } else {
            const msg = try std.fmt.allocPrint(allocator, "Unknown capability: {s}", .{key});
            try problems.append(allocator, .{ .line = line_num, .message = msg });
        }
    }

    return .{
        .caps = caps,
        .problems = problems,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseMemorySize" {
    // Basic sizes
    try std.testing.expectEqual(@as(usize, 128), try parseMemorySize("128"));
    try std.testing.expectEqual(@as(usize, 128), try parseMemorySize("128B"));

    // Kilobytes
    try std.testing.expectEqual(@as(usize, 1024), try parseMemorySize("1K"));
    try std.testing.expectEqual(@as(usize, 512 * 1024), try parseMemorySize("512K"));

    // Megabytes
    try std.testing.expectEqual(@as(usize, 128 * 1024 * 1024), try parseMemorySize("128M"));
    try std.testing.expectEqual(@as(usize, 1024 * 1024), try parseMemorySize("1M"));

    // Gigabytes
    try std.testing.expectEqual(@as(usize, 1024 * 1024 * 1024), try parseMemorySize("1G"));
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024 * 1024), try parseMemorySize("2G"));

    // Decimal values
    try std.testing.expectEqual(@as(usize, 1536 * 1024), try parseMemorySize("1.5M"));

    // Invalid
    try std.testing.expectError(ParseError.InvalidMemorySize, parseMemorySize(""));
    try std.testing.expectError(ParseError.InvalidMemorySize, parseMemorySize("abc"));
    try std.testing.expectError(ParseError.InvalidMemorySize, parseMemorySize("-128M"));
}

test "parseNetworkRule" {
    const allocator = std.testing.allocator;

    // TCP with port
    {
        const rule = try parseNetworkRule(allocator, "tcp:8080");
        defer if (rule.address.len > 0) allocator.free(rule.address);
        try std.testing.expectEqual(NetworkRule.Protocol.tcp, rule.protocol);
        try std.testing.expectEqual(@as(?u16, 8080), rule.port);
        try std.testing.expectEqual(Direction.both, rule.direction);
    }

    // TCP with direction
    {
        const rule = try parseNetworkRule(allocator, "tcp:8080:inbound");
        defer if (rule.address.len > 0) allocator.free(rule.address);
        try std.testing.expectEqual(NetworkRule.Protocol.tcp, rule.protocol);
        try std.testing.expectEqual(@as(?u16, 8080), rule.port);
        try std.testing.expectEqual(Direction.inbound, rule.direction);
    }

    // UDP outbound
    {
        const rule = try parseNetworkRule(allocator, "udp:53:outbound");
        defer if (rule.address.len > 0) allocator.free(rule.address);
        try std.testing.expectEqual(NetworkRule.Protocol.udp, rule.protocol);
        try std.testing.expectEqual(@as(?u16, 53), rule.port);
        try std.testing.expectEqual(Direction.outbound, rule.direction);
    }

    // Unix socket
    {
        const rule = try parseNetworkRule(allocator, "unix:/tmp/socket");
        defer if (rule.address.len > 0) allocator.free(rule.address);
        try std.testing.expectEqual(NetworkRule.Protocol.unix, rule.protocol);
        try std.testing.expectEqualStrings("/tmp/socket", rule.address);
    }

    // None
    {
        const rule = try parseNetworkRule(allocator, "none");
        try std.testing.expectEqual(NetworkRule.Protocol.none, rule.protocol);
    }
}

test "parseFileRule" {
    const allocator = std.testing.allocator;

    // Read-only (default)
    {
        const rule = try parseFileRule(allocator, "/tmp");
        defer allocator.free(rule.path);
        try std.testing.expectEqualStrings("/tmp", rule.path);
        try std.testing.expect(rule.permissions.read);
        try std.testing.expect(!rule.permissions.write);
    }

    // Explicit read-only
    {
        const rule = try parseFileRule(allocator, "/etc/resolv.conf:r");
        defer allocator.free(rule.path);
        try std.testing.expectEqualStrings("/etc/resolv.conf", rule.path);
        try std.testing.expect(rule.permissions.read);
        try std.testing.expect(!rule.permissions.write);
    }

    // Read-write
    {
        const rule = try parseFileRule(allocator, "/tmp/myapp:rw");
        defer allocator.free(rule.path);
        try std.testing.expectEqualStrings("/tmp/myapp", rule.path);
        try std.testing.expect(rule.permissions.read);
        try std.testing.expect(rule.permissions.write);
    }

    // Order and case of the letters do not matter
    {
        const rule = try parseFileRule(allocator, "/data:WR");
        defer allocator.free(rule.path);
        try std.testing.expect(rule.permissions.read and rule.permissions.write);
    }
}

test "parseFileRule rejects permissions it cannot apply" {
    const allocator = std.testing.allocator;
    // write-only, execute, unknown letters, repeated letters, empty
    const bad = [_][]const u8{ "/var/log:w", "/usr/bin/app:rx", "/data:rwx", "/data:x", "/data:rz", "/data:rr", "/data:" };
    for (bad) |rule| {
        try std.testing.expectError(ParseError.InvalidFileRule, parseFileRule(allocator, rule));
    }
}

test "parseNetworkRule rejects bad ports and directions" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.InvalidNetworkRule, parseNetworkRule(allocator, "tcp:8080:sideways"));
    try std.testing.expectError(ParseError.InvalidNetworkRule, parseNetworkRule(allocator, "tcp:10.0.0.1:notaport"));
    try std.testing.expectError(ParseError.InvalidNetworkRule, parseNetworkRule(allocator, "icmp:1"));
}

test "parseEnvVar rejects over-long entries" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.InvalidEnvVar, parseEnvVar(allocator, "N" ** 256 ++ "=v"));
    try std.testing.expectError(ParseError.InvalidEnvVar, parseEnvVar(allocator, "NAME=" ++ "v" ** 1024));
}

test "loadFromReader reports every line it cannot apply" {
    const allocator = std.testing.allocator;
    const content =
        \\user: auto
        \\memroy: 64M
        \\cpu: 50
        \\network_default: deny
        \\filesystem_default: deny
        \\filesystem: /var/log:w
        \\filesystem: /:rw
        \\env_clear: maybe
        \\memory:
        \\network_mode: vnet:
        \\not a key value line
        \\files: 64
    ;
    var reader: std.Io.Reader = .fixed(content);
    var result = try loadFromReader(allocator, &reader);
    defer result.deinit();

    // Every line except the first and the last is a problem
    try std.testing.expectEqual(@as(usize, 10), result.problems.items.len);
    for (result.problems.items, 2..) |problem, line| {
        try std.testing.expectEqual(line, problem.line);
    }
    try std.testing.expectEqual(@as(?u32, 64), result.caps.limits.max_files);
    try std.testing.expect(result.caps.limits.memory_bytes == null);
}

test "sysv_ipc is off unless asked for" {
    const allocator = std.testing.allocator;
    {
        var reader: std.Io.Reader = .fixed("user: auto\n");
        var result = try loadFromReader(allocator, &reader);
        defer result.deinit();
        try std.testing.expect(!result.caps.sysv_ipc);
    }
    {
        var reader: std.Io.Reader = .fixed("sysv_ipc: true\n");
        var result = try loadFromReader(allocator, &reader);
        defer result.deinit();
        try std.testing.expect(result.caps.sysv_ipc);
        try std.testing.expectEqual(@as(usize, 0), result.problems.items.len);
    }
    {
        var reader: std.Io.Reader = .fixed("sysv_ipc: shared\n");
        var result = try loadFromReader(allocator, &reader);
        defer result.deinit();
        try std.testing.expectEqual(@as(usize, 1), result.problems.items.len);
    }
}

test "loadFromReader: last value wins for repeated keys, without leaking" {
    const allocator = std.testing.allocator;
    const content =
        \\user: nobody
        \\user: www
        \\user: auto
        \\workspace: /a
        \\workspace: /b
        \\network_mode: vnet:epair0b
        \\network_mode: vnet:epair1b
        \\network_ip: 10.0.0.1/24
        \\network_ip: 10.0.0.2/24
    ;
    var reader: std.Io.Reader = .fixed(content);
    var result = try loadFromReader(allocator, &reader);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.problems.items.len);
    try std.testing.expectEqualStrings("auto", result.caps.username);
    try std.testing.expect(result.caps.create_user);
    try std.testing.expectEqualStrings("/b", result.caps.workspace_path.?);
    try std.testing.expectEqualStrings("epair1b", result.caps.network_config.interface.?);
    try std.testing.expectEqualStrings("10.0.0.2/24", result.caps.network_config.ip_address.?);
}

test "parseFileRule rejects unsafe paths" {
    const allocator = std.testing.allocator;
    const bad = [_][]const u8{ "/", "/:rw", "relative/path", "../etc:r", "/a/../etc:r", "/a/./b", "/a//b", "/etc/:r" };
    for (bad) |rule| {
        try std.testing.expectError(ParseError.InvalidFileRule, parseFileRule(allocator, rule));
    }
    try std.testing.expect(isSafeMountPath("/var/lib/app.d"));
    try std.testing.expect(isSafeMountPath("/tmp"));
}

test "parseEnvVar" {
    const allocator = std.testing.allocator;

    // Simple
    {
        const env = try parseEnvVar(allocator, "MY_VAR=hello");
        defer {
            allocator.free(env.name);
            allocator.free(env.value);
        }
        try std.testing.expectEqualStrings("MY_VAR", env.name);
        try std.testing.expectEqualStrings("hello", env.value);
    }

    // Value with equals sign
    {
        const env = try parseEnvVar(allocator, "PATH=/usr/bin:/bin");
        defer {
            allocator.free(env.name);
            allocator.free(env.value);
        }
        try std.testing.expectEqualStrings("PATH", env.name);
        try std.testing.expectEqualStrings("/usr/bin:/bin", env.value);
    }

    // Empty value
    {
        const env = try parseEnvVar(allocator, "EMPTY=");
        defer {
            allocator.free(env.name);
            allocator.free(env.value);
        }
        try std.testing.expectEqualStrings("EMPTY", env.name);
        try std.testing.expectEqualStrings("", env.value);
    }

    // Invalid (no equals)
    try std.testing.expectError(ParseError.InvalidEnvVar, parseEnvVar(allocator, "INVALID"));
}

test "loadFromReader" {
    const allocator = std.testing.allocator;

    const caps_content =
        \\# Test capability file
        \\user: auto
        \\memory: 128M
        \\processes: 5
        \\files: 256
        \\
        \\network: tcp:8080:inbound
        \\network: udp:53:outbound
        \\
        \\filesystem: /lib:r
        \\filesystem: /tmp:rw
        \\
        \\env: MY_VAR=hello
        \\env: PATH=/usr/bin:/bin
        \\
        \\env_clear: true
    ;

    var reader: std.Io.Reader = .fixed(caps_content);
    var result = try loadFromReader(allocator, &reader);
    defer result.deinit();

    const caps = &result.caps;

    // Check user
    try std.testing.expectEqualStrings("auto", caps.username);
    try std.testing.expect(caps.create_user);

    // Check limits
    try std.testing.expectEqual(@as(?usize, 128 * 1024 * 1024), caps.limits.memory_bytes);
    try std.testing.expectEqual(@as(?u32, 5), caps.limits.max_processes);
    try std.testing.expectEqual(@as(?u32, 256), caps.limits.max_files);

    // Check network rules
    try std.testing.expectEqual(@as(usize, 2), caps.network_rules.items.len);
    try std.testing.expectEqual(NetworkRule.Protocol.tcp, caps.network_rules.items[0].protocol);
    try std.testing.expectEqual(@as(?u16, 8080), caps.network_rules.items[0].port);
    try std.testing.expectEqual(Direction.inbound, caps.network_rules.items[0].direction);

    // Check file rules
    try std.testing.expectEqual(@as(usize, 2), caps.file_rules.items.len);
    try std.testing.expectEqualStrings("/lib", caps.file_rules.items[0].path);
    try std.testing.expect(caps.file_rules.items[0].permissions.read);
    try std.testing.expect(!caps.file_rules.items[0].permissions.write);

    // Check env vars
    try std.testing.expectEqual(@as(usize, 2), caps.env_vars.items.len);
    try std.testing.expectEqualStrings("MY_VAR", caps.env_vars.items[0].name);
    try std.testing.expectEqualStrings("hello", caps.env_vars.items[0].value);

    // Check env_clear
    try std.testing.expect(caps.env_clear);

    // No problems expected
    try std.testing.expectEqual(@as(usize, 0), result.problems.items.len);
}
