//! isolate - Infrastructureless container runner
//!
//! This is the main entry point for the isolate tool. It provides process
//! isolation using native OS primitives (FreeBSD jails, Linux namespaces).
//!
//! Usage:
//!   isolate <command> [options] [arguments]
//!
//! Commands:
//!   run      Run a binary in isolation
//!   detect   Detect and generate capability file
//!   list     List running isolated instances
//!   stop     Stop a running instance
//!   clean    Clean up orphaned instances and data

const std = @import("std");
const builtin = @import("builtin");
const c_api = @import("c_api.zig");
const caps = @import("caps.zig");
const detect = @import("detect.zig");
const registry = @import("registry.zig");
const syscheck = if (builtin.os.tag == .freebsd) @import("syscheck.zig") else struct {
    pub const SystemCapabilities = struct {
        racct_enabled: bool,
        vnet_available: bool,
        jails_available: bool,
        is_root: bool,
        osreldate: u32,
    };
    pub fn detect() SystemCapabilities {
        return .{ .racct_enabled = false, .vnet_available = false, .jails_available = false, .is_root = false, .osreldate = 0 };
    }
    pub fn printCheck(_: SystemCapabilities, writer: *std.Io.Writer) !void {
        try writer.print("System check only available on FreeBSD\n", .{});
    }
};

// Platform-specific isolation modules
const freebsd = if (builtin.os.tag == .freebsd) @import("freebsd.zig") else struct {};

const c = c_api.c;

/// Program version
pub const version = "0.3.0-zig";

/// Unbuffered stdout writer. Unbuffered so that nothing is left behind in a
/// buffer across fork()/execv()/_exit() in the isolation path.
fn stdoutWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stdout().writer(io, &.{});
}

/// Unbuffered stderr writer.
fn stderrWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stderr().writer(io, &.{});
}

/// Subcommands
const Command = enum {
    run,
    detect,
    list,
    stop,
    clean,
    check,
    help,
    version,
};

/// Run command options
const RunOptions = struct {
    caps_file: ?[]const u8 = null,
    workspace_dir: ?[]const u8 = null,
    name: ?[]const u8 = null,
    vnet_interface: ?[]const u8 = null,
    verbose: bool = false,
    dry_run: bool = false,
    target_binary: ?[]const u8 = null,
    binary_args: []const []const u8 = &.{},
};

/// Detect command options
const DetectOptions = struct {
    output_file: ?[]const u8 = null,
    target_binary: ?[]const u8 = null,
};

/// Stop command options
const StopOptions = struct {
    force: bool = false,
    name: ?[]const u8 = null,
};

/// Parsed arguments with owned memory
const ParsedArgs = struct {
    command: Command,
    run_opts: RunOptions = .{},
    detect_opts: DetectOptions = .{},
    stop_opts: StopOptions = .{},
    _allocator: std.mem.Allocator,

    pub fn deinit(self: *ParsedArgs) void {
        // Free binary_args if it was allocated
        if (self.run_opts.binary_args.len > 0) {
            self._allocator.free(self.run_opts.binary_args);
        }
    }
};

/// Parse command line arguments. `args` lives for the whole process (arena).
fn parseArgs(allocator: std.mem.Allocator, args: []const [:0]const u8) !ParsedArgs {
    var result = ParsedArgs{
        .command = .help,
        ._allocator = allocator,
    };

    if (args.len < 2) {
        return result; // Default to help
    }

    // Parse command
    const cmd_str = args[1];

    // Handle legacy flags as commands
    if (std.mem.eql(u8, cmd_str, "-h") or std.mem.eql(u8, cmd_str, "--help")) {
        result.command = .help;
        return result;
    }
    if (std.mem.eql(u8, cmd_str, "-V") or std.mem.eql(u8, cmd_str, "--version")) {
        result.command = .version;
        return result;
    }
    // Legacy detect mode
    if (std.mem.eql(u8, cmd_str, "-d") or std.mem.eql(u8, cmd_str, "--detect")) {
        result.command = .detect;
        // Parse remaining args for detect
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.startsWith(u8, arg, "-")) {
                if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
                    i += 1;
                    if (i >= args.len) return error.MissingArgument;
                    result.detect_opts.output_file = args[i];
                }
            } else {
                if (result.detect_opts.target_binary == null) {
                    result.detect_opts.target_binary = arg;
                } else if (result.detect_opts.output_file == null) {
                    result.detect_opts.output_file = arg;
                }
            }
        }
        return result;
    }

    // Parse subcommand
    if (std.mem.eql(u8, cmd_str, "run")) {
        result.command = .run;
        try parseRunArgs(&result.run_opts, args[2..], allocator);
    } else if (std.mem.eql(u8, cmd_str, "detect")) {
        result.command = .detect;
        try parseDetectArgs(&result.detect_opts, args[2..]);
    } else if (std.mem.eql(u8, cmd_str, "list") or std.mem.eql(u8, cmd_str, "ls")) {
        result.command = .list;
    } else if (std.mem.eql(u8, cmd_str, "stop")) {
        result.command = .stop;
        try parseStopArgs(&result.stop_opts, args[2..]);
    } else if (std.mem.eql(u8, cmd_str, "clean") or std.mem.eql(u8, cmd_str, "cleanup")) {
        result.command = .clean;
    } else if (std.mem.eql(u8, cmd_str, "check")) {
        result.command = .check;
    } else if (std.mem.eql(u8, cmd_str, "help")) {
        result.command = .help;
    } else if (std.mem.eql(u8, cmd_str, "version")) {
        result.command = .version;
    } else {
        // Legacy mode: treat first arg as binary path for 'run' command
        result.command = .run;
        try parseRunArgs(&result.run_opts, args[1..], allocator);
    }

    return result;
}

/// Parse run command arguments
fn parseRunArgs(opts: *RunOptions, args: []const [:0]const u8, allocator: std.mem.Allocator) !void {
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--caps")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.caps_file = args[i];
            } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--workspace")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.workspace_dir = args[i];
            } else if (std.mem.eql(u8, arg, "-N") or std.mem.eql(u8, arg, "--name")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.name = args[i];
            } else if (std.mem.eql(u8, arg, "--vnet")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.vnet_interface = args[i];
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
                opts.verbose = true;
            } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--dry-run")) {
                opts.dry_run = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return error.UnknownOption;
            }
        } else {
            try positional.append(allocator, arg);
        }
    }

    // First positional is target binary
    if (positional.items.len > 0) {
        opts.target_binary = positional.items[0];
        if (positional.items.len > 1) {
            opts.binary_args = try allocator.dupe([]const u8, positional.items[1..]);
        }
    }
}

/// Parse detect command arguments
fn parseDetectArgs(opts: *DetectOptions, args: []const [:0]const u8) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.output_file = args[i];
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return error.UnknownOption;
            }
        } else {
            if (opts.target_binary == null) {
                opts.target_binary = arg;
            } else if (opts.output_file == null) {
                opts.output_file = arg;
            }
        }
    }
}

/// Parse stop command arguments
fn parseStopArgs(opts: *StopOptions, args: []const [:0]const u8) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.startsWith(u8, arg, "-")) {
            if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--force")) {
                opts.force = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return error.UnknownOption;
            }
        } else {
            if (opts.name == null) {
                opts.name = arg;
            }
        }
    }
}

/// Print main usage information
fn printUsage(io: std.Io) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print(
        \\isolate - Infrastructureless container runner
        \\
        \\Usage: isolate <command> [options] [arguments]
        \\
        \\Commands:
        \\  run      Run a binary in isolation (default)
        \\  detect   Detect and generate capability file
        \\  list     List running isolated instances
        \\  stop     Stop a running instance
        \\  clean    Clean up orphaned instances and data
        \\  check    Check system capabilities for isolation
        \\
        \\Run 'isolate <command> --help' for command-specific help.
        \\
        \\Examples:
        \\  # Generate capability file for an application
        \\  isolate detect ./myapp
        \\
        \\  # Run application in isolation
        \\  doas isolate run ./myapp
        \\
        \\  # Run with workspace directory
        \\  doas isolate run -w /path/to/data ./myapp
        \\
        \\  # List running instances
        \\  isolate list
        \\
        \\  # Stop an instance
        \\  doas isolate stop myapp-abc123
        \\
        \\  # Clean up orphaned instances
        \\  doas isolate clean
        \\
        \\Options:
        \\  -h, --help       Show this help
        \\  -V, --version    Show version
        \\
    , .{}) catch {};
}

/// Print run command usage
fn printRunUsage(io: std.Io) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print(
        \\Usage: isolate run [options] <binary> [args...]
        \\
        \\Run a binary in isolation using OS-native primitives.
        \\
        \\Options:
        \\  -c, --caps <file>      Capability file (default: <binary>.caps)
        \\  -w, --workspace <dir>  Workspace directory (mounted as /workspace)
        \\  -N, --name <name>      Instance name (default: auto-generated)
        \\  --vnet <interface>     Use VNET jail with specified network interface
        \\  -v, --verbose          Verbose output
        \\  -n, --dry-run          No isolation (dry run)
        \\
        \\Examples:
        \\  doas isolate run ./myapp
        \\  doas isolate run -c custom.caps ./myapp arg1 arg2
        \\  doas isolate run -w /data/tenant1 -N tenant1-app ./myapp
        \\  doas isolate run --vnet epair0b ./myapp
        \\
    , .{}) catch {};
}

/// Print detect command usage
fn printDetectUsage(io: std.Io) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print(
        \\Usage: isolate detect [options] <binary> [output.caps]
        \\
        \\Analyze a binary and generate a capability file.
        \\
        \\Options:
        \\  -o, --output <file>    Output capability file (default: <binary>.caps)
        \\
        \\Examples:
        \\  isolate detect ./myapp
        \\  isolate detect -o custom.caps ./myapp
        \\  isolate detect ./myapp ./myapp.caps
        \\
    , .{}) catch {};
}

/// Print version information
fn printVersion(io: std.Io) void {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    stdout.print("isolate {s}\n", .{version}) catch {};
    stdout.print("Platform: {s}\n", .{@tagName(builtin.os.tag)}) catch {};
    stdout.print("Architecture: {s}\n", .{@tagName(builtin.cpu.arch)}) catch {};
}

// ============================================================================
// Command Handlers
// ============================================================================

/// Handle 'detect' command
fn cmdDetect(io: std.Io, allocator: std.mem.Allocator, opts: DetectOptions) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    if (opts.target_binary == null) {
        std.debug.print("Error: No target binary specified for detection\n", .{});
        printDetectUsage(io);
        return 1;
    }

    try stdout.print("Isolate Capability Detection\n", .{});
    try stdout.print("============================\n\n", .{});

    // Use native Zig ELF detection
    detect.detectCapabilities(io, allocator, opts.target_binary.?, opts.output_file) catch |err| {
        std.debug.print("Detection failed: {}\n", .{err});
        return 1;
    };

    try stdout.print("\nNext steps:\n", .{});
    try stdout.print("1. Review the generated capability file\n", .{});
    try stdout.print("2. Edit capabilities as needed\n", .{});
    try stdout.print("3. Run: doas isolate run {s}\n", .{opts.target_binary.?});

    return 0;
}

/// Handle 'run' command
fn cmdRun(io: std.Io, allocator: std.mem.Allocator, opts: RunOptions) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    if (opts.target_binary == null) {
        try stderr.print("Error: No target binary specified\n", .{});
        printRunUsage(io);
        return 1;
    }

    const target_binary = opts.target_binary.?;

    // Determine capability file
    var caps_file_buf: [c_api.PATH_MAX]u8 = undefined;
    const caps_file = if (opts.caps_file) |cf|
        cf
    else blk: {
        const formatted = std.fmt.bufPrint(&caps_file_buf, "{s}.caps", .{target_binary}) catch {
            try stderr.print("Error: Path too long\n", .{});
            return 1;
        };
        break :blk formatted;
    };

    if (opts.verbose) {
        try stdout.print("Isolate Process Isolation\n", .{});
        try stdout.print("=========================\n", .{});
        try stdout.print("Target binary: {s}\n", .{target_binary});
        try stdout.print("Capability file: {s}\n", .{caps_file});
        if (opts.workspace_dir) |ws| {
            try stdout.print("Workspace directory: {s}\n", .{ws});
        }
        if (opts.name) |name| {
            try stdout.print("Instance name: {s}\n", .{name});
        }
        try stdout.print("\n", .{});
    }

    // Validate workspace if specified
    if (opts.workspace_dir) |ws| {
        const stat = std.Io.Dir.cwd().statFile(io, ws, .{}) catch |err| {
            try stderr.print("Error: Workspace directory {s} - {}\n", .{ ws, err });
            return 1;
        };
        if (stat.kind != .directory) {
            try stderr.print("Error: {s} is not a directory\n", .{ws});
            return 1;
        }
    }

    // Load capabilities using Zig-native parser
    var parse_result: caps.ParseResult = undefined;

    if (caps.load(io, allocator, caps_file)) |result| {
        parse_result = result;
    } else |err| {
        if (err == caps.ParseError.FileNotFound) {
            try stderr.print("Warning: No capability file at {s}\n", .{caps_file});
        } else {
            try stderr.print("Warning: Could not load capabilities from {s}: {}\n", .{ caps_file, err });
        }
        try stderr.print("Running with default capabilities: ephemeral user, inherited network, no filesystem rules.\n", .{});
        try stderr.print("Nothing (not even /lib or /libexec) is mounted in the jail, so dynamically linked binaries will not start.\n", .{});
        try stderr.print("Run 'isolate detect {s}' to generate a capability file.\n\n", .{target_binary});
        // Use default capabilities
        parse_result = .{
            .caps = caps.Capabilities.init(allocator),
            .warnings = .empty,
        };
    }
    defer parse_result.deinit();

    // Print any warnings from parsing
    if (parse_result.warnings.items.len > 0 and opts.verbose) {
        for (parse_result.warnings.items) |warning| {
            try stderr.print("Warning (line {}): {s}\n", .{ warning.line, warning.message });
        }
    }

    // Set workspace path if specified
    if (opts.workspace_dir) |ws| {
        if (parse_result.caps.workspace_path) |old_wp| {
            allocator.free(old_wp);
        }
        parse_result.caps.workspace_path = try allocator.dupe(u8, ws);
    }

    // Set VNET interface if specified via CLI (overrides caps file)
    if (opts.vnet_interface) |iface| {
        parse_result.caps.network_config.mode = .vnet;
        if (parse_result.caps.network_config.interface) |old_iface| {
            allocator.free(old_iface);
        }
        parse_result.caps.network_config.interface = try allocator.dupe(u8, iface);
    }

    if (opts.verbose) {
        try parse_result.caps.print(stdout);
        try stdout.print("\n", .{});
    }

    if (opts.dry_run) {
        try stdout.print("Dry run - would execute with the above isolation settings.\n", .{});
        try stdout.print("Command would be: {s}", .{target_binary});
        for (opts.binary_args) |arg| {
            try stdout.print(" {s}", .{arg});
        }
        try stdout.print("\n", .{});
        return 0;
    }

    // Check for root privileges
    if (c.geteuid() != 0) {
        try stderr.print("Error: Isolation requires root privileges\n", .{});
        try stderr.print("Run with: doas isolate run {s}\n", .{target_binary});
        return 1;
    }

    // Set environment variable for C code
    _ = c.setenv("ISOLATE_TARGET_BINARY", @ptrCast(target_binary.ptr), 1);

    if (opts.verbose) {
        try stdout.print("Creating isolation context...\n", .{});
    }

    // Run isolation using native Zig implementation
    return runIsolation(io, allocator, &parse_result.caps, target_binary, opts.binary_args, opts.name, opts.verbose);
}

/// Handle 'list' command
fn cmdList(io: std.Io, allocator: std.mem.Allocator) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    var reg = registry.Registry.init(io, allocator);
    var instances = try reg.list();
    defer {
        for (instances.items) |*inst| {
            inst.deinit();
        }
        instances.deinit(allocator);
    }

    if (instances.items.len == 0) {
        try stdout.print("No running instances found.\n", .{});
        return 0;
    }

    // Print header
    try stdout.print("{s:<20} {s:<8} {s:<8} {s:<10} {s}\n", .{ "NAME", "PID", "JAIL_ID", "STATE", "BINARY" });
    try stdout.print("{s:-<20} {s:-<8} {s:-<8} {s:-<10} {s:-<30}\n", .{ "", "", "", "", "" });

    // Print instances
    for (instances.items) |inst| {
        const state_str = switch (inst.state) {
            .running => "running",
            .stopped => "stopped",
            .orphaned => "orphaned",
        };

        // Truncate binary path if too long
        var binary_display: [30]u8 = undefined;
        const binary_path = if (inst.binary_path.len > 29) blk: {
            @memcpy(binary_display[0..27], inst.binary_path[inst.binary_path.len - 27 ..]);
            binary_display[0] = '.';
            binary_display[1] = '.';
            binary_display[2] = '.';
            break :blk binary_display[0..30];
        } else inst.binary_path;

        try stdout.print("{s:<20} {d:<8} {d:<8} {s:<10} {s}\n", .{
            inst.name,
            inst.pid,
            inst.jail_id,
            state_str,
            binary_path,
        });
    }

    return 0;
}

/// Handle 'stop' command
fn cmdStop(io: std.Io, allocator: std.mem.Allocator, opts: StopOptions) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    if (opts.name == null) {
        try stderr.print("Error: No instance name specified\n", .{});
        try stderr.print("Usage: isolate stop <name>\n", .{});
        try stderr.print("Run 'isolate list' to see running instances.\n", .{});
        return 1;
    }

    // Check for root privileges
    if (c.geteuid() != 0) {
        try stderr.print("Error: Stopping instances requires root privileges\n", .{});
        try stderr.print("Run with: doas isolate stop {s}\n", .{opts.name.?});
        return 1;
    }

    var reg = registry.Registry.init(io, allocator);

    const inst_opt = try reg.get(opts.name.?);
    if (inst_opt == null) {
        try stderr.print("Error: Instance '{s}' not found\n", .{opts.name.?});
        return 1;
    }

    var inst = inst_opt.?;
    defer inst.deinit();

    if (inst.state != .running and !opts.force) {
        try stderr.print("Instance '{s}' is not running (state: {s})\n", .{
            opts.name.?,
            @tagName(inst.state),
        });
        try stderr.print("Use -f/--force to clean up anyway.\n", .{});
        return 1;
    }

    try stdout.print("Stopping instance '{s}'...\n", .{opts.name.?});

    // Send SIGTERM to the process
    if (inst.state == .running) {
        const kill_result = c.kill(inst.pid, c.SIGTERM);
        if (kill_result < 0) {
            try stderr.print("Warning: Failed to send SIGTERM to PID {d}\n", .{inst.pid});
        } else {
            try stdout.print("Sent SIGTERM to PID {d}\n", .{inst.pid});

            // Wait a moment for graceful shutdown
            io.sleep(.fromMilliseconds(500), .awake) catch {};
        }

        // Check if still running
        if (c.kill(inst.pid, 0) == 0) {
            if (opts.force) {
                try stdout.print("Process still running, sending SIGKILL...\n", .{});
                _ = c.kill(inst.pid, c.SIGKILL);
            } else {
                try stderr.print("Process still running. Use -f/--force for SIGKILL.\n", .{});
            }
        }
    }

    // Remove from registry
    reg.unregister(opts.name.?);
    try stdout.print("Instance '{s}' stopped and unregistered.\n", .{opts.name.?});

    return 0;
}

/// Handle 'clean' command
fn cmdClean(io: std.Io, allocator: std.mem.Allocator) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    // Check for root privileges (needed to clean jail directories)
    if (c.geteuid() != 0) {
        try stderr.print("Warning: Running without root. Some cleanup may be limited.\n", .{});
    }

    var reg = registry.Registry.init(io, allocator);

    try stdout.print("Cleaning orphaned instances...\n", .{});

    const cleaned = try reg.cleanOrphaned();

    if (cleaned == 0) {
        try stdout.print("No orphaned instances found.\n", .{});
    } else {
        try stdout.print("Cleaned {d} orphaned instance(s).\n", .{cleaned});
    }

    // Also clean any orphaned instance directories
    if (builtin.os.tag == .freebsd and c.geteuid() == 0) {
        try stdout.print("Checking for orphaned instance directories...\n", .{});

        // Instances that are still running keep their directories
        var instances = try reg.list();
        defer {
            for (instances.items) |*inst| {
                inst.deinit();
            }
            instances.deinit(allocator);
        }

        var dir = std.Io.Dir.openDirAbsolute(io, registry.REGISTRY_DIR, .{ .iterate = true }) catch {
            return 0;
        };
        defer dir.close(io);

        var cleaned_dirs: u32 = 0;
        var iter = dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .directory or !std.mem.startsWith(u8, entry.name, "inst-")) continue;

            var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ registry.REGISTRY_DIR, entry.name }) catch continue;

            // A running instance's jail root is <path>/root
            var in_use = false;
            for (instances.items) |inst| {
                if (inst.state != .running) continue;
                if (inst.jail_path.len > path.len and
                    std.mem.startsWith(u8, inst.jail_path, path) and
                    inst.jail_path[path.len] == '/')
                {
                    in_use = true;
                    break;
                }
            }
            if (in_use) continue;

            if (builtin.os.tag == .freebsd) {
                try stdout.print("Removing orphaned instance directory {s}\n", .{path});
                freebsd.cleanupInstanceDir(path) catch {
                    try stderr.print("Warning: Could not fully remove {s}\n", .{path});
                    continue;
                };
                cleaned_dirs += 1;
            }
        }

        if (cleaned_dirs > 0) {
            try stdout.print("Removed {d} orphaned instance directory(s).\n", .{cleaned_dirs});
        }
    }

    return 0;
}

/// Handle 'check' command
fn cmdCheck(io: std.Io) !u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;

    const sys_caps = syscheck.detect();
    try syscheck.printCheck(sys_caps, stdout);

    // Return non-zero if critical features are missing
    if (!sys_caps.jails_available) {
        return 1;
    }
    return 0;
}

// ============================================================================
// Isolation Implementation
// ============================================================================

/// Read exactly buf.len bytes from fd. False on EOF or error.
fn readFull(fd: c_int, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = c.read(fd, buf[off..].ptr, buf.len - off);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

/// Exit code to propagate for a waited-for child
fn childExitCode(status: c_int) u8 {
    if (c.WIFEXITED(status)) {
        return @intCast(c.WEXITSTATUS(status));
    } else if (c.WIFSIGNALED(status)) {
        return @intCast(128 + c.WTERMSIG(status));
    }
    return 1;
}

/// Run isolation using native Zig implementation
fn runIsolation(io: std.Io, allocator: std.mem.Allocator, capability: *const caps.Capabilities, target_binary: []const u8, args: []const []const u8, instance_name: ?[]const u8, verbose: bool) u8 {
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    // FreeBSD-specific implementation
    if (builtin.os.tag == .freebsd) {
        // Generate instance name if not provided
        var name_buf: [64]u8 = undefined;
        const name = if (instance_name) |n|
            n
        else blk: {
            // Try to derive a meaningful name:
            // 1. Use workspace directory name if available
            // 2. Otherwise use binary basename with common extensions stripped
            var process_name: []const u8 = undefined;

            if (capability.workspace_path) |ws_path| {
                // Extract last component of workspace path
                const trimmed = std.mem.trimEnd(u8, ws_path, "/");
                process_name = if (std.mem.findLast(u8, trimmed, "/")) |idx|
                    trimmed[idx + 1 ..]
                else
                    trimmed;
            } else {
                // Extract binary basename and strip common extensions
                const basename = if (std.mem.findLast(u8, target_binary, "/")) |idx|
                    target_binary[idx + 1 ..]
                else
                    target_binary;

                // Strip common script extensions for cleaner names
                process_name = if (std.mem.endsWith(u8, basename, ".sh"))
                    basename[0 .. basename.len - 3]
                else if (std.mem.endsWith(u8, basename, ".py"))
                    basename[0 .. basename.len - 3]
                else if (std.mem.endsWith(u8, basename, ".rb"))
                    basename[0 .. basename.len - 3]
                else if (std.mem.endsWith(u8, basename, ".pl"))
                    basename[0 .. basename.len - 3]
                else
                    basename;
            }

            // Generate random suffix
            var random_bytes: [4]u8 = undefined;
            io.random(&random_bytes);
            const suffix = std.fmt.bytesToHex(random_bytes, .lower);

            const formatted = std.fmt.bufPrint(&name_buf, "{s}-{s}", .{ process_name, suffix }) catch "isolate-instance";
            break :blk formatted;
        };

        // Create pipe for IPC (to pass jail info to parent for cleanup)
        var pipefd: [2]c_int = undefined;
        if (c.pipe(&pipefd) < 0) {
            stderr.print("Failed to create pipe\n", .{}) catch {};
            return 1;
        }

        const pid = c.fork();
        if (pid < 0) {
            stderr.print("Failed to fork\n", .{}) catch {};
            _ = c.close(pipefd[0]);
            _ = c.close(pipefd[1]);
            return 1;
        }

        if (pid == 0) {
            // Child process
            _ = c.close(pipefd[0]);

            // Create isolation context using native Zig implementation
            freebsd.createIsolation(io, capability, target_binary) catch |err| {
                stderr.print("Failed to create isolation context: {}\n", .{err}) catch {};
                _ = c.close(pipefd[1]);
                c._exit(1);
            };

            // Send jail info to parent for cleanup
            const jid = freebsd.freebsd_get_jail_id();
            var username: [64]u8 = undefined;
            const username_ptr = freebsd.freebsd_get_username();
            @memcpy(&username, @as([*]const u8, @ptrCast(username_ptr))[0..64]);

            var jailpath: [freebsd.PATH_MAX]u8 = undefined;
            const path_ptr = freebsd.freebsd_get_jail_path();
            @memcpy(&jailpath, @as([*]const u8, @ptrCast(path_ptr))[0..freebsd.PATH_MAX]);

            _ = c.write(pipefd[1], &jid, @sizeOf(c_int));
            _ = c.write(pipefd[1], &username, 64);
            _ = c.write(pipefd[1], &jailpath, freebsd.PATH_MAX);
            _ = c.close(pipefd[1]);

            if (verbose) {
                stdout.print("Isolation context created successfully.\n", .{}) catch {};
                stdout.print("Executing target binary...\n\n", .{}) catch {};
            }

            // Execute target binary
            const binary_name = if (std.mem.findLast(u8, target_binary, "/")) |idx|
                target_binary[idx + 1 ..]
            else
                target_binary;

            // Build the path inside the jail - binary is copied to jail root
            var exec_path_buf: [256]u8 = undefined;
            const exec_path = std.fmt.bufPrint(&exec_path_buf, "/{s}", .{binary_name}) catch {
                stderr.print("Binary name too long\n", .{}) catch {};
                c._exit(1);
                unreachable;
            };
            exec_path_buf[exec_path.len] = 0; // Null terminate

            // Build argv for execv
            var argv_buf: [64]?[*:0]const u8 = [_]?[*:0]const u8{null} ** 64;
            argv_buf[0] = @ptrCast(binary_name.ptr);

            var argc: usize = 1;
            for (args) |arg| {
                if (argc >= argv_buf.len - 1) break;
                argv_buf[argc] = @ptrCast(arg.ptr);
                argc += 1;
            }

            _ = c.execv(@ptrCast(&exec_path_buf), @ptrCast(&argv_buf));

            // If we get here, execv failed
            stderr.print("Failed to execute {s}\n", .{target_binary}) catch {};
            c._exit(1);
        } else {
            // Parent process
            _ = c.close(pipefd[1]);

            // Read jail info from child
            var jid: c_int = undefined;
            var username: [64]u8 = undefined;
            var jailpath: [freebsd.PATH_MAX]u8 = undefined;

            const complete = readFull(pipefd[0], std.mem.asBytes(&jid)) and
                readFull(pipefd[0], &username) and
                readFull(pipefd[0], &jailpath);
            _ = c.close(pipefd[0]);

            if (!complete) {
                // The child failed before it finished setting up and has
                // already torn down whatever it created; the variables
                // above hold nothing usable. Just report its exit status.
                var status: c_int = undefined;
                _ = c.waitpid(pid, &status, 0);
                stderr.print("Isolation setup failed; nothing was started\n", .{}) catch {};
                return childExitCode(status);
            }

            // The child NUL-terminates both; make sure of it before span()
            username[username.len - 1] = 0;
            jailpath[jailpath.len - 1] = 0;

            freebsd.freebsd_set_jail_id(jid);
            freebsd.freebsd_set_username(@ptrCast(&username));
            freebsd.freebsd_set_jail_path(@ptrCast(&jailpath));

            // Register instance
            var reg = registry.Registry.init(io, allocator);
            const jailpath_slice = std.mem.sliceTo(&jailpath, 0);
            const username_slice = std.mem.sliceTo(&username, 0);

            var instance = registry.Instance{
                .name = allocator.dupe(u8, name) catch name,
                .pid = pid,
                .jail_id = jid,
                .jail_path = allocator.dupe(u8, jailpath_slice) catch jailpath_slice,
                .username = allocator.dupe(u8, username_slice) catch username_slice,
                .binary_path = allocator.dupe(u8, target_binary) catch target_binary,
                .start_time = std.Io.Timestamp.now(io, .real).toSeconds(),
                .workspace_path = if (capability.workspace_path) |wp| allocator.dupe(u8, wp) catch null else null,
                .allocator = allocator,
            };
            defer instance.deinit();

            reg.register(instance) catch |err| {
                if (verbose) {
                    stderr.print("Warning: Failed to register instance: {}\n", .{err}) catch {};
                }
            };

            if (verbose) {
                stdout.print("Instance '{s}' registered.\n", .{name}) catch {};
            }

            // Wait for child
            var status: c_int = undefined;
            _ = c.waitpid(pid, &status, 0);

            if (verbose) {
                stdout.print("\nChild process exited, performing cleanup...\n", .{}) catch {};
            }

            // Cleanup using native Zig implementation
            freebsd.cleanupIsolation(io);

            // Unregister instance
            reg.unregister(instance.name);

            if (verbose) {
                stdout.print("Cleanup complete.\n", .{}) catch {};
            }

            // Return appropriate exit code
            return childExitCode(status);
        }

        return 0;
    } else {
        // Linux and other platforms - not yet implemented in Zig
        stderr.print("Error: Native Zig isolation not yet implemented for this platform\n", .{}) catch {};
        stderr.print("Use the C version or wait for Phase 4 (Linux support)\n", .{}) catch {};
        return 1;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.gpa;
    const io = init.io;

    // Arguments live in the process arena for the lifetime of the program
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var parsed = parseArgs(allocator, args) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        printUsage(io);
        return 1;
    };
    defer parsed.deinit();

    return switch (parsed.command) {
        .help => {
            printUsage(io);
            return 0;
        },
        .version => {
            printVersion(io);
            return 0;
        },
        .detect => cmdDetect(io, allocator, parsed.detect_opts),
        .run => cmdRun(io, allocator, parsed.run_opts),
        .list => cmdList(io, allocator),
        .stop => cmdStop(io, allocator, parsed.stop_opts),
        .clean => cmdClean(io, allocator),
        .check => cmdCheck(io),
    };
}

// Export main for use as library entry point
pub const std_options = std.Options{
    .log_level = .info,
};

// Tests
test {
    // Pull in the tests of every module so `zig build test` runs them all
    _ = c_api;
    _ = caps;
    _ = detect;
    _ = registry;
    if (builtin.os.tag == .freebsd) {
        _ = syscheck;
        _ = freebsd;
    }
}

test "parse args - help" {
    // Basic test that parsing infrastructure works
    // Full argument parsing tests would go here
}

test "version string" {
    try std.testing.expect(version.len > 0);
}
