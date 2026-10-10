//! isolate - a sandbox launcher for FreeBSD
//!
//! This is the main entry point for the isolate tool. It provides process
//! isolation using FreeBSD jails.
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
const netrules = @import("netrules.zig");
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
/// buffer across fork()/execv()/_exit() in the isolation path. Streaming
/// (write(2), not pwrite(2)): a positional writer keeps its own offset, so
/// with output redirected to a file every writer - and the jailed program
/// sharing the descriptor - would overwrite the others from offset 0.
fn stdoutWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stdout().writerStreaming(io, &.{});
}

/// Unbuffered stderr writer.
fn stderrWriter(io: std.Io) std.Io.File.Writer {
    return std.Io.File.stderr().writerStreaming(io, &.{});
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
    /// Write rules for whole library directories instead of the exact files
    dirs: bool = false,
};

/// Stop command options
const StopOptions = struct {
    force: bool = false,
    name: ?[]const u8 = null,
    /// Signal sent to the program to ask it to stop
    signal: StopSignal = .{ .number = c.SIGTERM, .name = "TERM" },
    /// How long to wait for the program to exit after signalling it
    timeout_seconds: u32 = 5,
};

/// A signal `isolate stop` can send, by number and by the name it is reported with
const StopSignal = struct {
    number: c_int,
    name: []const u8,

    const known = [_]StopSignal{
        .{ .number = c.SIGTERM, .name = "TERM" },
        .{ .number = c.SIGINT, .name = "INT" },
        .{ .number = c.SIGQUIT, .name = "QUIT" },
        .{ .number = c.SIGHUP, .name = "HUP" },
        .{ .number = c.SIGUSR1, .name = "USR1" },
        .{ .number = c.SIGUSR2, .name = "USR2" },
        .{ .number = c.SIGKILL, .name = "KILL" },
    };

    /// "INT", "SIGINT", "int" or the signal's number; null for anything else
    fn parse(text: []const u8) ?StopSignal {
        var name = text;
        if (name.len > 3 and std.ascii.eqlIgnoreCase(name[0..3], "SIG")) name = name[3..];
        for (known) |sig| {
            if (std.ascii.eqlIgnoreCase(name, sig.name)) return sig;
        }
        const number = std.fmt.parseInt(c_int, text, 10) catch return null;
        for (known) |sig| {
            if (sig.number == number) return sig;
        }
        return null;
    }
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

/// Parse run command arguments. Options are only recognized before the
/// target binary; everything after it belongs to the binary, so
/// `isolate run -v ./app -v --port 80` passes `-v --port 80` to the app.
/// A `--` ends option parsing explicitly.
fn parseRunArgs(opts: *RunOptions, args: []const [:0]const u8, allocator: std.mem.Allocator) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            break;
        }
        if (!std.mem.startsWith(u8, arg, "-")) break;

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
    }

    // The first remaining argument is the target binary, the rest are its
    // arguments, whatever they look like
    if (i < args.len) {
        opts.target_binary = args[i];
        const rest = args[i + 1 ..];
        if (rest.len > 0) {
            const binary_args = try allocator.alloc([]const u8, rest.len);
            for (rest, binary_args) |src, *dst| dst.* = src;
            opts.binary_args = binary_args;
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
            } else if (std.mem.eql(u8, arg, "--dirs")) {
                opts.dirs = true;
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
            } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--signal")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.signal = StopSignal.parse(args[i]) orelse {
                    std.debug.print("Unknown signal: {s} (use TERM, INT, QUIT, HUP, USR1, USR2 or KILL)\n", .{args[i]});
                    return error.UnknownOption;
                };
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--timeout")) {
                i += 1;
                if (i >= args.len) return error.MissingArgument;
                opts.timeout_seconds = std.fmt.parseInt(u32, args[i], 10) catch {
                    std.debug.print("Invalid timeout: {s} (seconds)\n", .{args[i]});
                    return error.UnknownOption;
                };
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
        \\isolate - run a program in a jail that contains only what you list
        \\
        \\Usage: isolate <command> [options] [arguments]
        \\
        \\Commands:
        \\  run      Run a binary in isolation (default)
        \\  detect   List the libraries a program needs, as a capability file
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
        \\The shared libraries the binary is linked against are listed file by
        \\file, so the jail holds exactly those and nothing else.
        \\
        \\Options:
        \\  -o, --output <file>    Output capability file (default: <binary>.caps)
        \\  --dirs                 Mount whole library directories instead
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
    detect.detectCapabilities(io, allocator, opts.target_binary.?, opts.output_file, opts.dirs) catch |err| {
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

    if (opts.name) |name| {
        if (!registry.isValidInstanceName(name)) {
            try stderr.print("Error: Invalid instance name '{s}'\n", .{name});
            try stderr.print("Use letters, digits, '.', '_' and '-' (not starting with '.'), at most 64 characters.\n", .{});
            return 1;
        }
    }

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
        // Only a file that does not exist falls back to the defaults. One
        // that exists but cannot be read or parsed stops the run: its
        // author meant something, and the defaults are not it.
        if (err != caps.ParseError.FileNotFound) {
            try stderr.print("Error: Could not read capability file {s}: {}\n", .{ caps_file, err });
            return 1;
        }
        try stderr.print("Warning: No capability file at {s}\n", .{caps_file});
        try stderr.print("Running with default capabilities: ephemeral user, inherited network, no filesystem rules.\n", .{});
        try stderr.print("Nothing (not even /lib or /libexec) is mounted in the jail, so dynamically linked binaries will not start.\n", .{});
        try stderr.print("Run 'isolate detect {s}' to generate a capability file.\n\n", .{target_binary});
        // Use default capabilities
        parse_result = .{
            .caps = caps.Capabilities.init(allocator),
            .problems = .empty,
        };
    }
    defer parse_result.deinit();

    // A capability file with a line isolate cannot apply as written is
    // refused outright: running with part of a policy is worse than not
    // running.
    if (parse_result.problems.items.len > 0) {
        for (parse_result.problems.items) |problem| {
            try stderr.print("{s}:{d}: {s}\n", .{ caps_file, problem.line, problem.message });
        }
        try stderr.print("Error: {d} problem(s) in {s}; not starting.\n", .{ parse_result.problems.items.len, caps_file });
        return 1;
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

    // Network rules are enforced or the run is refused; they are never
    // quietly ignored. This is checked after the command-line overrides,
    // since --vnet can supply the interface.
    if (netrules.unenforceable(&parse_result.caps)) |reason| {
        try stderr.print("Error: {s}: {s}\n", .{ caps_file, reason });
        return 1;
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
        const binary_path = if (inst.binary_path.len > binary_display.len) blk: {
            // "..." followed by the tail of the path
            const tail_len = binary_display.len - 3;
            @memcpy(binary_display[0..3], "...");
            @memcpy(binary_display[3..], inst.binary_path[inst.binary_path.len - tail_len ..]);
            break :blk binary_display[0..];
        } else inst.binary_path;

        // Format the numbers first: a width on {d} prints a leading '+'
        var pid_buf: [12]u8 = undefined;
        var jid_buf: [12]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{inst.pid}) catch "?";
        const jid_str = std.fmt.bufPrint(&jid_buf, "{d}", .{inst.jail_id}) catch "?";

        try stdout.print("{s:<20} {s:<8} {s:<8} {s:<10} {s}\n", .{
            inst.name,
            pid_str,
            jid_str,
            state_str,
            binary_path,
        });
    }

    return 0;
}

/// Handle 'stop' command
fn cmdStop(io: std.Io, allocator: std.mem.Allocator, opts: StopOptions) !u8 {
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    if (opts.name == null) {
        try stderr.print("Error: No instance name specified\n", .{});
        try stderr.print("Usage: isolate stop [-f] [-s signal] [-t seconds] <name>\n", .{});
        try stderr.print("Run 'isolate list' to see running instances.\n", .{});
        return 1;
    }

    // Check for root privileges
    if (c.geteuid() != 0) {
        try stderr.print("Error: Stopping instances requires root privileges\n", .{});
        try stderr.print("Run with: doas isolate stop {s}\n", .{opts.name.?});
        return 1;
    }

    if (builtin.os.tag != .freebsd) {
        try stderr.print("Error: Stopping instances is only supported on FreeBSD\n", .{});
        return 1;
    } else {
        return stopInstance(io, allocator, opts);
    }
}

/// Stop a registered instance. Cleans up after it only if the isolate
/// process that started it is no longer around to do so itself.
fn stopInstance(io: std.Io, allocator: std.mem.Allocator, opts: StopOptions) !u8 {
    const name = opts.name.?;
    const force = opts.force;
    var stdout_file = stdoutWriter(io);
    const stdout = &stdout_file.interface;
    var stderr_file = stderrWriter(io);
    const stderr = &stderr_file.interface;

    var reg = registry.Registry.init(io, allocator);

    const inst_opt = try reg.get(name);
    if (inst_opt == null) {
        try stderr.print("Error: Instance '{s}' not found\n", .{name});
        return 1;
    }

    var inst = inst_opt.?;
    defer inst.deinit();

    if (inst.state != .running and !force) {
        try stderr.print("Instance '{s}' is not running (state: {s})\n", .{ name, @tagName(inst.state) });
        try stderr.print("Use -f/--force to clean up anyway.\n", .{});
        return 1;
    }

    try stdout.print("Stopping instance '{s}'...\n", .{name});

    // Signal the jailed process only while its jail still exists: once
    // the jail is gone, the PID may already belong to another process
    if (inst.state == .running and freebsd.jailBelongsTo(inst.jail_id, inst.pid)) {
        if (c.kill(inst.pid, opts.signal.number) < 0) {
            try stderr.print("Warning: Failed to send SIG{s} to PID {d}\n", .{ opts.signal.name, inst.pid });
        } else {
            try stdout.print("Sent SIG{s} to PID {d}, waiting up to {d} seconds for it to exit...\n", .{ opts.signal.name, inst.pid, opts.timeout_seconds });
            var waited: u64 = 0;
            const ticks = @as(u64, opts.timeout_seconds) * 10;
            while (waited < ticks and c.kill(inst.pid, 0) == 0) : (waited += 1) {
                io.sleep(.fromMilliseconds(100), .awake) catch {};
            }
        }

        if (c.kill(inst.pid, 0) == 0) {
            if (!force) {
                try stderr.print("Process {d} is still running after {d} seconds.\n", .{ inst.pid, opts.timeout_seconds });
                try stderr.print("Use -f/--force to remove the jail, which kills everything inside it.\n", .{});
                return 1;
            }
            try stdout.print("Process still running, removing jail JID {d}...\n", .{inst.jail_id});
            freebsd.removeJail(inst.jail_id);
        }
    }

    // The isolate process that started the instance cleans up and
    // unregisters it when its child exits; only do that here if it is gone
    if (inst.manager_pid > 0 and c.kill(inst.manager_pid, 0) == 0) {
        try stdout.print("Instance '{s}' stopped; its isolate process (PID {d}) is cleaning up.\n", .{ name, inst.manager_pid });
        return 0;
    }

    freebsd.teardownInstance(io, inst.pid, inst.jail_id, inst.jail_path, inst.username);
    reg.unregister(name);
    try stdout.print("Instance '{s}' stopped and unregistered.\n", .{name});

    return 0;
}

/// Clean up every registered instance whose isolate process has died:
/// remove its jail (and whatever still runs in it), its directory and its
/// ephemeral user, then unregister it. Returns the number cleaned.
fn cleanOrphans(io: std.Io, allocator: std.mem.Allocator, reg: *registry.Registry) !u32 {
    if (builtin.os.tag != .freebsd) {
        // Without jail support there is only the registry entry to drop
        return reg.cleanOrphaned();
    } else {
        var stdout_file = stdoutWriter(io);
        const stdout = &stdout_file.interface;

        var instances = try reg.list();
        defer {
            for (instances.items) |*inst| {
                inst.deinit();
            }
            instances.deinit(allocator);
        }

        var cleaned: u32 = 0;
        for (instances.items) |inst| {
            // Still managed: its isolate process will clean up itself
            if (inst.manager_pid > 0 and c.kill(inst.manager_pid, 0) == 0) continue;

            try stdout.print("Instance '{s}' is orphaned (state: {s}, isolate process gone)\n", .{ inst.name, @tagName(inst.state) });
            freebsd.teardownInstance(io, inst.pid, inst.jail_id, inst.jail_path, inst.username);
            reg.unregister(inst.name);
            cleaned += 1;
        }
        return cleaned;
    }
}

/// `clean` leaves an instance directory alone for this long after its last
/// modification: a run creates the directory a moment before its jail.
const instance_dir_grace_seconds = 60;

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

    const cleaned = if (c.geteuid() == 0)
        try cleanOrphans(io, allocator, &reg)
    else
        try reg.cleanOrphaned();

    if (cleaned == 0) {
        try stdout.print("No orphaned instances found.\n", .{});
    } else {
        try stdout.print("Cleaned {d} orphaned instance(s).\n", .{cleaned});
    }

    // Then whatever isolate left behind that no registry entry accounts
    // for: see docs/design/03-lifecycle.md, LIF-2
    if (builtin.os.tag == .freebsd and c.geteuid() == 0) {
        // The entries that remain belong to instances whose isolate process
        // is alive. Their jails, users and directories are in use.
        var instances = try reg.list();
        defer {
            for (instances.items) |*inst| {
                inst.deinit();
            }
            instances.deinit(allocator);
        }

        var managed_jids: std.ArrayList(i32) = .empty;
        defer managed_jids.deinit(allocator);
        var managed_users: std.ArrayList([]const u8) = .empty;
        defer managed_users.deinit(allocator);
        for (instances.items) |inst| {
            try managed_jids.append(allocator, inst.jail_id);
            try managed_users.append(allocator, inst.username);
        }

        const stray_jails = freebsd.removeStrayJails(io, managed_jids.items);
        if (stray_jails > 0) {
            try stdout.print("Removed {d} unregistered jail(s).\n", .{stray_jails});
        }

        const purged = freebsd.purgeStaleLimits();
        if (purged > 0) {
            try stdout.print("Removed resource limits of {d} jail(s) that no longer exist.\n", .{purged});
        }

        const purged_anchors = freebsd.purgeStaleNetworkRules();
        if (purged_anchors > 0) {
            try stdout.print("Removed network rules of {d} jail(s) that no longer exist.\n", .{purged_anchors});
        }

        try stdout.print("Checking for orphaned instance directories...\n", .{});

        var cleaned_dirs: u32 = 0;
        if (std.Io.Dir.openDirAbsolute(io, registry.REGISTRY_DIR, .{ .iterate = true })) |opened| {
            var dir = opened;
            defer dir.close(io);

            var iter = dir.iterate();
            while (try iter.next(io)) |entry| {
                if (entry.kind != .directory or !std.mem.startsWith(u8, entry.name, "inst-")) continue;

                var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
                const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ registry.REGISTRY_DIR, entry.name }) catch continue;

                // In use: some jail has its root here, or a run created the
                // directory moments ago and has not created its jail yet
                if (freebsd.instanceDirHasJail(path)) continue;
                if ((freebsd.pathAgeSeconds(path) orelse 0) < instance_dir_grace_seconds) continue;

                try stdout.print("Removing orphaned instance directory {s}\n", .{path});
                freebsd.cleanupInstanceDir(path) catch {
                    try stderr.print("Warning: Could not fully remove {s}\n", .{path});
                    continue;
                };
                cleaned_dirs += 1;
            }
        } else |_| {}

        if (cleaned_dirs > 0) {
            try stdout.print("Removed {d} orphaned instance directory(s).\n", .{cleaned_dirs});
        }

        const stray_users = freebsd.removeStrayUsers(io, allocator, managed_users.items);
        if (stray_users > 0) {
            try stdout.print("Removed {d} unused ephemeral user(s).\n", .{stray_users});
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

    if (builtin.os.tag == .freebsd) {
        try stdout.print("Network rules (pf):\n", .{});
        switch (freebsd.pfState()) {
            .ready => try stdout.print("  [OK] pf                   Enabled, with isolate's anchor - network rules can be enforced\n", .{}),
            .unavailable => try stdout.print("  [!!] pf                   Not available, or not running as root - files with network rules will be refused\n", .{}),
            .disabled => try stdout.print("  [!!] pf                   Not enabled - files with network rules will be refused\n", .{}),
            .no_anchor => try stdout.print("  [!!] pf                   Enabled, but pf.conf lacks:  {s}\n", .{netrules.anchor_line}),
        }
        try stdout.print("\n", .{});
    }

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

// The jailed child's PID and the number of termination signals the parent
// has received so far, for forwardSignal()
var child_pid: c.pid_t = 0;
var signals_received: u32 = 0;

/// SIGINT/SIGTERM/SIGHUP in the parent: pass the first one on to the child
/// so it can shut down; on the second, kill it. The parent itself keeps
/// waiting, and once the child is gone its normal cleanup removes the jail
/// (and with it anything else still running inside), the mounts, the
/// directory and the user - instead of all that being left behind when the
/// parent dies first. Only kill(2) is called here; removing the jail
/// involves running other programs, which is not for a signal handler.
fn forwardSignal(sig: c_int) callconv(.c) void {
    signals_received += 1;
    if (child_pid <= 0) return;
    _ = c.kill(child_pid, if (signals_received >= 2) c.SIGKILL else sig);
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

            // Keep the name valid for the registry: replace anything outside
            // the allowed character set and leave room for the suffix
            var base_buf: [64 - 9]u8 = undefined;
            const base_len = @min(process_name.len, base_buf.len);
            for (process_name[0..base_len], 0..) |ch, i| {
                base_buf[i] = switch (ch) {
                    'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => ch,
                    else => '-',
                };
            }
            var base: []const u8 = base_buf[0..base_len];
            if (base.len == 0 or base[0] == '.') base = "app";

            const formatted = std.fmt.bufPrint(&name_buf, "{s}-{s}", .{ base, suffix }) catch "isolate-instance";
            break :blk formatted;
        };

        // The program runs from the absolute path it has on the host
        var program_buf: [c_api.PATH_MAX]u8 = undefined;
        if (c.realpath(@ptrCast(target_binary.ptr), &program_buf) == null) {
            stderr.print("Error: {s} not found\n", .{target_binary}) catch {};
            return 1;
        }
        const program_path: [:0]const u8 = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&program_buf)), 0);

        // Instance names are unique. Refuse before anything is created.
        {
            var reg = registry.Registry.init(io, allocator);
            if (reg.exists(name)) {
                stderr.print("Error: An instance named '{s}' is already registered.\n", .{name}) catch {};
                stderr.print("See 'isolate list'. If it is not running, 'isolate clean' removes it.\n", .{}) catch {};
                return 1;
            }
        }

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
            freebsd.createIsolation(io, capability, program_path) catch |err| {
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

            // Build argv for execv: the program's path, then every argument
            // given on the command line, however many there are. Each is a
            // slice of a NUL-terminated command-line string.
            const argv = allocator.alloc(?[*:0]const u8, args.len + 2) catch {
                stderr.print("Out of memory\n", .{}) catch {};
                c._exit(1);
            };
            argv[0] = program_path.ptr;
            for (args, 1..) |arg, i| argv[i] = @ptrCast(arg.ptr);
            argv[args.len + 1] = null;

            // The program gets stdin, stdout and stderr and nothing else
            // that happened to be open in this process
            c.closefrom(3);

            // The program is in the jail at the path it has on the host
            _ = c.execv(program_path.ptr, @ptrCast(argv.ptr));

            // If we get here, execv failed
            const reason = std.mem.span(c.strerror(std.c._errno().*));
            stderr.print("Failed to execute {s}: {s}\n", .{ program_path, reason }) catch {};
            c._exit(1);
        } else {
            // Parent process
            _ = c.close(pipefd[1]);

            // From here on, termination signals go to the child first and
            // the jail second; the parent stays alive to clean up
            child_pid = pid;
            _ = c.signal(c.SIGINT, &forwardSignal);
            _ = c.signal(c.SIGTERM, &forwardSignal);
            _ = c.signal(c.SIGHUP, &forwardSignal);

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
                .manager_pid = c.getpid(),
                .jail_id = jid,
                .jail_path = allocator.dupe(u8, jailpath_slice) catch jailpath_slice,
                .username = allocator.dupe(u8, username_slice) catch username_slice,
                .binary_path = allocator.dupe(u8, target_binary) catch target_binary,
                .start_time = std.Io.Timestamp.now(io, .real).toSeconds(),
                .workspace_path = if (capability.workspace_path) |wp| allocator.dupe(u8, wp) catch null else null,
                .allocator = allocator,
            };
            defer instance.deinit();

            // An instance that cannot be registered cannot be listed,
            // stopped or cleaned up after, so it is not left running
            var registered = true;
            reg.register(instance) catch |err| {
                registered = false;
                stderr.print("Error: Could not register instance '{s}': {}. Stopping it.\n", .{ name, err }) catch {};
                freebsd.removeJail(jid);
            };

            if (verbose and registered) {
                stdout.print("Instance '{s}' registered.\n", .{name}) catch {};
            }

            // Wait for child; a forwarded signal may interrupt the wait
            var status: c_int = undefined;
            while (c.waitpid(pid, &status, 0) < 0) {
                if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) break;
            }
            child_pid = 0;

            if (verbose) {
                stdout.print("\nChild process exited, performing cleanup...\n", .{}) catch {};
            }

            // Cleanup using native Zig implementation
            freebsd.cleanupIsolation(io);
            freebsd.removeResourceLimitsForPid(pid);
            freebsd.removeNetworkRulesForPid(pid);

            // Unregister instance (never someone else's entry of the same name)
            if (registered) {
                reg.unregister(instance.name);
            } else {
                return 1;
            }

            if (verbose) {
                stdout.print("Cleanup complete.\n", .{}) catch {};
            }

            // Return appropriate exit code
            return childExitCode(status);
        }

        return 0;
    } else {
        // Only FreeBSD is supported
        stderr.print("Error: isolate can only run programs in isolation on FreeBSD\n", .{}) catch {};
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
    _ = @import("libs.zig");
    _ = netrules;
    _ = registry;
    if (builtin.os.tag == .freebsd) {
        _ = syscheck;
        _ = freebsd;
    }
}

test "parseArgs: no arguments and help" {
    const allocator = std.testing.allocator;
    var none = try parseArgs(allocator, &.{"isolate"});
    defer none.deinit();
    try std.testing.expectEqual(Command.help, none.command);

    var help = try parseArgs(allocator, &.{ "isolate", "--help" });
    defer help.deinit();
    try std.testing.expectEqual(Command.help, help.command);
}

test "parseRunArgs: options before the binary" {
    const allocator = std.testing.allocator;
    var parsed = try parseArgs(allocator, &.{ "isolate", "run", "-v", "-c", "x.caps", "-N", "name", "./app", "a", "b" });
    defer parsed.deinit();
    const opts = parsed.run_opts;
    try std.testing.expectEqual(Command.run, parsed.command);
    try std.testing.expect(opts.verbose);
    try std.testing.expectEqualStrings("x.caps", opts.caps_file.?);
    try std.testing.expectEqualStrings("name", opts.name.?);
    try std.testing.expectEqualStrings("./app", opts.target_binary.?);
    try std.testing.expectEqual(@as(usize, 2), opts.binary_args.len);
    try std.testing.expectEqualStrings("b", opts.binary_args[1]);
}

test "parseRunArgs: options after the binary belong to the binary" {
    const allocator = std.testing.allocator;
    var parsed = try parseArgs(allocator, &.{ "isolate", "run", "./app", "-v", "--port", "80", "-n", "-c", "other" });
    defer parsed.deinit();
    const opts = parsed.run_opts;
    try std.testing.expect(!opts.verbose);
    try std.testing.expect(!opts.dry_run);
    try std.testing.expect(opts.caps_file == null);
    try std.testing.expectEqualStrings("./app", opts.target_binary.?);
    try std.testing.expectEqual(@as(usize, 6), opts.binary_args.len);
    try std.testing.expectEqualStrings("-v", opts.binary_args[0]);
    try std.testing.expectEqualStrings("other", opts.binary_args[5]);
}

test "parseRunArgs: -- ends options" {
    const allocator = std.testing.allocator;
    var parsed = try parseArgs(allocator, &.{ "isolate", "run", "-n", "--", "-odd-name", "-x" });
    defer parsed.deinit();
    const opts = parsed.run_opts;
    try std.testing.expect(opts.dry_run);
    try std.testing.expectEqualStrings("-odd-name", opts.target_binary.?);
    try std.testing.expectEqual(@as(usize, 1), opts.binary_args.len);
    try std.testing.expectEqualStrings("-x", opts.binary_args[0]);
}

test "parseStopArgs: signal and timeout" {
    const allocator = std.testing.allocator;

    var plain = try parseArgs(allocator, &.{ "isolate", "stop", "pg" });
    defer plain.deinit();
    try std.testing.expectEqualStrings("pg", plain.stop_opts.name.?);
    try std.testing.expectEqual(@as(c_int, c.SIGTERM), plain.stop_opts.signal.number);
    try std.testing.expectEqual(@as(u32, 5), plain.stop_opts.timeout_seconds);
    try std.testing.expect(!plain.stop_opts.force);

    var fast = try parseArgs(allocator, &.{ "isolate", "stop", "-s", "SIGINT", "--timeout", "60", "-f", "pg" });
    defer fast.deinit();
    try std.testing.expectEqual(@as(c_int, c.SIGINT), fast.stop_opts.signal.number);
    try std.testing.expectEqualStrings("INT", fast.stop_opts.signal.name);
    try std.testing.expectEqual(@as(u32, 60), fast.stop_opts.timeout_seconds);
    try std.testing.expect(fast.stop_opts.force);

    var by_number = try parseArgs(allocator, &.{ "isolate", "stop", "-s", "2", "pg" });
    defer by_number.deinit();
    try std.testing.expectEqual(@as(c_int, c.SIGINT), by_number.stop_opts.signal.number);

    try std.testing.expectError(error.UnknownOption, parseArgs(allocator, &.{ "isolate", "stop", "-s", "NOPE", "pg" }));
    try std.testing.expectError(error.UnknownOption, parseArgs(allocator, &.{ "isolate", "stop", "-t", "soon", "pg" }));
    try std.testing.expectError(error.MissingArgument, parseArgs(allocator, &.{ "isolate", "stop", "-s" }));
}

test "parseRunArgs: errors" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.MissingArgument, parseArgs(allocator, &.{ "isolate", "run", "-c" }));

    var no_binary = try parseArgs(allocator, &.{ "isolate", "run", "-v" });
    defer no_binary.deinit();
    try std.testing.expect(no_binary.run_opts.target_binary == null);
}

test "parseArgs: legacy form without a subcommand" {
    const allocator = std.testing.allocator;
    var parsed = try parseArgs(allocator, &.{ "isolate", "./app", "-x" });
    defer parsed.deinit();
    try std.testing.expectEqual(Command.run, parsed.command);
    try std.testing.expectEqualStrings("./app", parsed.run_opts.target_binary.?);
    try std.testing.expectEqualStrings("-x", parsed.run_opts.binary_args[0]);
}

test "version string" {
    try std.testing.expect(version.len > 0);
}
