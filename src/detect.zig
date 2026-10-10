//! Capability detection module for isolate
//!
//! Analyzes ELF binaries to suggest capability requirements.
//! Uses native ELF parsing instead of shell commands (ldd, nm, strings).
//!
//! Detection phases:
//! 1. Library dependencies - from .dynamic section DT_NEEDED entries
//! 2. Symbol analysis - from .dynsym section
//! 3. String analysis - embedded paths and URLs
//! 4. Pattern matching - based on binary name

const std = @import("std");
const Allocator = std.mem.Allocator;
const elf = std.elf;
const caps = @import("caps.zig");
const libs = @import("libs.zig");

/// Maximum capability hints
pub const MAX_CAPABILITY_HINTS = 64;

/// A capability hint discovered during analysis
pub const CapabilityHint = struct {
    description: []const u8,
    capability: []const u8,
    confidence: u8, // 0-100

    pub fn format(self: CapabilityHint, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("[{d}%] {s}", .{ self.confidence, self.description });
    }
};

/// Result of capability detection
pub const DetectionResult = struct {
    allocator: Allocator,
    hints: std.ArrayList(CapabilityHint),
    binary_name: []const u8,
    /// The program imports dlopen(): it may load libraries at run time
    /// that no static analysis can list
    uses_dlopen: bool = false,

    const Self = @This();

    pub fn init(allocator: Allocator, binary_path: []const u8) Self {
        // Extract basename
        const basename = if (std.mem.findScalarLast(u8, binary_path, '/')) |idx|
            binary_path[idx + 1 ..]
        else
            binary_path;

        return .{
            .allocator = allocator,
            .hints = .empty,
            .binary_name = basename,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.hints.items) |hint| {
            self.allocator.free(hint.description);
            self.allocator.free(hint.capability);
        }
        self.hints.deinit(self.allocator);
    }

    pub fn addHint(self: *Self, description: []const u8, capability: []const u8, confidence: u8) !void {
        if (self.hints.items.len >= MAX_CAPABILITY_HINTS) return;

        try self.hints.append(self.allocator, .{
            .description = try self.allocator.dupe(u8, description),
            .capability = try self.allocator.dupe(u8, capability),
            .confidence = confidence,
        });
    }

    /// Sort hints by confidence (descending)
    pub fn sortByConfidence(self: *Self) void {
        std.mem.sort(CapabilityHint, self.hints.items, {}, struct {
            fn lessThan(_: void, a: CapabilityHint, b: CapabilityHint) bool {
                return a.confidence > b.confidence;
            }
        }.lessThan);
    }
};

/// Known library patterns and their capability implications
const LibraryPattern = struct {
    pattern: []const u8,
    description: []const u8,
    capability: []const u8,
    confidence: u8,
};

const library_patterns = [_]LibraryPattern{
    .{ .pattern = "libssl", .description = "SSL/TLS library - likely needs network access", .capability = "network: tcp:443:outbound\nnetwork: tcp:80:outbound", .confidence = 80 },
    .{ .pattern = "libcrypto", .description = "Cryptography library", .capability = "network: tcp:443:outbound", .confidence = 75 },
    .{ .pattern = "libpq", .description = "PostgreSQL library - needs database connection", .capability = "network: tcp:5432:outbound", .confidence = 85 },
    .{ .pattern = "libmysql", .description = "MySQL library - needs database connection", .capability = "network: tcp:3306:outbound", .confidence = 85 },
    .{ .pattern = "libmariadb", .description = "MariaDB library - needs database connection", .capability = "network: tcp:3306:outbound", .confidence = 85 },
    .{ .pattern = "libsqlite", .description = "SQLite library - local database", .capability = "filesystem: /tmp:rw", .confidence = 70 },
    .{ .pattern = "libcurl", .description = "HTTP client library", .capability = "network: tcp:80:outbound\nnetwork: tcp:443:outbound", .confidence = 85 },
    .{ .pattern = "libX11", .description = "X11 library - needs display access", .capability = "filesystem: /tmp/.X11-unix:rw\nenv: DISPLAY=/tmp/.X11-unix/X0", .confidence = 90 },
    .{ .pattern = "libgtk", .description = "GTK library - needs display access", .capability = "filesystem: /tmp/.X11-unix:rw\nenv: DISPLAY=/tmp/.X11-unix/X0", .confidence = 90 },
    .{ .pattern = "libQt", .description = "Qt library - needs display access", .capability = "filesystem: /tmp/.X11-unix:rw\nenv: DISPLAY=/tmp/.X11-unix/X0", .confidence = 90 },
    .{ .pattern = "libz.so", .description = "Compression library", .capability = "", .confidence = 50 },
    .{ .pattern = "libpthread", .description = "Threading library", .capability = "processes: 10", .confidence = 60 },
    .{ .pattern = "librt.so", .description = "Realtime library", .capability = "", .confidence = 50 },
    .{ .pattern = "libdl.so", .description = "Dynamic loading library", .capability = "", .confidence = 50 },
};

/// Known application name patterns
const AppPattern = struct {
    pattern: []const u8,
    description: []const u8,
    capability: []const u8,
    confidence: u8,
};

const app_patterns = [_]AppPattern{
    .{ .pattern = "httpd", .description = "Web server detected", .capability = "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 256M", .confidence = 90 },
    .{ .pattern = "nginx", .description = "Nginx web server", .capability = "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 128M", .confidence = 90 },
    .{ .pattern = "apache", .description = "Apache web server", .capability = "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 256M", .confidence = 90 },
    .{ .pattern = "sshd", .description = "SSH server", .capability = "network: tcp:22:inbound\nfilesystem: /etc/ssh:r\nprocesses: 20", .confidence = 95 },
    .{ .pattern = "mysqld", .description = "MySQL database server", .capability = "network: tcp:3306:inbound\nfilesystem: /var/lib/mysql:rw\nmemory: 512M\nprocesses: 50", .confidence = 90 },
    .{ .pattern = "postgres", .description = "PostgreSQL database", .capability = "network: tcp:5432:inbound\nfilesystem: /var/lib/postgresql:rw\nmemory: 256M\nprocesses: 20", .confidence = 90 },
    .{ .pattern = "redis", .description = "Redis server", .capability = "network: tcp:6379:inbound\nfilesystem: /var/lib/redis:rw\nmemory: 128M", .confidence = 90 },
    .{ .pattern = "mongod", .description = "MongoDB server", .capability = "network: tcp:27017:inbound\nfilesystem: /var/lib/mongodb:rw\nmemory: 256M", .confidence = 90 },
    .{ .pattern = "server", .description = "Generic server application", .capability = "network: tcp:8080:inbound\nmemory: 128M", .confidence = 60 },
    .{ .pattern = "client", .description = "Generic client application", .capability = "network: tcp:80:outbound\nnetwork: tcp:443:outbound", .confidence = 60 },
    .{ .pattern = "daemon", .description = "System daemon", .capability = "processes: 5\nfilesystem: /var/run:rw\nfilesystem: /var/log:rw", .confidence = 70 },
    .{ .pattern = "bot", .description = "Bot application", .capability = "network: tcp:443:outbound\nfilesystem: /tmp:rw\nmemory: 64M", .confidence = 65 },
};

/// Errors that can occur during detection
pub const DetectError = error{
    FileNotFound,
    NotAnElf,
    InvalidElf,
    IoError,
    OutOfMemory,
    AccessDenied,
};

/// ELF analyzer for native binary analysis
pub const ElfAnalyzer = struct {
    io: std.Io,
    allocator: Allocator,
    file: std.Io.File,
    header: elf.Elf64_Ehdr,
    section_headers: []elf.Elf64_Shdr,
    shstrtab: []const u8,

    const Self = @This();

    pub fn init(io: std.Io, allocator: Allocator, path: []const u8) DetectError!Self {
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
            return switch (err) {
                error.FileNotFound => DetectError.FileNotFound,
                error.AccessDenied => DetectError.AccessDenied,
                else => DetectError.IoError,
            };
        };
        errdefer file.close(io);

        // Read ELF header
        var header: elf.Elf64_Ehdr = undefined;
        const bytes_read = file.readPositionalAll(io, std.mem.asBytes(&header), 0) catch {
            return DetectError.IoError;
        };

        if (bytes_read < @sizeOf(elf.Elf64_Ehdr)) {
            return DetectError.InvalidElf;
        }

        // Verify ELF magic
        if (!std.mem.eql(u8, header.e_ident[0..4], "\x7fELF")) {
            return DetectError.NotAnElf;
        }

        // Read section headers
        const sh_size = @as(usize, header.e_shnum) * @sizeOf(elf.Elf64_Shdr);
        const section_headers = allocator.alloc(elf.Elf64_Shdr, header.e_shnum) catch {
            return DetectError.OutOfMemory;
        };
        errdefer allocator.free(section_headers);

        const sh_bytes = std.mem.sliceAsBytes(section_headers);
        const sh_read = file.readPositionalAll(io, sh_bytes, header.e_shoff) catch return DetectError.IoError;
        if (sh_read < sh_size) {
            return DetectError.InvalidElf;
        }

        // Read section header string table
        if (header.e_shstrndx >= header.e_shnum) {
            return DetectError.InvalidElf;
        }
        const shstrtab_hdr = section_headers[header.e_shstrndx];
        const shstrtab = allocator.alloc(u8, shstrtab_hdr.sh_size) catch {
            return DetectError.OutOfMemory;
        };
        errdefer allocator.free(shstrtab);

        const strtab_read = file.readPositionalAll(io, shstrtab, shstrtab_hdr.sh_offset) catch return DetectError.IoError;
        if (strtab_read < shstrtab_hdr.sh_size) {
            return DetectError.InvalidElf;
        }

        return Self{
            .io = io,
            .allocator = allocator,
            .file = file,
            .header = header,
            .section_headers = section_headers,
            .shstrtab = shstrtab,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.shstrtab);
        self.allocator.free(self.section_headers);
        self.file.close(self.io);
    }

    /// Find a section by name
    fn findSection(self: *const Self, name: []const u8) ?*const elf.Elf64_Shdr {
        for (self.section_headers) |*shdr| {
            if (shdr.sh_name >= self.shstrtab.len) continue;
            const section_name = std.mem.sliceTo(self.shstrtab[shdr.sh_name..], 0);
            if (std.mem.eql(u8, section_name, name)) {
                return shdr;
            }
        }
        return null;
    }

    /// Get linked libraries from .dynamic section (DT_NEEDED entries)
    pub fn getNeededLibraries(self: *Self, result: *std.ArrayList([]const u8)) !void {
        return self.getDynamicStrings(elf.DT_NEEDED, result);
    }

    /// The program interpreter named in the .interp section, e.g.
    /// /libexec/ld-elf.so.1. Null for a statically linked program. Caller
    /// owns the result.
    pub fn getInterpreter(self: *Self) !?[]const u8 {
        const shdr = self.findSection(".interp") orelse return null;
        if (shdr.sh_size == 0 or shdr.sh_size > 4096) return null;

        const data = try self.allocator.alloc(u8, shdr.sh_size);
        defer self.allocator.free(data);
        const n = self.file.readPositionalAll(self.io, data, shdr.sh_offset) catch return null;

        const path = std.mem.sliceTo(data[0..n], 0);
        if (path.len == 0) return null;
        return try self.allocator.dupe(u8, path);
    }

    /// Append the string value of every .dynamic entry with the given tag:
    /// DT_NEEDED (library names), DT_RPATH or DT_RUNPATH (search paths).
    /// The strings are owned by the caller.
    pub fn getDynamicStrings(self: *Self, tag: i64, result: *std.ArrayList([]const u8)) !void {
        // Find .dynamic section
        const dynamic_shdr = self.findSection(".dynamic") orelse return;

        // Find .dynstr section for library names
        const dynstr_shdr = self.findSection(".dynstr") orelse return;

        // Read .dynstr
        const dynstr = try self.allocator.alloc(u8, dynstr_shdr.sh_size);
        defer self.allocator.free(dynstr);

        _ = self.file.readPositionalAll(self.io, dynstr, dynstr_shdr.sh_offset) catch return;

        // Read .dynamic entries
        const entry_size = @sizeOf(elf.Elf64_Dyn);
        const num_entries = dynamic_shdr.sh_size / entry_size;

        var i: usize = 0;
        while (i < num_entries) : (i += 1) {
            var dyn: elf.Elf64_Dyn = undefined;
            const offset = dynamic_shdr.sh_offset + i * entry_size;
            const bytes = self.file.readPositionalAll(self.io, std.mem.asBytes(&dyn), offset) catch break;
            if (bytes < entry_size) break;

            if (dyn.d_tag == tag) {
                const name_offset = dyn.d_val;
                if (name_offset < dynstr.len) {
                    const lib_name = std.mem.sliceTo(dynstr[name_offset..], 0);
                    if (lib_name.len > 0) {
                        try result.append(self.allocator, try self.allocator.dupe(u8, lib_name));
                    }
                }
            } else if (dyn.d_tag == elf.DT_NULL) {
                break;
            }
        }
    }

    /// Get dynamic symbols from .dynsym section
    pub fn getDynamicSymbols(self: *Self, result: *std.ArrayList([]const u8)) !void {
        // Find .dynsym section
        const dynsym_shdr = self.findSection(".dynsym") orelse return;

        // Find .dynstr section for symbol names
        const dynstr_shdr = self.findSection(".dynstr") orelse return;

        // Read .dynstr
        const dynstr = try self.allocator.alloc(u8, dynstr_shdr.sh_size);
        defer self.allocator.free(dynstr);

        _ = self.file.readPositionalAll(self.io, dynstr, dynstr_shdr.sh_offset) catch return;

        // Read symbols
        const sym_size = @sizeOf(elf.Elf64_Sym);
        const num_syms = dynsym_shdr.sh_size / sym_size;

        var i: usize = 0;
        while (i < num_syms) : (i += 1) {
            var sym: elf.Elf64_Sym = undefined;
            const offset = dynsym_shdr.sh_offset + i * sym_size;
            const bytes = self.file.readPositionalAll(self.io, std.mem.asBytes(&sym), offset) catch break;
            if (bytes < sym_size) break;

            if (sym.st_name > 0 and sym.st_name < dynstr.len) {
                const sym_name = std.mem.sliceTo(dynstr[sym.st_name..], 0);
                if (sym_name.len > 0) {
                    try result.append(self.allocator, try self.allocator.dupe(u8, sym_name));
                }
            }
        }
    }

    /// Extract printable strings from the binary
    pub fn extractStrings(self: *Self, min_length: usize, result: *std.ArrayList([]const u8)) !void {
        // Read interesting sections for strings
        const sections_to_scan = [_][]const u8{ ".rodata", ".data", ".dynstr" };

        for (sections_to_scan) |section_name| {
            const shdr = self.findSection(section_name) orelse continue;
            if (shdr.sh_size == 0 or shdr.sh_size > 10 * 1024 * 1024) continue; // Skip empty or huge sections

            const data = try self.allocator.alloc(u8, shdr.sh_size);
            defer self.allocator.free(data);

            const bytes_read = self.file.readPositionalAll(self.io, data, shdr.sh_offset) catch continue;
            if (bytes_read < shdr.sh_size) continue;

            // Find printable strings
            var start: ?usize = null;
            for (data, 0..) |byte, idx| {
                const is_printable = (byte >= 0x20 and byte < 0x7f) or byte == '\n' or byte == '\t';
                if (is_printable) {
                    if (start == null) start = idx;
                } else {
                    if (start) |s| {
                        const str = data[s..idx];
                        if (str.len >= min_length) {
                            // Filter for interesting strings (paths, URLs, etc.)
                            if (isInterestingString(str)) {
                                try result.append(self.allocator, try self.allocator.dupe(u8, str));
                            }
                        }
                    }
                    start = null;
                }
            }
        }
    }

    fn isInterestingString(str: []const u8) bool {
        // Check for paths
        if (std.mem.startsWith(u8, str, "/etc/")) return true;
        if (std.mem.startsWith(u8, str, "/var/")) return true;
        if (std.mem.startsWith(u8, str, "/tmp/")) return true;
        if (std.mem.startsWith(u8, str, "/usr/")) return true;
        if (std.mem.startsWith(u8, str, "/home/")) return true;

        // Check for URLs
        if (std.mem.startsWith(u8, str, "http://")) return true;
        if (std.mem.startsWith(u8, str, "https://")) return true;
        if (std.mem.startsWith(u8, str, "ftp://")) return true;

        // Check for config files
        if (std.mem.endsWith(u8, str, ".conf")) return true;
        if (std.mem.endsWith(u8, str, ".cfg")) return true;
        if (std.mem.endsWith(u8, str, ".ini")) return true;

        return false;
    }
};

/// Analyze library dependencies
pub fn analyzeDependencies(allocator: Allocator, analyzer: *ElfAnalyzer, result: *DetectionResult) !void {
    var libraries: std.ArrayList([]const u8) = .empty;
    defer {
        for (libraries.items) |lib| allocator.free(lib);
        libraries.deinit(allocator);
    }

    try analyzer.getNeededLibraries(&libraries);

    for (libraries.items) |lib| {
        for (library_patterns) |pattern| {
            if (std.mem.find(u8, lib, pattern.pattern) != null) {
                if (pattern.capability.len > 0) {
                    try result.addHint(pattern.description, pattern.capability, pattern.confidence);
                }
                break;
            }
        }
    }
}

/// Analyze dynamic symbols for system calls
pub fn analyzeSymbols(allocator: Allocator, analyzer: *ElfAnalyzer, result: *DetectionResult) !void {
    var symbols: std.ArrayList([]const u8) = .empty;
    defer {
        for (symbols.items) |sym| allocator.free(sym);
        symbols.deinit(allocator);
    }

    try analyzer.getDynamicSymbols(&symbols);

    var has_socket = false;
    var has_bind = false;
    var has_file_ops = false;
    var has_process_ops = false;

    for (symbols.items) |sym| {
        if (std.mem.eql(u8, sym, "socket") or std.mem.eql(u8, sym, "__socket")) {
            has_socket = true;
        }
        if (std.mem.eql(u8, sym, "dlopen")) {
            result.uses_dlopen = true;
        }
        if (std.mem.eql(u8, sym, "bind") or std.mem.eql(u8, sym, "listen")) {
            has_bind = true;
        }
        if (std.mem.eql(u8, sym, "open") or std.mem.eql(u8, sym, "read") or
            std.mem.eql(u8, sym, "write") or std.mem.eql(u8, sym, "fopen"))
        {
            has_file_ops = true;
        }
        if (std.mem.eql(u8, sym, "fork") or std.mem.eql(u8, sym, "exec") or
            std.mem.eql(u8, sym, "execve") or std.mem.eql(u8, sym, "posix_spawn"))
        {
            has_process_ops = true;
        }
    }

    if (has_socket) {
        if (has_bind) {
            try result.addHint("Socket operations detected (server)", "network: tcp:8080:inbound", 85);
        } else {
            try result.addHint("Socket operations detected (client)", "network: tcp:80:outbound", 75);
        }
    }

    if (has_file_ops) {
        try result.addHint("File operations detected", "filesystem: /tmp:rw", 70);
    }

    if (has_process_ops) {
        try result.addHint("Process management detected", "processes: 10", 80);
    }
}

/// Analyze embedded strings for paths and URLs
pub fn analyzeStrings(allocator: Allocator, analyzer: *ElfAnalyzer, result: *DetectionResult) !void {
    var strings: std.ArrayList([]const u8) = .empty;
    defer {
        for (strings.items) |s| allocator.free(s);
        strings.deinit(allocator);
    }

    try analyzer.extractStrings(4, &strings);

    for (strings.items) |str| {
        // Limit to 20 string hints
        if (result.hints.items.len >= MAX_CAPABILITY_HINTS - 10) break;

        if (std.mem.startsWith(u8, str, "/etc/")) {
            var desc_buf: [256]u8 = undefined;
            const desc = std.fmt.bufPrint(&desc_buf, "Configuration file: {s}", .{str[0..@min(str.len, 60)]}) catch continue;
            var cap_buf: [512]u8 = undefined;
            const cap = std.fmt.bufPrint(&cap_buf, "filesystem: {s}:r", .{str}) catch continue;
            try result.addHint(desc, cap, 60);
        } else if (std.mem.startsWith(u8, str, "/var/")) {
            var desc_buf: [256]u8 = undefined;
            const desc = std.fmt.bufPrint(&desc_buf, "Data directory: {s}", .{str[0..@min(str.len, 60)]}) catch continue;
            var cap_buf: [512]u8 = undefined;
            const cap = std.fmt.bufPrint(&cap_buf, "filesystem: {s}:rw", .{str}) catch continue;
            try result.addHint(desc, cap, 65);
        } else if (std.mem.startsWith(u8, str, "http://") or std.mem.startsWith(u8, str, "https://")) {
            var desc_buf: [256]u8 = undefined;
            const truncated = str[0..@min(str.len, 50)];
            const suffix: []const u8 = if (str.len > 50) "..." else "";
            const desc = std.fmt.bufPrint(&desc_buf, "HTTP URL found: {s}{s}", .{ truncated, suffix }) catch continue;
            try result.addHint(desc, "network: tcp:80:outbound\nnetwork: tcp:443:outbound", 70);
        }
    }
}

/// Analyze application patterns based on binary name
pub fn analyzePatterns(result: *DetectionResult) !void {
    for (app_patterns) |pattern| {
        if (std.mem.find(u8, result.binary_name, pattern.pattern) != null) {
            try result.addHint(pattern.description, pattern.capability, pattern.confidence);
            break; // Only match first pattern
        }
    }
}

/// The key of a "key: value" capability line, and its value
fn splitLine(line: []const u8) ?struct { key: []const u8, value: []const u8 } {
    const colon = std.mem.findScalar(u8, line, ':') orelse return null;
    return .{
        .key = std.mem.trim(u8, line[0..colon], " \t"),
        .value = std.mem.trim(u8, line[colon + 1 ..], " \t"),
    };
}

/// Whether a path exists on this host as something a filesystem rule can
/// mount: a directory or a regular file
fn isMountable(io: std.Io, path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .directory or st.kind == .file;
}

/// Generate capability file from detection results.
///
/// Every line written without a leading '#' is one `isolate run` applies as
/// written, so the file loads with no problems (design: DET-2).
///
/// Two kinds of line are written, and only one kind is live:
///
///   Facts - the shared libraries the program is linked against, found by
///   following its dependencies. These are live rules.
///
///   Guesses - anything inferred from the program's name, the symbols it
///   imports or strings embedded in it. These are written as comments for
///   a person to enable. A guess is never live: the strings in a binary
///   name files such as private keys, and a generated file must not grant
///   access to them unasked.
pub fn generateCapabilityFile(
    io: std.Io,
    allocator: Allocator,
    binary_path: []const u8,
    output_path: []const u8,
    result: *DetectionResult,
    closure: ?*const libs.Closure,
    /// Write the directories the libraries are in, not the files
    use_dirs: bool,
) !void {
    const file = try std.Io.Dir.cwd().createFile(io, output_path, .{});
    defer file.close(io);

    var write_buf: [4096]u8 = undefined;
    var file_writer = file.writer(io, &write_buf);
    const writer = &file_writer.interface;

    // Get current time
    const timestamp = std.Io.Timestamp.now(io, .real).toSeconds();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    // Sort hints by confidence
    result.sortByConfidence();

    // The limits appear once. A hint can only raise them above the defaults.
    var memory_bytes: usize = 128 * 1024 * 1024;
    var processes: u32 = 5;
    const files: u32 = 512;
    for (result.hints.items) |hint| {
        var lines = std.mem.splitScalar(u8, hint.capability, '\n');
        while (lines.next()) |line| {
            const kv = splitLine(line) orelse continue;
            if (std.mem.eql(u8, kv.key, "memory")) {
                const bytes = caps.parseMemorySize(kv.value) catch continue;
                memory_bytes = @max(memory_bytes, bytes);
            } else if (std.mem.eql(u8, kv.key, "processes")) {
                const n = std.fmt.parseInt(u32, kv.value, 10) catch continue;
                processes = @max(processes, n);
            }
        }
    }

    // Write header
    try writer.print("# Auto-generated capability file for {s}\n", .{binary_path});
    try writer.print("# Generated on: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}\n", .{
        year_day.year,
        @as(u32, @intFromEnum(month_day.month)), // the enum starts at 1 for January
        month_day.day_index + 1, // day is 0-indexed
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
    try writer.writeAll("#\n# Live lines are facts read from the binary: the libraries it links against.\n");
    try writer.writeAll("# Commented lines are guesses from its name, symbols and embedded strings;\n");
    try writer.writeAll("# uncomment the ones the program really needs.\n");
    try writer.writeAll("# Check the result with: isolate run -n -v <binary>\n\n");

    try writer.writeAll("# User context - creates ephemeral user automatically\n");
    try writer.writeAll("user: auto\n\n");

    try writer.writeAll("# Resource limits: defaults, raised by what was detected. Adjust them.\n");
    try writer.print("memory: {d}M\n", .{memory_bytes / (1024 * 1024)});
    try writer.print("processes: {d}\n", .{processes});
    try writer.print("files: {d}\n\n", .{files});

    // Track what has been written, to avoid duplicates
    var added_hints = std.StringHashMap(void).init(allocator);
    defer added_hints.deinit();
    var added_lines = std.StringHashMap(void).init(allocator);
    defer added_lines.deinit();
    var added_paths = std.StringHashMap(void).init(allocator);
    defer {
        var keys = added_paths.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        added_paths.deinit();
    }
    var file_rule_count: usize = 0;
    var env_count: usize = 0;

    if (closure) |cl| {
        if (cl.interpreter == null and cl.libraries.items.len == 0) {
            try writer.writeAll("# Statically linked: this program needs no shared libraries.\n\n");
        } else {
            if (use_dirs) {
                try writer.writeAll("# Shared libraries: the directories this program's libraries are in.\n");
                try writer.writeAll("# Everything in these directories is visible in the jail. Without\n");
                try writer.writeAll("# --dirs, detect lists only the library files themselves.\n");
                var lib_dirs = try cl.directories(allocator);
                defer lib_dirs.deinit(allocator);
                if (cl.interpreter) |interp| {
                    if (std.fs.path.dirname(interp)) |interp_dir| {
                        try writer.print("filesystem: {s}:r\n", .{interp_dir});
                        try added_paths.put(try allocator.dupe(u8, interp_dir), {});
                        file_rule_count += 1;
                    }
                }
                for (lib_dirs.items) |lib_dir| {
                    if (added_paths.contains(lib_dir)) continue;
                    try writer.print("filesystem: {s}:r\n", .{lib_dir});
                    try added_paths.put(try allocator.dupe(u8, lib_dir), {});
                    file_rule_count += 1;
                }
            } else {
                try writer.writeAll("# Shared libraries: exactly the files this program is linked against,\n");
                try writer.writeAll("# found by following its dependencies the way the run-time linker does.\n");
                try writer.writeAll("# Nothing else from the library directories is visible in the jail.\n");
                if (cl.interpreter) |interp| {
                    try writer.print("filesystem: {s}:r\n", .{interp});
                    try added_paths.put(try allocator.dupe(u8, interp), {});
                    file_rule_count += 1;
                }
                for (cl.libraries.items) |path| {
                    if (added_paths.contains(path)) continue;
                    if (file_rule_count >= caps.MAX_FILE_RULES) {
                        try writer.print("#   filesystem: {s}:r    (over the limit of {d} filesystem rules)\n", .{ path, caps.MAX_FILE_RULES });
                        continue;
                    }
                    try writer.print("filesystem: {s}:r\n", .{path});
                    try added_paths.put(try allocator.dupe(u8, path), {});
                    file_rule_count += 1;
                }
            }
            for (cl.unresolved.items) |name| {
                try writer.print("#   {s}    (needed, but not found on this host)\n", .{name});
            }

            // isolate sets LD_LIBRARY_PATH to the usual three directories.
            // Libraries found anywhere else need the linker told where.
            var dirs = try cl.directories(allocator);
            defer dirs.deinit(allocator);
            var needs_path = false;
            for (dirs.items) |dir| {
                var builtin = false;
                for (libs.builtin_dirs) |known| {
                    if (std.mem.eql(u8, dir, known)) builtin = true;
                }
                if (!builtin) needs_path = true;
            }
            if (needs_path) {
                try writer.writeAll("# Where the linker finds them\n");
                try writer.writeAll("env: LD_LIBRARY_PATH=");
                for (dirs.items, 0..) |dir, i| {
                    if (i > 0) try writer.writeByte(':');
                    try writer.writeAll(dir);
                }
                try writer.writeByte('\n');
                env_count += 1;
            }

            if (result.uses_dlopen) {
                try writer.writeAll("#\n# This program calls dlopen(): it can load further libraries at run time\n");
                try writer.writeAll("# (plugins, modules). Those cannot be found by reading the binary. If it\n");
                try writer.writeAll("# fails to load one, add a rule for that file or for its directory.\n");
            }
            try writer.writeAll("\n");
        }
    }

    try writer.writeAll("# Guesses, most confident first. None of these is applied.\n");
    try writer.writeAll("# Uncomment a line to use it.\n\n");

    var current_conf_range: ?u8 = null;

    for (result.hints.items) |hint| {
        // Skip if already added
        if (added_hints.contains(hint.capability)) continue;
        try added_hints.put(hint.capability, {});

        // Write confidence section header
        const conf_range = (hint.confidence / 10) * 10;
        if (current_conf_range == null or current_conf_range.? != conf_range) {
            if (current_conf_range != null) try writer.writeAll("\n");
            try writer.print("# Confidence: {d}-{d}%\n", .{ conf_range, conf_range + 9 });
            current_conf_range = conf_range;
        }

        // Write hint
        try writer.print("# {s}\n", .{hint.description});

        var iter = std.mem.splitScalar(u8, hint.capability, '\n');
        while (iter.next()) |cap_line| {
            if (cap_line.len == 0) continue;
            const kv = splitLine(cap_line) orelse {
                try writer.print("#   {s}    (not a capability line)\n", .{cap_line});
                continue;
            };

            if (std.mem.eql(u8, kv.key, "memory") or std.mem.eql(u8, kv.key, "processes") or std.mem.eql(u8, kv.key, "files")) {
                // Folded into the limits at the top of the file
                try writer.print("#   {s}    (see the limits above)\n", .{cap_line});
            } else if (std.mem.eql(u8, kv.key, "network")) {
                try writer.print("# {s}\n", .{cap_line});
            } else if (std.mem.eql(u8, kv.key, "filesystem")) {
                const rule = caps.parseFileRule(allocator, kv.value) catch {
                    try writer.print("#   {s}    (not a usable rule)\n", .{cap_line});
                    continue;
                };
                // The rule's path is kept as the key of added_paths
                if (added_paths.contains(rule.path)) {
                    allocator.free(rule.path);
                    continue;
                }
                try added_paths.put(rule.path, {});

                const is_tmp = std.mem.eql(u8, rule.path, "/tmp");
                if (!is_tmp and !isMountable(io, rule.path)) {
                    try writer.print("#   {s}    (not present on this host)\n", .{cap_line});
                } else {
                    try writer.print("# {s}\n", .{cap_line});
                }
            } else if (std.mem.eql(u8, kv.key, "env")) {
                if (added_lines.contains(cap_line)) continue;
                try added_lines.put(cap_line, {});
                try writer.print("# {s}\n", .{cap_line});
            } else {
                try writer.print("#   {s}    (not applied)\n", .{cap_line});
            }
        }
    }

    try writer.writeAll("\n");

    // Add commented examples
    try writer.writeAll("# Other settings (commented out):\n");
    try writer.writeAll("# network_mode: none             # no network at all (default: inherit, the host's network)\n");
    try writer.writeAll("# network_mode: vnet:epair0b     # a network stack of its own; needed for network: rules\n");
    try writer.writeAll("# network: tcp:443:outbound      # with rules, everything not listed is blocked\n");
    try writer.writeAll("# filesystem: /home/user:rw      # a directory or file, read-only (r) or read-write (rw)\n");
    try writer.writeAll("# env: PATH=/usr/bin:/bin        # custom environment\n");
    try writer.writeAll("# env_clear: true                # start from an empty environment\n");

    try writer.flush();
}

/// Main detection function
pub fn detectCapabilities(
    io: std.Io,
    allocator: Allocator,
    binary_path: []const u8,
    output_path: ?[]const u8,
    /// Mount whole library directories instead of the exact library files
    use_dirs: bool,
) DetectError!void {
    var stdout_file = std.Io.File.stdout().writerStreaming(io, &.{});
    const stdout = &stdout_file.interface;

    stdout.print("Detecting capabilities for: {s}\n", .{binary_path}) catch {};

    // Check if binary exists
    std.Io.Dir.cwd().access(io, binary_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            std.debug.print("Error: Binary {s} not found\n", .{binary_path});
            return DetectError.FileNotFound;
        }
        return DetectError.AccessDenied;
    };

    // Determine output file
    var output_buf: [4096]u8 = undefined;
    const output = output_path orelse blk: {
        const len = std.fmt.bufPrint(&output_buf, "{s}.caps", .{binary_path}) catch {
            return DetectError.OutOfMemory;
        };
        break :blk len;
    };

    stdout.print("Output capability file: {s}\n\n", .{output}) catch {};

    // Initialize result
    var result = DetectionResult.init(allocator, binary_path);
    defer result.deinit();

    // The exact library files, unless whole directories were asked for or
    // the binary cannot be followed
    var closure: ?libs.Closure = null;
    defer if (closure) |*cl| cl.deinit();
    {
        const system_dirs = libs.searchDirs(io, allocator) catch null;
        defer if (system_dirs) |dirs| allocator.free(dirs);
        if (system_dirs) |dirs| {
            closure = libs.resolve(io, allocator, binary_path, dirs) catch null;
        }
        if (closure) |cl| {
            stdout.print("Resolving shared libraries... {d} found", .{cl.libraries.items.len}) catch {};
            if (cl.unresolved.items.len > 0) stdout.print(", {d} not found", .{cl.unresolved.items.len}) catch {};
            stdout.writeAll("\n") catch {};
        }
    }

    // Try ELF analysis
    if (ElfAnalyzer.init(io, allocator, binary_path)) |elf_result| {
        var analyzer = elf_result;
        defer analyzer.deinit();

        stdout.writeAll("Analyzing library dependencies...\n") catch {};
        analyzeDependencies(allocator, &analyzer, &result) catch {};

        stdout.writeAll("Analyzing dynamic symbols...\n") catch {};
        analyzeSymbols(allocator, &analyzer, &result) catch {};

        stdout.writeAll("Analyzing embedded strings...\n") catch {};
        analyzeStrings(allocator, &analyzer, &result) catch {};
    } else |err| {
        stdout.print("Warning: Could not analyze ELF: {}\n", .{err}) catch {};
    }

    stdout.writeAll("Analyzing application patterns...\n") catch {};
    analyzePatterns(&result) catch {};

    // Display summary
    stdout.print("\nDetection Summary:\n", .{}) catch {};
    stdout.print("==================\n", .{}) catch {};
    stdout.print("Found {d} capability hints\n", .{result.hints.items.len}) catch {};

    // Generate capability file
    generateCapabilityFile(io, allocator, binary_path, output, &result, if (closure) |*cl| cl else null, use_dirs) catch |err| {
        std.debug.print("Error generating capability file: {}\n", .{err});
        return DetectError.IoError;
    };

    stdout.print("\nGenerated capability file: {s}\n", .{output}) catch {};
    stdout.writeAll("Review and edit the file before using with isolate.\n") catch {};
}

// ============================================================================
// Tests
// ============================================================================

test "DetectionResult init and deinit" {
    const allocator = std.testing.allocator;

    var result = DetectionResult.init(allocator, "/usr/bin/test");
    defer result.deinit();

    try std.testing.expectEqualStrings("test", result.binary_name);
}

test "DetectionResult addHint" {
    const allocator = std.testing.allocator;

    var result = DetectionResult.init(allocator, "test");
    defer result.deinit();

    try result.addHint("Test hint", "filesystem: /tmp:rw", 80);

    try std.testing.expectEqual(@as(usize, 1), result.hints.items.len);
    try std.testing.expectEqualStrings("Test hint", result.hints.items[0].description);
    try std.testing.expectEqual(@as(u8, 80), result.hints.items[0].confidence);
}

test "generated capability files load without problems" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    var out_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const out_path = try std.fmt.bufPrint(&out_buf, "{s}/out.caps", .{dir_buf[0..dir_len]});

    var result = DetectionResult.init(allocator, "/usr/local/sbin/nginx");
    defer result.deinit();

    // Everything detection can produce, including what isolate cannot apply
    try result.addHint("libraries", "filesystem: /tmp:rw\nfilesystem: /nonexistent/isolate-test:r", 95);
    try result.addHint("server", "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nmemory: 256M", 90);
    try result.addHint("threads", "processes: 10", 80);
    try result.addHint("fork", "processes: 20", 75);
    try result.addHint("x11", "filesystem: /tmp:rw\nenv: DISPLAY=:0", 70);
    try result.addHint("string", "filesystem: /var/run/%s.pid # x:rw", 65);
    try result.addHint("string", "filesystem: relative/path:rw", 60);
    try result.addHint("daemon", "filesystem: /var/log:w", 55);

    try generateCapabilityFile(io, allocator, "/usr/local/sbin/nginx", out_path, &result, null, false);

    var parsed = try caps.load(io, allocator, out_path);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 0), parsed.problems.items.len);
    // Limits are written once, raised to the largest hint
    try std.testing.expectEqual(@as(?usize, 256 * 1024 * 1024), parsed.caps.limits.memory_bytes);
    try std.testing.expectEqual(@as(?u32, 20), parsed.caps.limits.max_processes);
    try std.testing.expectEqual(@as(?u32, 512), parsed.caps.limits.max_files);
    // Network rules are comments, not rules
    try std.testing.expectEqual(@as(usize, 0), parsed.caps.network_rules.items.len);
    // Everything here was a guess, so nothing is live: no filesystem rule,
    // no environment entry
    try std.testing.expectEqual(@as(usize, 0), parsed.caps.file_rules.items.len);
    try std.testing.expectEqual(@as(usize, 0), parsed.caps.env_vars.items.len);
}

test "generated files list the library closure file by file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    // Two stand-in "libraries" that exist, in a directory the linker would
    // not search by default
    var lib_a_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var lib_b_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const lib_a = try std.fmt.bufPrint(&lib_a_buf, "{s}/liba.so.1", .{dir});
    const lib_b = try std.fmt.bufPrint(&lib_b_buf, "{s}/libb.so.2", .{dir});
    for ([_][]const u8{ lib_a, lib_b }) |path| {
        const f = try std.Io.Dir.cwd().createFile(io, path, .{});
        f.close(io);
    }

    var closure = libs.Closure{ .allocator = allocator };
    defer closure.deinit();
    closure.interpreter = try allocator.dupe(u8, lib_a); // any existing file
    try closure.libraries.append(allocator, try allocator.dupe(u8, lib_b));
    try closure.unresolved.append(allocator, try allocator.dupe(u8, "libmissing.so.9"));

    var result = DetectionResult.init(allocator, "/usr/local/bin/app");
    defer result.deinit();
    result.uses_dlopen = true;
    try result.addHint("temp files", "filesystem: /tmp:rw", 70);

    var out_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const out_path = try std.fmt.bufPrint(&out_buf, "{s}/out.caps", .{dir});
    try generateCapabilityFile(io, allocator, "/usr/local/bin/app", out_path, &result, &closure, false);

    var parsed = try caps.load(io, allocator, out_path);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), parsed.problems.items.len);

    // The interpreter and the library are facts and live. The /tmp hint is
    // a guess and is not.
    try std.testing.expectEqual(@as(usize, 2), parsed.caps.file_rules.items.len);
    try std.testing.expectEqualStrings(lib_a, parsed.caps.file_rules.items[0].path);
    try std.testing.expectEqualStrings(lib_b, parsed.caps.file_rules.items[1].path);
    try std.testing.expect(!parsed.caps.file_rules.items[1].permissions.write);

    // The library directory is not one of isolate's defaults, so the
    // linker is told about it
    try std.testing.expectEqual(@as(usize, 1), parsed.caps.env_vars.items.len);
    try std.testing.expectEqualStrings("LD_LIBRARY_PATH", parsed.caps.env_vars.items[0].name);
    try std.testing.expectEqualStrings(dir, parsed.caps.env_vars.items[0].value);
}

test "DetectionResult sortByConfidence" {
    const allocator = std.testing.allocator;

    var result = DetectionResult.init(allocator, "test");
    defer result.deinit();

    try result.addHint("Low", "cap1", 50);
    try result.addHint("High", "cap2", 90);
    try result.addHint("Medium", "cap3", 70);

    result.sortByConfidence();

    try std.testing.expectEqual(@as(u8, 90), result.hints.items[0].confidence);
    try std.testing.expectEqual(@as(u8, 70), result.hints.items[1].confidence);
    try std.testing.expectEqual(@as(u8, 50), result.hints.items[2].confidence);
}

test "library pattern matching" {
    // Test that we can find patterns in library names
    const test_libs = [_][]const u8{
        "libcurl.so.4",
        "libssl.so.1.1",
        "libpq.so.5",
    };

    var matches: usize = 0;
    for (test_libs) |lib| {
        for (library_patterns) |pattern| {
            if (std.mem.find(u8, lib, pattern.pattern) != null) {
                matches += 1;
                break;
            }
        }
    }

    try std.testing.expectEqual(@as(usize, 3), matches);
}

test "app pattern matching" {
    // Test application name pattern matching
    const test_names = [_]struct { name: []const u8, should_match: bool }{
        .{ .name = "nginx", .should_match = true },
        .{ .name = "my-nginx-server", .should_match = true },
        .{ .name = "httpd", .should_match = true },
        .{ .name = "randomapp", .should_match = false },
    };

    for (test_names) |test_case| {
        var found = false;
        for (app_patterns) |pattern| {
            if (std.mem.find(u8, test_case.name, pattern.pattern) != null) {
                found = true;
                break;
            }
        }
        try std.testing.expectEqual(test_case.should_match, found);
    }
}

test "ElfAnalyzer isInterestingString" {
    try std.testing.expect(ElfAnalyzer.isInterestingString("/etc/passwd"));
    try std.testing.expect(ElfAnalyzer.isInterestingString("/var/log/app.log"));
    try std.testing.expect(ElfAnalyzer.isInterestingString("https://example.com"));
    try std.testing.expect(ElfAnalyzer.isInterestingString("config.conf"));
    try std.testing.expect(!ElfAnalyzer.isInterestingString("random string"));
    try std.testing.expect(!ElfAnalyzer.isInterestingString("hello world"));
}
