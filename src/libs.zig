//! Shared-library closure of an ELF binary
//!
//! Works out which library files a dynamically linked program needs, the way
//! the run-time linker would find them, without running the program:
//!
//!   1. read the binary's DT_NEEDED entries and its DT_RPATH / DT_RUNPATH;
//!   2. look each name up in the run path, then in the directories listed in
//!      the linker's hints file, then in /lib and /usr/lib;
//!   3. repeat for every library found.
//!
//! The result is the list of files `isolate detect` turns into filesystem
//! rules, so that a jail holds exactly the libraries its program links
//! against instead of whole library directories.
//!
//! What this cannot see: libraries a program loads at run time with
//! dlopen(3) - plugins, modules, name-service backends.

const std = @import("std");
const Allocator = std.mem.Allocator;
const elf = std.elf;
const detect = @import("detect.zig");

/// The hints file rtld(1) reads its search directories from
pub const hints_path = "/var/run/ld-elf.so.hints";

/// Directories rtld(1) searches when nothing else matches
pub const default_dirs = "/lib:/usr/lib";

/// Library directories isolate already puts in LD_LIBRARY_PATH
pub const builtin_dirs = [_][]const u8{ "/usr/local/lib", "/usr/lib", "/lib" };

/// Upper bound on libraries followed, as a guard against a malformed binary
const max_libraries = 512;

pub const Closure = struct {
    allocator: Allocator,
    /// The program's interpreter (PT_INTERP), e.g. /libexec/ld-elf.so.1.
    /// Null for a statically linked program.
    interpreter: ?[]const u8 = null,
    /// Library files, as the paths the linker will open, in the order found
    libraries: std.ArrayList([]const u8) = .empty,
    /// Names that could not be found on this host
    unresolved: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Closure) void {
        if (self.interpreter) |interp| self.allocator.free(interp);
        for (self.libraries.items) |path| self.allocator.free(path);
        self.libraries.deinit(self.allocator);
        for (self.unresolved.items) |name| self.allocator.free(name);
        self.unresolved.deinit(self.allocator);
    }

    /// The directories the libraries were found in, without duplicates, in
    /// the order first seen. Caller owns the list, not the strings.
    pub fn directories(self: *const Closure, allocator: Allocator) !std.ArrayList([]const u8) {
        var dirs: std.ArrayList([]const u8) = .empty;
        errdefer dirs.deinit(allocator);
        outer: for (self.libraries.items) |path| {
            const dir = std.fs.path.dirname(path) orelse continue;
            for (dirs.items) |seen| {
                if (std.mem.eql(u8, seen, dir)) continue :outer;
            }
            try dirs.append(allocator, dir);
        }
        return dirs;
    }
};

/// The colon-separated directory list in an rtld hints file, or null if the
/// bytes are not one.
///
/// struct elfhints_hdr { u32 magic, version, strtab, strsize, dirlist,
///                       dirlistlen; u32 spare[26]; }
/// The directory list is `dirlistlen` bytes at offset `strtab + dirlist`.
pub fn parseHints(bytes: []const u8) ?[]const u8 {
    const magic: u32 = 0x746e6845; // "Ehnt"
    if (bytes.len < 6 * 4) return null;
    if (std.mem.readInt(u32, bytes[0..4], .little) != magic) return null;

    const strtab = std.mem.readInt(u32, bytes[8..12], .little);
    const dirlist = std.mem.readInt(u32, bytes[16..20], .little);
    const dirlistlen = std.mem.readInt(u32, bytes[20..24], .little);

    const start = @as(usize, strtab) + dirlist;
    const end = start + dirlistlen;
    if (end > bytes.len or start > end) return null;
    return bytes[start..end];
}

/// The directories rtld(1) searches on this host: those in the hints file,
/// then the built-in defaults. Caller owns the result.
pub fn searchDirs(io: std.Io, allocator: Allocator) ![]const u8 {
    const hinted: ?[]u8 = std.Io.Dir.cwd().readFileAlloc(io, hints_path, allocator, .limited(1 << 20)) catch null;
    defer if (hinted) |bytes| allocator.free(bytes);

    if (hinted) |bytes| {
        if (parseHints(bytes)) |dirs| {
            return std.fmt.allocPrint(allocator, "{s}:{s}", .{ dirs, default_dirs });
        }
    }
    return allocator.dupe(u8, default_dirs);
}

/// Replace $ORIGIN and ${ORIGIN} in a run path entry with the directory of
/// the object that carries it. Caller owns the result.
pub fn expandOrigin(allocator: Allocator, dir: []const u8, origin: []const u8) ![]const u8 {
    const braced = try std.mem.replaceOwned(u8, allocator, dir, "${ORIGIN}", origin);
    defer allocator.free(braced);
    return std.mem.replaceOwned(u8, allocator, braced, "$ORIGIN", origin);
}

fn isFile(io: std.Io, path: []const u8) bool {
    const st = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return st.kind == .file;
}

/// Find library `name`, needed by an object in directory `origin` with the
/// given run paths. Caller owns the result; null if it is nowhere.
fn locate(
    io: std.Io,
    allocator: Allocator,
    name: []const u8,
    origin: []const u8,
    run_paths: []const []const u8,
    system_dirs: []const u8,
) !?[]const u8 {
    // A name with a slash is a path, not something to search for
    if (std.mem.findScalar(u8, name, '/') != null) {
        return if (isFile(io, name)) try allocator.dupe(u8, name) else null;
    }

    for (run_paths) |list| {
        var dirs = std.mem.splitScalar(u8, list, ':');
        while (dirs.next()) |raw| {
            if (raw.len == 0) continue;
            const dir = try expandOrigin(allocator, raw, origin);
            defer allocator.free(dir);
            const candidate = try std.fs.path.join(allocator, &.{ dir, name });
            if (isFile(io, candidate)) return candidate;
            allocator.free(candidate);
        }
    }

    var dirs = std.mem.splitScalar(u8, system_dirs, ':');
    while (dirs.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, name });
        if (isFile(io, candidate)) return candidate;
        allocator.free(candidate);
    }
    return null;
}

fn freeStrings(allocator: Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |s| allocator.free(s);
    list.deinit(allocator);
}

/// Resolve the library closure of `binary_path`. `system_dirs` is the
/// colon-separated list from `searchDirs`.
pub fn resolve(io: std.Io, allocator: Allocator, binary_path: []const u8, system_dirs: []const u8) !Closure {
    var closure = Closure{ .allocator = allocator };
    errdefer closure.deinit();

    // Names already looked up, found or not: the linker loads each once
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var keys = seen.keyIterator();
        while (keys.next()) |key| allocator.free(key.*);
        seen.deinit();
    }

    // Objects whose dependencies are still to be read. Paths are borrowed
    // from `closure.libraries`, except the first.
    var queue: std.ArrayList([]const u8) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, binary_path);

    var index: usize = 0;
    while (index < queue.items.len) : (index += 1) {
        const object = queue.items[index];

        var analyzer = detect.ElfAnalyzer.init(io, allocator, object) catch |err| {
            if (index == 0) return err; // the program itself must be readable ELF
            continue;
        };
        defer analyzer.deinit();

        if (index == 0) closure.interpreter = try analyzer.getInterpreter();

        var needed: std.ArrayList([]const u8) = .empty;
        defer freeStrings(allocator, &needed);
        try analyzer.getDynamicStrings(elf.DT_NEEDED, &needed);

        // DT_RUNPATH replaces DT_RPATH when both are present
        var run_paths: std.ArrayList([]const u8) = .empty;
        defer freeStrings(allocator, &run_paths);
        try analyzer.getDynamicStrings(elf.DT_RUNPATH, &run_paths);
        if (run_paths.items.len == 0) try analyzer.getDynamicStrings(elf.DT_RPATH, &run_paths);

        const origin = std.fs.path.dirname(object) orelse ".";

        for (needed.items) |name| {
            if (seen.contains(name)) continue;
            try seen.put(try allocator.dupe(u8, name), {});

            const found = try locate(io, allocator, name, origin, run_paths.items, system_dirs);
            if (found) |path| {
                try closure.libraries.append(allocator, path);
                if (queue.items.len < max_libraries) try queue.append(allocator, path);
            } else {
                try closure.unresolved.append(allocator, try allocator.dupe(u8, name));
            }
        }
    }

    return closure;
}

// ============================================================================
// Tests
// ============================================================================

test "parseHints reads the directory list" {
    // A header (128 bytes), then a string table whose directory list starts
    // 4 bytes in
    var bytes = [_]u8{0} ** 160;
    std.mem.writeInt(u32, bytes[0..4], 0x746e6845, .little);
    std.mem.writeInt(u32, bytes[4..8], 1, .little);
    std.mem.writeInt(u32, bytes[8..12], 128, .little); // strtab
    std.mem.writeInt(u32, bytes[12..16], 32, .little); // strsize
    std.mem.writeInt(u32, bytes[16..20], 4, .little); // dirlist
    const dirs = "/lib:/usr/local/lib";
    std.mem.writeInt(u32, bytes[20..24], dirs.len, .little);
    @memcpy(bytes[132..][0..dirs.len], dirs);

    try std.testing.expectEqualStrings(dirs, parseHints(&bytes).?);
}

test "parseHints rejects anything else" {
    try std.testing.expect(parseHints("") == null);
    try std.testing.expect(parseHints("not a hints file at all, just text") == null);

    // Right magic, directory list pointing past the end
    var bytes = [_]u8{0} ** 32;
    std.mem.writeInt(u32, bytes[0..4], 0x746e6845, .little);
    std.mem.writeInt(u32, bytes[8..12], 24, .little);
    std.mem.writeInt(u32, bytes[20..24], 4096, .little);
    try std.testing.expect(parseHints(&bytes) == null);
}

test "expandOrigin" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "/usr/local/lib", .out = "/usr/local/lib" },
        .{ .in = "$ORIGIN/../lib", .out = "/opt/app/bin/../lib" },
        .{ .in = "${ORIGIN}/lib", .out = "/opt/app/bin/lib" },
    };
    for (cases) |case| {
        const got = try expandOrigin(allocator, case.in, "/opt/app/bin");
        defer allocator.free(got);
        try std.testing.expectEqualStrings(case.out, got);
    }
}

test "Closure.directories lists each directory once" {
    const allocator = std.testing.allocator;
    var closure = Closure{ .allocator = allocator };
    defer closure.deinit();
    for ([_][]const u8{ "/lib/libc.so.7", "/usr/local/lib/libpq.so.5", "/lib/libm.so.5" }) |path| {
        try closure.libraries.append(allocator, try allocator.dupe(u8, path));
    }

    var dirs = try closure.directories(allocator);
    defer dirs.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), dirs.items.len);
    try std.testing.expectEqualStrings("/lib", dirs.items[0]);
    try std.testing.expectEqualStrings("/usr/local/lib", dirs.items[1]);
}

test "resolve fails on something that is not ELF" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/script.sh", .{dir_buf[0..dir_len]});

    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    try file.writeStreamingAll(io, "#!/bin/sh\necho this is a script, long enough to hold an ELF header's worth of bytes\n");
    file.close(io);

    try std.testing.expect(std.meta.isError(resolve(io, allocator, path, default_dirs)));
}
