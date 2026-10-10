//! Network rules as pf rules
//!
//! A capability file's `network:` rules say which connections a program may
//! make and accept. They are enforced with pf(4), on the host end of the
//! epair(4) whose other end is inside the program's VNET jail. Every packet
//! to or from the jail crosses that interface, so nothing can go around it:
//!
//!     the jail  [ epair0b ] ===== [ epair0a ]  the host, and beyond
//!                                     ^
//!                              pf filters here
//!
//! Seen from the host end, the directions are mirrored: what the jail sends
//! arrives *in* on epair0a, and what is sent to the jail goes *out* on it.
//!
//! This module only turns rules into text and decides whether a capability
//! file's rules can be enforced at all. Loading them into pf is done by
//! freebsd.zig.

const std = @import("std");
const caps = @import("caps.zig");

/// The anchor under which every instance's rules are loaded. The host's
/// pf.conf must contain:  anchor "isolate/*"
pub const anchor_root = "isolate";
pub const anchor_line = "anchor \"" ++ anchor_root ++ "/*\"";

/// The host end of an epair, given the end that goes into the jail:
/// "epair0b" -> "epair0a". Null for anything that is not the b end of an
/// epair; there is then no interface on the host to filter on.
pub fn hostSide(buf: []u8, jail_interface: []const u8) ?[]const u8 {
    const prefix = "epair";
    if (!std.mem.startsWith(u8, jail_interface, prefix)) return null;
    if (jail_interface.len < prefix.len + 2 or jail_interface.len > buf.len) return null;
    if (jail_interface[jail_interface.len - 1] != 'b') return null;
    for (jail_interface[prefix.len .. jail_interface.len - 1]) |ch| {
        if (!std.ascii.isDigit(ch)) return null;
    }
    @memcpy(buf[0..jail_interface.len], jail_interface);
    buf[jail_interface.len - 1] = 'a';
    return buf[0..jail_interface.len];
}

/// Why this capability file's network rules cannot be enforced, or null if
/// they can (or there are none). Rules are never silently dropped: a file
/// that has them and cannot have them enforced is refused.
pub fn unenforceable(capability: *const caps.Capabilities) ?[]const u8 {
    if (capability.network_rules.items.len == 0) return null;

    if (capability.network_config.mode != .vnet) {
        return "network rules need network_mode: vnet:<epair> (they are enforced on the host end of the jail's interface; with the host's network, or none, there is nothing to filter on)";
    }
    const interface = capability.network_config.interface orelse {
        return "network rules need the jail's interface: network_mode: vnet:<epair>";
    };
    var buf: [32]u8 = undefined;
    if (hostSide(&buf, interface) == null) {
        return "network rules need the jail's interface to be the b end of an epair, such as epair0b (its a end stays on the host, where the rules are applied)";
    }
    return null;
}

/// Write the pf rules for one instance.
///
/// Every rule is `quick`: the first match decides, here and now, whatever
/// the rest of the host's ruleset says. The last rule blocks everything
/// else on the interface, so with any rule present the default is deny.
pub fn write(writer: *std.Io.Writer, host_interface: []const u8, rules: []const caps.NetworkRule) !void {
    for (rules) |rule| {
        if (rule.protocol == .none) continue; // "network: none": only the block below

        if (rule.direction == .outbound or rule.direction == .both) {
            // From the jail: arrives in on the host end
            try writer.print("pass in quick on {s} inet proto {s} from any to ", .{ host_interface, @tagName(rule.protocol) });
            try writer.writeAll(if (rule.address.len > 0) rule.address else "any");
            if (rule.port) |port| try writer.print(" port {d}", .{port});
            try writer.writeAll(" keep state\n");
        }
        if (rule.direction == .inbound or rule.direction == .both) {
            // To the jail: leaves out on the host end
            try writer.print("pass out quick on {s} inet proto {s} from ", .{ host_interface, @tagName(rule.protocol) });
            try writer.writeAll(if (rule.address.len > 0) rule.address else "any");
            try writer.writeAll(" to any");
            if (rule.port) |port| try writer.print(" port {d}", .{port});
            try writer.writeAll(" keep state\n");
        }
    }
    try writer.print("block drop quick on {s} all\n", .{host_interface});
}

// ============================================================================
// Tests
// ============================================================================

test "hostSide" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("epair0a", hostSide(&buf, "epair0b").?);
    try std.testing.expectEqualStrings("epair12a", hostSide(&buf, "epair12b").?);
    for ([_][]const u8{ "epair0a", "epair0", "epairb", "em0", "vlan5", "epair0b; pass all", "epairxb", "" }) |name| {
        try std.testing.expect(hostSide(&buf, name) == null);
    }
}

fn rulesText(allocator: std.mem.Allocator, lines: []const []const u8) ![]u8 {
    var rules: std.ArrayList(caps.NetworkRule) = .empty;
    defer {
        for (rules.items) |rule| {
            if (rule.address.len > 0) allocator.free(rule.address);
        }
        rules.deinit(allocator);
    }
    for (lines) |line| try rules.append(allocator, try caps.parseNetworkRule(allocator, line));

    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try write(&out.writer, "epair0a", rules.items);
    return out.toOwnedSlice();
}

test "write: a client that may reach one port" {
    const allocator = std.testing.allocator;
    const text = try rulesText(allocator, &.{"tcp:443:outbound"});
    defer allocator.free(text);
    try std.testing.expectEqualStrings(
        \\pass in quick on epair0a inet proto tcp from any to any port 443 keep state
        \\block drop quick on epair0a all
        \\
    , text);
}

test "write: a server, a database it talks to, and DNS" {
    const allocator = std.testing.allocator;
    const text = try rulesText(allocator, &.{
        "tcp:8080:inbound",
        "tcp:10.0.0.5:5432:outbound",
        "udp:53:outbound",
        "tcp:10.0.99.1:9100:inbound",
        "udp:514:both",
    });
    defer allocator.free(text);
    try std.testing.expectEqualStrings(
        \\pass out quick on epair0a inet proto tcp from any to any port 8080 keep state
        \\pass in quick on epair0a inet proto tcp from any to 10.0.0.5 port 5432 keep state
        \\pass in quick on epair0a inet proto udp from any to any port 53 keep state
        \\pass out quick on epair0a inet proto tcp from 10.0.99.1 to any port 9100 keep state
        \\pass in quick on epair0a inet proto udp from any to any port 514 keep state
        \\pass out quick on epair0a inet proto udp from any to any port 514 keep state
        \\block drop quick on epair0a all
        \\
    , text);
}

test "write: network: none blocks everything" {
    const allocator = std.testing.allocator;
    const text = try rulesText(allocator, &.{"none"});
    defer allocator.free(text);
    try std.testing.expectEqualStrings("block drop quick on epair0a all\n", text);
}

test "unenforceable" {
    const allocator = std.testing.allocator;

    const cases = [_]struct { file: []const u8, ok: bool }{
        .{ .file = "user: auto\n", .ok = true }, // no rules: nothing to enforce
        .{ .file = "network_mode: vnet:epair0b\nnetwork: tcp:443:outbound\n", .ok = true },
        .{ .file = "network: tcp:443:outbound\n", .ok = false }, // inherit
        .{ .file = "network_mode: none\nnetwork: tcp:443:outbound\n", .ok = false },
        .{ .file = "network_mode: vnet:em0\nnetwork: tcp:443:outbound\n", .ok = false },
        .{ .file = "network_mode: vnet:epair0a\nnetwork: tcp:443:outbound\n", .ok = false },
    };
    for (cases) |case| {
        var reader: std.Io.Reader = .fixed(case.file);
        var result = try caps.loadFromReader(allocator, &reader);
        defer result.deinit();
        try std.testing.expectEqual(@as(usize, 0), result.problems.items.len);
        try std.testing.expectEqual(case.ok, unenforceable(&result.caps) == null);
    }
}
