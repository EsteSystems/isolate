const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options - defaults to native, allows cross-compilation
    const target = b.standardTargetOptions(.{});

    // Standard optimization options
    const optimize = b.standardOptimizeOption(.{});

    // Determine if we're building for FreeBSD
    const is_freebsd = target.result.os.tag == .freebsd;

    // Main module - pure Zig implementation, links libc for system calls
    const isolate_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Add platform-specific libraries
    // FreeBSD: need libjail for jail API
    if (is_freebsd) {
        isolate_mod.linkSystemLibrary("jail", .{});
    }

    const exe = b.addExecutable(.{
        .name = "isolate",
        .root_module = isolate_mod,
    });

    // Install the executable
    b.installArtifact(exe);

    // Create run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Allow passing arguments to the application
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run isolate");
    run_step.dependOn(&run_cmd.step);

    // Unit tests - built from the same module as the executable
    const unit_tests = b.addTest(.{
        .root_module = isolate_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Build examples
    const hello_exe = b.addExecutable(.{
        .name = "hello",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    hello_exe.root_module.addCSourceFile(.{
        .file = b.path("examples/hello.c"),
        .flags = &.{},
    });

    const server_exe = b.addExecutable(.{
        .name = "server",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    server_exe.root_module.addCSourceFile(.{
        .file = b.path("examples/server.c"),
        .flags = &.{},
    });

    // Install examples to zig-out/examples/
    const install_hello = b.addInstallArtifact(hello_exe, .{
        .dest_dir = .{ .override = .{ .custom = "examples" } },
    });
    const install_server = b.addInstallArtifact(server_exe, .{
        .dest_dir = .{ .override = .{ .custom = "examples" } },
    });

    const examples_step = b.step("examples", "Build example programs");
    examples_step.dependOn(&install_hello.step);
    examples_step.dependOn(&install_server.step);

    // All step - build everything
    const all_step = b.step("all", "Build isolate and all examples");
    all_step.dependOn(b.getInstallStep());
    all_step.dependOn(examples_step);
}
