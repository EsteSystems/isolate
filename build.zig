const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options - defaults to native, allows cross-compilation
    const target = b.standardTargetOptions(.{});

    // Standard optimization options
    const optimize = b.standardOptimizeOption(.{});

    // Determine if we're building for FreeBSD
    const is_freebsd = target.result.os.tag == .freebsd;

    // Main executable - pure Zig implementation
    const exe = b.addExecutable(.{
        .name = "isolate",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add platform-specific libraries
    // FreeBSD: need libjail for jail API
    if (is_freebsd) {
        exe.linkSystemLibrary("jail");
    }

    // Link libc for system calls
    exe.linkLibC();

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

    // Unit tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (is_freebsd) {
        unit_tests.linkSystemLibrary("jail");
    }
    unit_tests.linkLibC();

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests (separate module)
    const integration_tests = b.addTest(.{
        .root_source_file = b.path("src/tests/integration.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (is_freebsd) {
        integration_tests.linkSystemLibrary("jail");
    }
    integration_tests.linkLibC();

    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_integration_tests.step);

    // Build examples
    const hello_exe = b.addExecutable(.{
        .name = "hello",
        .target = target,
        .optimize = optimize,
    });
    hello_exe.addCSourceFile(.{
        .file = b.path("examples/hello.c"),
        .flags = &.{},
    });
    hello_exe.linkLibC();

    const server_exe = b.addExecutable(.{
        .name = "server",
        .target = target,
        .optimize = optimize,
    });
    server_exe.addCSourceFile(.{
        .file = b.path("examples/server.c"),
        .flags = &.{},
    });
    server_exe.linkLibC();

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
