const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const args_mod = b.dependency("args", .{}).module("args");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("zsum.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("args", args_mod);

    const exe = b.addExecutable(.{
        .name = "zsum",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run zsum");
    run_step.dependOn(&run_cmd.step);
}
