const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Run step
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("zsum.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{
            .name = "args",
            .module = b.dependency("args", .{}).module("args"),
        }},
    });

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

    // Release step
    const release_step = b.step("release", "Build release binaries");
    const release_install_opts: std.Build.Step.InstallArtifact.Options = .{
        .dest_dir = .{ .override = .{ .custom = "release" } },
    };

    const x86_linux_exe = makeReleaseExe(b, .linux, .x86, "x86-zsum");
    release_step.dependOn(&b.addInstallArtifact(x86_linux_exe, release_install_opts).step);

    const x64_linux_exe = makeReleaseExe(b, .linux, .x86_64, "x86_64-zsum");
    release_step.dependOn(&b.addInstallArtifact(x64_linux_exe, release_install_opts).step);

    const x86_windows_exe = makeReleaseExe(b, .windows, .x86, "x86-zsum");
    release_step.dependOn(&b.addInstallArtifact(x86_windows_exe, release_install_opts).step);

    const x64_windows_exe = makeReleaseExe(b, .windows, .x86_64, "x86_64-zsum");
    release_step.dependOn(&b.addInstallArtifact(x64_windows_exe, release_install_opts).step);

    release_step.dependOn(&b.addInstallFileWithDir(
        getChecksum(b, exe, &.{
            x86_linux_exe,
            x64_linux_exe,
            x86_windows_exe,
            x64_windows_exe,
        }),
        release_install_opts.dest_dir.override,
        "checksums.txt",
    ).step);
}

fn makeReleaseExe(
    b: *std.Build,
    os_tag: std.Target.Os.Tag,
    cpu_arch: std.Target.Cpu.Arch,
    name: []const u8,
) *std.Build.Step.Compile {
    const args_mod = b.dependency("args", .{}).module("args");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("zsum.zig"),
        .target = b.resolveTargetQuery(.{
            .os_tag = os_tag,
            .cpu_arch = cpu_arch,
            .cpu_model = .determined_by_arch_os,
        }),
        .optimize = .ReleaseFast,
        .strip = true,
    });
    exe_mod.addImport("args", args_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = exe_mod,
    });
    return exe;
}

fn getChecksum(
    b: *std.Build,
    zsum_exe: *std.Build.Step.Compile,
    files: []const *std.Build.Step.Compile,
) std.Build.LazyPath {
    const exe = b.addExecutable(.{
        .name = "gen-checksum",
        .root_module = b.createModule(.{
            .root_source_file = b.path("gen-checksum.zig"),
            .target = b.resolveTargetQuery(.{}),
            .optimize = .Debug,
        }),
    });

    const cmd = b.addRunArtifact(exe);
    cmd.addArtifactArg(zsum_exe);
    for (files) |file| {
        cmd.addArtifactArg(file);
    }
    cmd.expectExitCode(0);
    return cmd.captureStdOut();
}
