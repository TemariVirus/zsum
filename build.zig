const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Run step
    const exe = makeExe(b, "zsum", target, optimize, null);
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

    const x86_linux_exe = makeReleaseExe(b, .linux, .x86, "x86-linux-zsum");
    release_step.dependOn(&b.addInstallArtifact(x86_linux_exe, release_install_opts).step);

    const x64_linux_exe = makeReleaseExe(b, .linux, .x86_64, "x86_64-linux-zsum");
    release_step.dependOn(&b.addInstallArtifact(x64_linux_exe, release_install_opts).step);

    const x86_windows_exe = makeReleaseExe(b, .windows, .x86, "x86-windows-zsum");
    release_step.dependOn(&b.addInstallArtifact(x86_windows_exe, release_install_opts).step);

    const x64_windows_exe = makeReleaseExe(b, .windows, .x86_64, "x86_64-windows-zsum");
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

fn getOwnVersion(allocator: std.mem.Allocator) []const u8 {
    const zon = std.zon.parse.fromSlice(
        struct { version: []const u8 },
        allocator,
        @embedFile("build.zig.zon"),
        null,
        .{ .ignore_unknown_fields = true },
    ) catch @panic("Failed to get program version");
    return zon.version;
}

fn makeExe(
    b: *std.Build,
    name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    strip: ?bool,
) *std.Build.Step.Compile {
    const args_mod = b.dependency("args", .{}).module("args");

    const options = b.addOptions();
    options.addOption([]const u8, "version", getOwnVersion(b.allocator));

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("zsum.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
    });
    exe_mod.addImport("args", args_mod);
    exe_mod.addImport("options", options.createModule());

    return b.addExecutable(.{
        .name = name,
        .root_module = exe_mod,
        // TODO: remove the following line when https://github.com/ziglang/zig/issues/25180 is fixed
        .use_llvm = true,
    });
}

fn makeReleaseExe(
    b: *std.Build,
    os_tag: std.Target.Os.Tag,
    cpu_arch: std.Target.Cpu.Arch,
    name: []const u8,
) *std.Build.Step.Compile {
    return makeExe(
        b,
        name,
        b.resolveTargetQuery(.{
            .os_tag = os_tag,
            .cpu_arch = cpu_arch,
            .cpu_model = .determined_by_arch_os,
        }),
        .ReleaseFast,
        true,
    );
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
        // TODO: remove the following line when https://github.com/ziglang/zig/issues/25180 is fixed
        .use_llvm = true,
    });

    const cmd = b.addRunArtifact(exe);
    cmd.addArtifactArg(zsum_exe);
    for (files) |file| {
        cmd.addArtifactArg(file);
    }
    cmd.expectExitCode(0);
    return cmd.captureStdOut();
}
