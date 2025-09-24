const std = @import("std");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var stdout = std.fs.File.stdout().writer(&.{});

    _ = args.skip(); // Skip exe name
    const zsum_path = args.next().?;
    std.log.info("zsum: '{s}'", .{zsum_path});
    while (args.next()) |arg| {
        var zsum_proc: std.process.Child = .init(&.{ zsum_path, "--algo", "sha256" }, allocator);
        zsum_proc.stdin_behavior = .Pipe;
        zsum_proc.stdout_behavior = .Pipe;

        try zsum_proc.spawn();
        errdefer {
            _ = zsum_proc.kill() catch {};
        }
        try zsum_proc.waitForSpawn();

        {
            const file = try std.fs.cwd().openFile(arg, .{});
            defer file.close();
            var reader = file.reader(&.{});

            var write_buf: [4096]u8 = undefined;
            var stdin = zsum_proc.stdin.?.writer(&write_buf);
            _ = try stdin.interface.sendFileAll(&reader, .unlimited);
            try stdin.interface.flush();
        }
        zsum_proc.stdin.?.close();
        zsum_proc.stdin = null;

        var poller = std.Io.poll(
            allocator,
            enum { stdout },
            .{ .stdout = zsum_proc.stdout.? },
        );
        defer poller.deinit();
        while (try poller.poll()) {}

        const reader = poller.reader(.stdout);
        const hash = std.mem.trim(
            u8,
            reader.buffered(),
            &std.ascii.whitespace,
        );

        switch (try zsum_proc.wait()) {
            .Exited => |code| switch (code) {
                0 => {},
                else => {
                    std.log.err("zsum exited with code {d}, expected 0", .{code});
                    return error.ProcessError;
                },
            },
            else => |term| {
                std.log.err("zsum failed: {any}", .{term});
                return error.ProcessError;
            },
        }

        std.log.info("{s}    {s}", .{ hash, std.fs.path.basename(arg) });
        try stdout.interface.print("{s}    {s}\n", .{ hash, std.fs.path.basename(arg) });
    }
    try stdout.interface.flush();
}
