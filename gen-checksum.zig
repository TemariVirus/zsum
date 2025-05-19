const std = @import("std");

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    const stdout = std.io.getStdOut().writer();

    _ = args.skip(); // Skip exe name
    const zsum_path = args.next().?;
    std.log.err("zsum: '{s}'", .{zsum_path});
    while (args.next()) |arg| {
        var zsum_proc: std.process.Child = .init(&.{ zsum_path, "--algo", "sha256" }, allocator);
        zsum_proc.stdin_behavior = .Pipe;
        zsum_proc.stdout_behavior = .Pipe;

        const file = try std.fs.openFileAbsolute(arg, .{});
        defer file.close();

        try zsum_proc.spawn();
        errdefer {
            _ = zsum_proc.kill() catch {};
        }
        try zsum_proc.waitForSpawn();

        try zsum_proc.stdin.?.writeFileAll(file, .{});
        zsum_proc.stdin.?.close();
        zsum_proc.stdin = null;

        var poller = std.io.poll(
            allocator,
            enum { stdout },
            .{ .stdout = zsum_proc.stdout.? },
        );
        defer poller.deinit();
        while (try poller.poll()) {}

        const fifo = poller.fifo(.stdout);
        if (fifo.head != 0) fifo.realign();
        const hash = std.mem.trim(
            u8,
            fifo.buf[0..fifo.count],
            std.ascii.whitespace,
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

        std.log.err("{s}    {s}", .{ hash, std.fs.path.basename(arg) });
        try stdout.print("{s}    {s}\n", .{ hash, std.fs.path.basename(arg) });
    }
}
