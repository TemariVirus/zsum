const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

const argsParser = @import("args");
const ArgsError = argsParser.Error;

const SortedWalker = @import("SortedWalker.zig");

const runtime_safety = switch (@import("builtin").mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

var stdout: *Writer = undefined;
var stderr: *Writer = undefined;
var tty_config: std.Io.tty.Config = undefined;

const Algo = enum {
    blake2b_128,
    blake2b_160,
    blake2b_256,
    blake2b_384,
    blake2b_512,
    blake2s_128,
    blake2s_160,
    blake2s_224,
    blake2s_256,
    blake3,
    md5,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,

    pub const MAX_DIGEST_LENGTH = blk: {
        var max: usize = 0;
        for (std.meta.tags(Algo)) |tag| {
            max = @max(max, tag.digestLength());
        }
        break :blk max;
    };

    pub fn impl(algo: Algo) type {
        const hash = std.crypto.hash;
        return switch (algo) {
            .blake2b_128 => hash.blake2.Blake2b(128),
            .blake2b_160 => hash.blake2.Blake2b(160),
            .blake2b_256 => hash.blake2.Blake2b(256),
            .blake2b_384 => hash.blake2.Blake2b(384),
            .blake2b_512 => hash.blake2.Blake2b(512),
            .blake2s_128 => hash.blake2.Blake2s(128),
            .blake2s_160 => hash.blake2.Blake2s(160),
            .blake2s_224 => hash.blake2.Blake2s(224),
            .blake2s_256 => hash.blake2.Blake2s(256),
            .blake3 => hash.Blake3,
            .md5 => hash.Md5,
            .sha1 => hash.Sha1,
            .sha224 => hash.sha2.Sha224,
            .sha256 => hash.sha2.Sha256,
            .sha384 => hash.sha2.Sha384,
            .sha512 => hash.sha2.Sha512,
            .sha3_224 => hash.sha3.Sha3_224,
            .sha3_256 => hash.sha3.Sha3_256,
            .sha3_384 => hash.sha3.Sha3_384,
            .sha3_512 => hash.sha3.Sha3_512,
        };
    }

    pub fn digestLength(algo: Algo) usize {
        return switch (algo) {
            inline else => |s| s.impl().digest_length,
        };
    }
};

const Args = struct {
    algo: Algo = .sha256,
    checksum: ?[]const u8 = null,
    help: bool = false,
    list: bool = false,
    verbose: bool = false,

    pub const shorthands = .{
        .a = "algo",
        .c = "checksum",
        .h = "help",
        .l = "list",
        .v = "verbose",
    };

    pub const meta = .{
        .usage_summary = "[options] PATH",
        .full_text = 
        \\Print the hash of PATH to stdout. If PATH is '-', read from stdin.
        \\
        \\If PATH is a file, hash the contents of the file.
        \\If PATH is a directory, hash the file paths and their contents.
        \\Empty directories and file metadata are ignored.
        \\
        \\
    ++ enumValuesHelp(Algo),

        .option_docs = .{
            .algo = std.fmt.comptimePrint("The hashing algorithm to use (default: {s}).", .{@tagName((Args{}).algo)}),
            .checksum =
            \\The expected hash to check against. If given, no hash will be printed.
            \\                   If the hashes match, exit with code 0. Otherwise, exit with code 1.
            ,
            .help = "Print this help message and exit.",
            .list = "List all files in the directory and their hashes. If given, PATH must be a directory.",
            .verbose = "Print stats to stderr.",
        },
    };
};
const ArgsResult = argsParser.ParseArgsResult(Args, null);

pub fn main() !void {
    var debug_alloc: std.heap.DebugAllocator(.{}) = .init;
    defer if (runtime_safety) {
        _ = debug_alloc.deinit();
    };
    const alloc = if (runtime_safety)
        debug_alloc.allocator()
    else
        std.heap.smp_allocator;

    var stderr_buf: [512]u8 = undefined;
    // Very little data is written to stdout, so buffering is inconsequential
    var stdout_writer = std.fs.File.stdout().writer(&.{});
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
    stdout = &stdout_writer.interface;
    stderr = &stderr_writer.interface;
    tty_config = .detect(.stdout());

    const args = try argsParser.parseForCurrentProcess(
        Args,
        alloc,
        .{ .forward = handleArgsError },
    );
    defer args.deinit();

    if (args.options.help) {
        printErrorAndExit(args, error.HelpFlag);
    }
    if (args.options.list and args.options.checksum != null) {
        printErrorAndExit(args, error.ListChecksumFlagConflict);
    }

    const checksum = if (args.options.checksum) |check|
        parseHash(alloc, check) catch |err| switch (err) {
            error.InvalidLength => printErrorAndExit(args, error.BadChecksumLength),
            error.InvalidCharacter => printErrorAndExit(args, error.BadChecksum),
            error.OutOfMemory => return err,
            error.NoSpaceLeft => unreachable,
        }
    else
        null;
    defer if (checksum) |cs| alloc.free(cs);

    if (checksum) |cs| {
        if (cs.len != args.options.algo.digestLength()) {
            printErrorAndExit(args, error.BadChecksumLength);
        }
    }

    if (args.positionals.len > 0) dir: {
        if (std.mem.eql(u8, "-", args.positionals[0])) {
            break :dir;
        }

        var dir = std.fs.cwd().openDir(args.positionals[0], .{ .iterate = true }) catch |err| switch (err) {
            error.NotDir => break :dir,
            else => return err,
        };
        defer dir.close();

        var walker: SortedWalker = try .init(alloc, dir);
        defer walker.deinit();

        switch (args.options.algo) {
            inline else => |a| try hashDirAndExit(
                a.impl(),
                &walker,
                checksum,
                args.options.list,
                args.options.verbose,
            ),
        }
    }

    const start_nanos = std.time.nanoTimestamp();
    const stdin: std.fs.File = .stdin();
    const is_piped = !stdin.isTty();
    const file: std.fs.File = switch (args.positionals.len) {
        0 => if (is_piped) stdin else printErrorAndExit(args, error.BadArgs),
        else => if (std.mem.eql(u8, "-", args.positionals[0]))
            stdin
        else
            try std.fs.cwd().openFile(args.positionals[0], .{}),
    };
    defer file.close();

    var hash_buf: [Algo.MAX_DIGEST_LENGTH]u8 = undefined;
    const hash, const hashed_bytes = switch (args.options.algo) {
        inline else => |a| try hashFile(a.impl(), file, &hash_buf),
    };
    if (args.options.verbose) {
        printStats(@intCast(hashed_bytes), start_nanos, std.time.nanoTimestamp(), .all) catch {};
        stderr.flush() catch {};
    }
    try printResultAndExit(args.options.checksum, hash);
}

fn printResultAndExit(checksum: ?[]const u8, hash: []const u8) !noreturn {
    if (checksum) |cs| {
        if (std.mem.eql(u8, cs, hash)) {
            try stdout.writeAll("Hashes ");
            try tty_config.setColor(stdout, .green);
            try stdout.writeAll("match");
            try tty_config.setColor(stdout, .reset);
            try stdout.writeAll("\n");
        } else {
            try tty_config.setColor(stdout, .red);
            try stdout.writeAll("Mismatch");
            try tty_config.setColor(stdout, .reset);
            try stdout.writeAll("\n");
            std.process.exit(1);
        }
    } else {
        try stdout.printHex(hash, .lower);
        try stdout.writeAll("\n");
    }
    std.process.exit(0);
}

fn printStats(
    hashed_bytes: u64,
    start_nanos: i128,
    end_nanos: i128,
    mode: enum { all, speed },
) !void {
    const nanoseconds: u64 = @intCast(@max(1, end_nanos - start_nanos));
    // Cast to u128 to avoid overflow when multiplying
    const bytes_per_second = @as(u128, hashed_bytes) * std.time.ns_per_s / nanoseconds;
    switch (mode) {
        .all => try stderr.print(
            "Hashed {Bi:>9.2} in {D:>9} {Bi:>9.2}/s\n",
            .{
                hashed_bytes,
                nanoseconds,
                @as(u64, @intCast(bytes_per_second)),
            },
        ),
        .speed => try stderr.print("{Bi:>9.2}/s", .{@as(u64, @intCast(bytes_per_second))}),
    }
}

fn printErrorAndExit(
    args: ArgsResult,
    err: error{
        BadArgs,
        HelpFlag,
        BadChecksum,
        BadChecksumLength,
        ListChecksumFlagConflict,
    },
) noreturn {
    switch (err) {
        error.BadArgs, error.HelpFlag => {
            const exe_name = std.fs.path.stem(args.executable_name.?);
            argsParser.printHelp(Args, exe_name, stderr) catch {};
        },
        error.BadChecksum => {
            tty_config.setColor(stderr, .red) catch {};
            stderr.writeAll("Bad") catch {};
            tty_config.setColor(stderr, .reset) catch {};
            stderr.writeAll(" checksum. Checksum must be in hexadecimal.\n") catch {};
        },
        error.BadChecksumLength => {
            tty_config.setColor(stderr, .red) catch {};
            stderr.writeAll("Bad") catch {};
            tty_config.setColor(stderr, .reset) catch {};
            stderr.print(
                " checksum length. Checksum must be {d} hex digits long.\n",
                .{2 * args.options.algo.digestLength()},
            ) catch {};
        },
        error.ListChecksumFlagConflict => {
            stderr.writeAll("--list and --check cannot be used together.\n") catch {};
        },
    }
    stderr.flush() catch {};
    std.process.exit(switch (err) {
        error.HelpFlag => 0,
        else => 1,
    });
}

fn handleArgsError(err: ArgsError) !void {
    stderr.print("{f}\n", .{err}) catch {};
    stderr.flush() catch {};
    std.process.exit(1);
}

fn parseHash(alloc: Allocator, hash: []const u8) ![]u8 {
    const bytes = try alloc.alloc(u8, hash.len / 2);
    errdefer alloc.free(bytes);
    return std.fmt.hexToBytes(bytes, hash);
}

fn hashFile(Hasher: type, file: std.fs.File, out: []u8) !struct { []u8, usize } {
    var buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(&.{});
    var hashing: std.Io.Writer.Hashing(Hasher) = .init(&buf);
    const hashed_btyes = try hashing.writer.sendFileAll(&reader, .unlimited);
    try hashing.writer.flush();

    hashing.hasher.final(@ptrCast(out));
    return .{
        out[0..Hasher.digest_length],
        hashed_btyes,
    };
}

fn hashDirAndExit(
    Hasher: type,
    walker: *SortedWalker,
    checksum: ?[]const u8,
    list: bool,
    verbose: bool,
) !noreturn {
    var hash_buf: [Algo.MAX_DIGEST_LENGTH]u8 = undefined;
    var hasher: Hasher = .init(.{});
    const start_nanos = std.time.nanoTimestamp();
    var total_hashed_bytes: u64 = 0;

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .file, .sym_link => {},
            else => continue,
        }

        const file = try entry.dir.openFileZ(entry.basename, .{});
        defer file.close();

        const file_start_nanos = std.time.nanoTimestamp();
        const hash, const hashed_bytes = try hashFile(Hasher, file, &hash_buf);
        total_hashed_bytes += @intCast(hashed_bytes);
        if (verbose) {
            printStats(@intCast(hashed_bytes), file_start_nanos, std.time.nanoTimestamp(), .speed) catch {};
            if (list) {
                // Align with ther path printed to stdout
                stderr.splatByteAll(' ', 2 * Hasher.digest_length - 8) catch {};
            }
            stderr.print(" {s}\n", .{entry.path}) catch {};
            stderr.flush() catch {};
        }
        if (list) {
            try stdout.printHex(hash, .lower);
            try stdout.print("    {s}\n", .{entry.path});
        } else {
            var sub_hasher: Hasher = .init(.{});
            // Include terminating null byte as separator
            sub_hasher.update(entry.path[0..entry.path.len]);
            sub_hasher.update(hash);
            sub_hasher.final(@ptrCast(&hash_buf));
            hasher.update(hash_buf[0..Hasher.digest_length]);
        }
    }

    if (verbose) {
        printStats(total_hashed_bytes, start_nanos, std.time.nanoTimestamp(), .all) catch {};
        stderr.flush() catch {};
    }
    if (!list) {
        hasher.final(@ptrCast(&hash_buf));
        try printResultAndExit(checksum, hash_buf[0..Hasher.digest_length]);
    }
    std.process.exit(0);
}

fn writeEnumValues(Enum: type, writer: *Writer) !void {
    try writer.writeAll("Supported hashing algorithms:");
    for (@typeInfo(Enum).@"enum".fields) |field| {
        try writer.writeAll("\n  " ++ field.name);
    }
}

fn enumValuesHelp(Enum: type) []const u8 {
    const help_text = comptime blk: {
        var counter: std.Io.Writer.Discarding = .init(&.{});
        writeEnumValues(Enum, &counter.writer) catch unreachable;
        const help_len = counter.count;

        var buf: [help_len]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buf);
        writeEnumValues(Enum, &writer) catch unreachable;
        break :blk buf;
    };

    return &help_text;
}
