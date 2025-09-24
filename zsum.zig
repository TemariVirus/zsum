const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

const argsParser = @import("args");
const ArgsError = argsParser.Error;

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
    help: bool = false,

    pub const shorthands = .{
        .a = "algo",
        .h = "help",
    };

    pub const meta = .{
        .usage_summary = "[options] [checksum] file",
        .full_text = 
        \\If checksum is provided, check if the file's hash matches the given checksum.
        \\Otherwise, print the file's hash to stdout.
        \\
        \\file is either a file path or the file's contents piped from stdin.
        \\
        \\
    ++ enumValuesHelp(Algo),

        .option_docs = .{
            .algo = std.fmt.comptimePrint("The hashing algorithm to use (default: {s}).", .{@tagName((Args{}).algo)}),
            .help = "Print this help message and exit.",
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

    var stdout_writer = std.fs.File.stdout().writer(&.{});
    var stderr_writer = std.fs.File.stderr().writer(&.{});
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
        printHelpAndExit(args, .help_flag);
    }

    const file, const checksum, const is_piped = getPositionalArgs(alloc, args) catch |err|
        switch (err) {
            error.InvalidLength => printLengthMismatchAndExit(args),
            else => return err,
        };
    defer if (checksum) |cs| alloc.free(cs);
    defer if (!is_piped) file.close();

    if (checksum) |cs| {
        if (cs.len != args.options.algo.digestLength()) {
            printLengthMismatchAndExit(args);
        }
    }

    const hash = switch (args.options.algo) {
        inline else => |a| try hashFileAny(a.impl(), alloc, file),
    };
    defer alloc.free(hash);

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

fn printHelpAndExit(args: ArgsResult, cause: enum { bad_args, help_flag }) noreturn {
    const exe_name = std.fs.path.stem(args.executable_name.?);
    argsParser.printHelp(Args, exe_name, stderr) catch unreachable;
    std.process.exit(switch (cause) {
        .bad_args => 1,
        .help_flag => 0,
    });
}

fn printLengthMismatchAndExit(args: ArgsResult) noreturn {
    tty_config.setColor(stderr, .red) catch unreachable;
    stderr.writeAll("Wrong") catch unreachable;
    tty_config.setColor(stderr, .reset) catch unreachable;
    stderr.print(
        " checksum length. Checksum should be {d} hex digits long.\n",
        .{2 * args.options.algo.digestLength()},
    ) catch unreachable;
    std.process.exit(1);
}

fn handleArgsError(err: ArgsError) !void {
    try stderr.print("{f}\n", .{err});
    std.process.exit(1);
}

fn getPositionalArgs(alloc: Allocator, args: ArgsResult) !struct { std.fs.File, ?[]const u8, bool } {
    var file: std.fs.File = undefined;
    var checksum: ?[]u8 = undefined;

    const stdin: std.fs.File = .stdin();
    const is_piped = !stdin.isTty();
    if (is_piped) {
        file = stdin;
        checksum = switch (args.positionals.len) {
            0 => null,
            else => try parseHash(alloc, args.positionals[0]),
        };
    } else {
        const file_path = switch (args.positionals.len) {
            0 => printHelpAndExit(args, .bad_args),
            1 => args.positionals[0],
            else => args.positionals[1],
        };
        file = try std.fs.cwd().openFile(file_path, .{});
        errdefer file.close();
        checksum = switch (args.positionals.len) {
            0 => printHelpAndExit(args, .bad_args),
            1 => null,
            else => try parseHash(alloc, args.positionals[0]),
        };
    }

    return .{ file, checksum, is_piped };
}

fn parseHash(alloc: Allocator, hash: []const u8) ![]u8 {
    const bytes = try alloc.alloc(u8, hash.len / 2);
    errdefer alloc.free(bytes);
    return std.fmt.hexToBytes(bytes, hash);
}

fn hashFileAny(Hasher: type, alloc: Allocator, file: std.fs.File) ![]u8 {
    var buf: [64 * 1024]u8 = undefined;
    var reader = file.reader(&.{});
    var hashing: std.Io.Writer.Hashing(Hasher) = .init(&buf);
    _ = try hashing.writer.sendFileAll(&reader, .unlimited);
    try hashing.writer.flush();

    const hash = try alloc.alloc(u8, Hasher.digest_length);
    hashing.hasher.final(@ptrCast(hash));
    return hash;
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
