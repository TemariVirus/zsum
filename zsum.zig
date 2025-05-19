const std = @import("std");
const Allocator = std.mem.Allocator;

const argsParser = @import("args");
const ArgsError = argsParser.Error;

const runtime_safety = switch (@import("builtin").mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};
var color_output = true;

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

    check_color: {
        const value = std.process.getEnvVarOwned(alloc, "NO_COLOR") catch break :check_color;
        defer alloc.free(value);
        color_output = value.len == 0;
    }
    const stdout = std.io.getStdOut().writer();

    const args = try argsParser.parseForCurrentProcess(
        Args,
        alloc,
        .{ .forward = handleArgsError },
    );
    defer args.deinit();

    if (args.options.help) {
        printHelpAndExit(args);
    }

    const file, const checksum, const is_piped = getPositionalArgs(alloc, args) catch |err|
        switch (err) {
            error.InvalidLength => printLengthMismatchAndExit(args),
            else => return err,
        };
    defer if (checksum) |cs| alloc.free(cs);
    defer if (!is_piped) file.close();

    if (checksum) |cs| {
        if (cs.len != digestLength(args.options.algo)) {
            printLengthMismatchAndExit(args);
        }
    }

    const hash = try hashFile(alloc, file, args.options.algo);
    defer alloc.free(hash);

    if (checksum) |cs| {
        if (std.mem.eql(u8, cs, hash)) {
            try stdout.writeAll("Hashes ");
            try writeColored(stdout, "match", .ok);
            try stdout.writeAll("\n");
        } else {
            try writeColored(stdout, "Mismatch", .err);
            try stdout.writeAll("\n");
            std.process.exit(1);
        }
    } else {
        try stdout.print("{}\n", .{std.fmt.fmtSliceHexLower(hash)});
    }
    std.process.exit(0);
}

fn printHelpAndExit(args: ArgsResult) noreturn {
    const exe_name = std.fs.path.stem(args.executable_name.?);
    argsParser.printHelp(Args, exe_name, std.io.getStdErr().writer()) catch unreachable;
    std.process.exit(1);
}

fn printLengthMismatchAndExit(args: ArgsResult) noreturn {
    const stderr = std.io.getStdErr().writer();
    writeColored(stderr, "Wrong", .err) catch unreachable;
    stderr.print(
        " checksum length. Checksum should be {d} hex digits long.\n",
        .{digestLength(args.options.algo)},
    ) catch unreachable;
    std.process.exit(1);
}

fn handleArgsError(err: ArgsError) !void {
    try std.io.getStdErr().writer().print("{}\n", .{err});
    std.process.exit(1);
}

fn getPositionalArgs(alloc: Allocator, args: ArgsResult) !struct { std.fs.File, ?[]const u8, bool } {
    var file: std.fs.File = undefined;
    var checksum: ?[]u8 = undefined;

    const is_piped = !std.io.getStdIn().isTty();
    if (is_piped) {
        file = std.io.getStdIn();
        checksum = switch (args.positionals.len) {
            0 => null,
            else => try parseHash(alloc, args.positionals[0]),
        };
    } else {
        const file_path = switch (args.positionals.len) {
            0 => printHelpAndExit(args),
            1 => args.positionals[0],
            else => args.positionals[1],
        };
        file = try std.fs.cwd().openFile(file_path, .{});
        errdefer file.close();
        checksum = switch (args.positionals.len) {
            0 => printHelpAndExit(args),
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

fn digestLength(algo: Algo) usize {
    return switch (algo) {
        inline else => |s| s.impl().digest_length,
    };
}

fn hashFile(alloc: Allocator, file: std.fs.File, algo: Algo) ![]u8 {
    return switch (algo) {
        inline else => |s| hashFileAny(s.impl(), alloc, file),
    };
}

fn hashFileAny(Hasher: type, alloc: Allocator, file: std.fs.File) ![]u8 {
    var hasher: Hasher = .init(.{});

    var file_buf: [4096]u8 = undefined;
    while (true) {
        const len = try file.readAll(&file_buf);
        hasher.update(file_buf[0..len]);
        if (len < file_buf.len) break;
    }

    const hash = try alloc.alloc(u8, Hasher.digest_length);
    hasher.final(@ptrCast(hash));
    return hash;
}

fn writeColored(writer: anytype, text: []const u8, status: enum { ok, err }) !void {
    const CSI = "\x1b[";
    const OK = CSI ++ "32m";
    const ERR = CSI ++ "31m";
    const RESET = CSI ++ "39m";

    const color = switch (status) {
        .ok => OK,
        .err => ERR,
    };

    if (color_output) {
        try writer.writeAll(color);
    }
    try writer.writeAll(text);
    if (color_output) {
        try writer.writeAll(RESET);
    }
}

fn writeEnumValues(Enum: type, writer: anytype) !void {
    try writer.writeAll("Supported hashing algorithms:");
    for (@typeInfo(Enum).@"enum".fields) |field| {
        try writer.writeAll("\n  " ++ field.name);
    }
}

fn enumValuesHelp(Enum: type) []const u8 {
    const help_len = blk: {
        var counter = std.io.countingWriter(std.io.null_writer);
        writeEnumValues(Enum, counter.writer()) catch unreachable;
        break :blk counter.bytes_written;
    };

    var buf: [help_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    writeEnumValues(Enum, writer) catch unreachable;

    return fbs.getWritten();
}
