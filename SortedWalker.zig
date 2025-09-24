const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.fs.Dir;

stack: std.ArrayListUnmanaged(StackItem),
name_buffer: std.ArrayListUnmanaged(u8),
allocator: Allocator,

const Self = @This();

// Use the same path separator for all platforms for consistent hashing
const path_sep = '/';

const StackItem = struct {
    // Not closed in `deinit`.
    dir: Dir,
    // Always sorted with dirs last, and then by name in descending order
    entry_stack: std.ArrayListUnmanaged(Dir.Entry),
    dirname_len: usize,
    arena: std.heap.ArenaAllocator.State,

    pub fn init(allocator: Allocator, dir: Dir, dirname_len: usize) !StackItem {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        errdefer arena.deinit();

        var entries: std.ArrayListUnmanaged(Dir.Entry) = .empty;
        var it = dir.iterate();
        while (try it.next()) |entry| {
            try entries.append(arena.allocator(), .{
                .kind = entry.kind,
                .name = try arena.allocator().dupe(u8, entry.name),
            });
        }

        std.sort.pdq(Dir.Entry, entries.items, {}, entryDescending);
        return .{
            .dir = dir,
            .entry_stack = entries,
            .dirname_len = dirname_len,
            .arena = arena.state,
        };
    }

    pub fn deinit(self: *StackItem, allocator: Allocator) void {
        const arena = self.arena.promote(allocator);
        arena.deinit();
    }
};

pub const Entry = struct {
    dir: Dir,
    basename: [:0]const u8,
    path: [:0]const u8,
    kind: Dir.Entry.Kind,
};

pub fn init(allocator: Allocator, dir: Dir) !Self {
    var stack: std.ArrayListUnmanaged(StackItem) = .empty;
    errdefer stack.deinit(allocator);

    var first_item: StackItem = try .init(allocator, dir, 0);
    errdefer first_item.deinit(allocator);

    try stack.append(allocator, first_item);
    return .{
        .stack = stack,
        .name_buffer = .empty,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    for (self.stack.items, 0..) |*item, i| {
        if (i > 0) {
            item.dir.close();
        }
        item.deinit(self.allocator);
    }
    self.stack.deinit(self.allocator);
    self.name_buffer.deinit(self.allocator);
    self.* = undefined;
}

pub fn next(self: *Self) !?Entry {
    while (self.stack.items.len > 0) {
        // `top` and `containing` become invalid after appending to `self.stack`
        var top = &self.stack.items[self.stack.items.len - 1];
        const containing = top;
        var dirname_len = top.dirname_len;
        if (top.entry_stack.pop()) |base| {
            self.name_buffer.shrinkRetainingCapacity(dirname_len);
            if (self.name_buffer.items.len > 0) {
                try self.name_buffer.append(self.allocator, path_sep);
                dirname_len += 1;
            }
            try self.name_buffer.ensureUnusedCapacity(self.allocator, base.name.len + 1);
            self.name_buffer.appendSliceAssumeCapacity(base.name);
            self.name_buffer.appendAssumeCapacity(0);

            if (base.kind == .directory) {
                var new_dir = top.dir.openDir(base.name, .{ .iterate = true }) catch |err| switch (err) {
                    error.NameTooLong => unreachable, // no path sep in base.name
                    else => |e| return e,
                };
                {
                    errdefer new_dir.close();
                    var item = try StackItem.init(self.allocator, new_dir, self.name_buffer.items.len - 1);
                    errdefer item.deinit(self.allocator);
                    try self.stack.append(self.allocator, item);
                    top = &self.stack.items[self.stack.items.len - 1];
                    // containing = &self.stack.items[self.stack.items.len - 2];
                }
            }
            return .{
                .dir = containing.dir,
                .basename = self.name_buffer.items[dirname_len .. self.name_buffer.items.len - 1 :0],
                .path = self.name_buffer.items[0 .. self.name_buffer.items.len - 1 :0],
                .kind = base.kind,
            };
        } else {
            var item = self.stack.pop().?;
            if (self.stack.items.len != 0) {
                item.dir.close();
            }
            item.deinit(self.allocator);
        }
    }
    return null;
}

// By name in descending order
fn entryDescending(_: void, a: Dir.Entry, b: Dir.Entry) bool {
    const len = @min(a.name.len, b.name.len);
    const step = @divExact(@bitSizeOf(usize), 8);

    var i: usize = 0;
    while (i + step <= len) : (i += step) {
        const astr = std.mem.readInt(usize, @ptrCast(a.name[i..]), .big);
        const bstr = std.mem.readInt(usize, @ptrCast(b.name[i..]), .big);
        if (astr > bstr) return true;
        if (astr < bstr) return false;
    }
    for (a.name[i..len], b.name[i..len]) |achar, bchar| {
        if (achar > bchar) return true;
        if (achar < bchar) return false;
    }

    return a.name.len > b.name.len;
}
