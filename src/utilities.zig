const std = @import("std");
const Endian = std.builtin.Endian;
const Allocator = std.mem.Allocator;

const dwarf = @import("root.zig");

/// This function takes the debug_info section text and reads only the CU headers along with their root DIE entries.
pub const CU_HeaderResult = struct {
    hdr: dwarf.CU_Header,
    root: dwarf.DebugInfoEntry,
};

pub fn get_cu_headers(gpa: Allocator, debug_info: []const u8, tables: *const dwarf.abbrev.Tables, endian: Endian) ![]CU_HeaderResult {
    var reader: std.Io.Reader = .fixed(debug_info);
    var results: std.ArrayList(CU_HeaderResult) = .{};
    defer {
        for (results.items) |*r| r.die.deinit(gpa);
        results.deinit(gpa);
    }

    while (true) {
        const cu_hdr = try dwarf.CU_Header.from_reader(&reader, endian);
        if (cu_hdr.unit_length == 0)
            break;

        std.log.info("cu_hdr: {}", .{cu_hdr});
        const table = tables.get(cu_hdr.abbrev_offset) orelse return error.FailedToFindAbbrevTable;

        const start_offset = reader.seek;
        const cu_reader: std.Io.Reader = .fixed(debug_info[start_offset .. start_offset + cu_hdr.unit_length]);
        _ = try reader.discard(@enumFromInt(cu_hdr.unit_length));
        var root = try dwarf.DebugInfoEntry.from_reader(gpa, &cu_reader, &cu_hdr, &table, endian) orelse continue;
        errdefer root.deinit(gpa);

        try results.append(gpa, .{
            .hdr = cu_hdr,
            .root = root,
        });
    }

    return results.toOwnedSlice(gpa);
}
