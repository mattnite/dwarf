const std = @import("std");
const Allocator = std.mem.Allocator;
const Endian = std.builtin.Endian;

const dwarf = @import("root.zig");

pub const StandardOpcode = enum(u8) {
    // This is the value of 0x00, when we see this value, then the opcode value
    // is an unsigned LEB128 value following this byte.
    extended_op = dw.LNS.extended_op,
    /// The DW_LNS_copy opcode takes no operands. It appends a row to the
    /// matrix using the current values of the state machine registers. Then it
    /// sets the discriminator register to 0, and sets the basic_block,
    /// prologue_end and epilogue_begin registers to “false.”
    copy = dw.LNS.copy,
    /// The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand as
    /// the operation advance and modifies the address and op_index registers
    advance_pc = dw.LNS.advance_pc,
    /// The DW_LNS_advance_line opcode takes a single signed LEB128 operand and
    /// adds that value to the line register of the state machine.
    advance_line = dw.LNS.advance_line,
    /// The DW_LNS_set_file opcode takes a single unsigned LEB128 operand and
    /// stores it in the file register of the state machine.
    set_file = dw.LNS.set_file,
    /// The DW_LNS_set_column opcode takes a single unsigned LEB128 operand and
    /// stores it in the column register of the state machine.
    set_column = dw.LNS.set_column,
    /// The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt
    /// register of the state machine to the logical negation of its current
    /// value.
    negate_stmt = dw.LNS.negate_stmt,
    /// The DW_LNS_set_basic_block opcode takes no operands. It sets the
    /// basic_block register of the state machine to “true.”
    set_basic_block = dw.LNS.set_basic_block,
    /// The DW_LNS_const_add_pc opcode takes no operands. It advances the
    /// address and op_index registers by the increments corresponding to
    /// special opcode 255.
    const_add_pc = dw.LNS.const_add_pc,
    /// The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded)
    /// operand and adds it to the address register of the state machine and
    /// sets the op_index register to 0. This is the only standard opcode whose
    /// operand is not a variable length number. It also does not multiply the
    /// operand by the minimum_instruction_length field of the header.
    fixed_advance_pc = dw.LNS.fixed_advance_pc,
    /// The DW_LNS_set_prologue_end opcode takes no operands. It sets the
    /// prologue_end register to “true.”
    set_prologue_end = dw.LNS.set_prologue_end,
    /// The DW_LNS_set_epilogue_begin opcode takes no operands. It sets the
    /// epilogue_begin register to “true.”
    set_epilogue_begin = dw.LNS.set_epilogue_begin,
    /// The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and
    /// stores that value in the isa register of the state machine.
    set_isa = dw.LNS.set_isa,
    _,

    const dw = std.dwarf;

    pub fn format(lns: @This(), writer: *std.Io.Writer) !void {
        inline for (@typeInfo(@This()).@"enum".fields) |field| {
            if (lns == @field(@This(), field.name)) {
                try writer.print("DW_LNS_{s}", .{field.name});
                return;
            }
        }

        try writer.print("DW_LNS_({})", .{@intFromEnum(lns)});
    }
};

pub const ExtendedOpcode = enum(u8) {
    padding = dw.LNE.padding,
    end_sequence = dw.LNE.end_sequence,
    set_address = dw.LNE.set_address,
    define_file = dw.LNE.define_file,
    set_discriminator = dw.LNE.set_discriminator,
    lo_user = dw.LNE.lo_user,
    hi_user = dw.LNE.hi_user,

    // Zig extensions
    ZIG_set_decl = dw.LNE.ZIG_set_decl,
    _,

    const dw = std.dwarf;
    pub fn format(lne: @This(), writer: *std.Io.Writer) !void {
        inline for (@typeInfo(@This()).@"enum".fields) |field| {
            if (lne == @field(@This(), field.name)) {
                try writer.print("DW_LNE_{s}", .{field.name});
                return;
            }
        }

        try writer.print("DW_LNE_({})", .{@intFromEnum(lne)});
    }
};

pub fn ContentType(comptime T: type) type {
    return enum(T) {
        /// Null-terminated string
        ///
        /// If the form is string, the string occurs immediately in containing
        /// directories or file_names fields.
        ///
        /// If the form is line_strp, strp, or strp_sup then the debug string
        /// is found in the .debug_line_str, .debug_str, or supplementary
        /// string section. It's offset occurs immediately in the containing
        /// directories or file_names fields.
        path = dw.LNCT.path,
        /// The unsigned directory index represents an entry in the directories
        /// field of the header.
        ///
        /// This content code is always paired with one of DW_FORM_data1,
        /// DW_FORM_data2 or DW_FORM_udata.
        directory_index = dw.LNCT.directory_index,
        timestamp = dw.LNCT.timestamp,
        size = dw.LNCT.size,
        MD5 = dw.LNCT.MD5,
        lo_user = dw.LNCT.lo_user,
        hi_user = dw.LNCT.hi_user,
        LLVM_source = dw.LNCT.LLVM_source,
        _,

        const dw = std.dwarf;

        pub fn format(lnct: @This(), writer: *std.Io.Writer) !void {
            inline for (@typeInfo(@This()).@"enum".fields) |field| {
                if (lnct == @field(@This(), field.name)) {
                    try writer.print("DW_LNCT_{s}", .{field.name});
                    return;
                }
            }

            try writer.print("DW_LNCT_({})", .{@intFromEnum(lnct)});
        }
    };
}

pub const FormatEntry = struct {
    content_type: ContentType(u128),
    form: dwarf.Form(u128),
};

fn entries_match_known_fmt(
    entries: []const FormatEntry,
    known_fmt: []const ContentType(u128),
) bool {
    if (known_fmt.len != entries.len)
        return false;

    for (known_fmt, entries) |known_fmt_entry, entry|
        if (known_fmt_entry != entry.content_type)
            return false;

    return true;
}

// TODO: make this an optional. We can handle unknown content types as long as
// we handle every form, but we do need to eat each form. For the directory
// table, we will have to make the strings optional there, as keeping the index
// stable is imporant for building the file paths.
fn read_value_string(
    gpa: Allocator,
    reader: *std.Io.Reader,
    entry: FormatEntry,
    directories: []const []const u8,
    line_str: []const u8,
    format: dwarf.Format,
    endian: Endian,
) ![]u8 {
    return switch (entry.content_type) {
        .path => switch (entry.form) {
            .line_strp => blk: {
                const offset = try dwarf.read_format_usize(reader, format, endian);
                var line_str_reader: std.Io.Reader = .fixed(line_str);
                line_str_reader.seek = offset;

                const str_z = try line_str_reader.takeSentinel(0);
                const str = std.mem.span(str_z.ptr);
                const str_copy = try gpa.dupe(u8, str);
                errdefer gpa.free(str_copy);

                std.log.debug("got path: {s}", .{str_copy});
                break :blk str_copy;
            },
            else => {
                std.log.err("Form unhandled: {f}", .{entry.form});
                return error.Unhandled;
            },
        },
        .directory_index => blk: {
            const index: u64 = switch (entry.form) {
                .data1 => try reader.takeByte(),
                .data2 => try reader.takeInt(u16, endian),
                .udata => try reader.takeLeb128(u64),
                else => return error.InvalidForm,
            };

            if (index >= directories.len)
                return error.OutOfBounds;

            break :blk try gpa.dupe(u8, directories[index]);
        },
        .LLVM_source => switch (entry.form) {
            .line_strp => blk: {
                const offset = try dwarf.read_format_usize(reader, format, endian);
                std.log.debug("LLVM_source offset: 0x{X}", .{offset});
                var line_str_reader: std.Io.Reader = .fixed(line_str);
                line_str_reader.seek = offset;

                const str_z = try line_str_reader.takeSentinel(0);
                const str = std.mem.span(str_z.ptr);
                const str_copy = try gpa.dupe(u8, str);
                errdefer gpa.free(str_copy);

                std.log.debug("got path: {s}", .{str_copy});
                break :blk str_copy;
            },
            else => {
                std.log.err("Form unhandled: {f}", .{entry.form});
                return error.Unhandled;
            },
        },
        else => {
            std.log.err("Content type unhandled: {f}", .{entry.content_type});
            return error.Unhandled;
        },
    };
}

fn read_and_format(
    gpa: Allocator,
    reader: *std.Io.Reader,
    entries: []const FormatEntry,
    directories: []const []const u8,
    line_str: []const u8,
    format: dwarf.Format,
    endian: Endian,
) ![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    return if (entries_match_known_fmt(entries, &.{.path}))
        try read_value_string(gpa, reader, entries[0], directories, line_str, format, endian)
    else if (entries_match_known_fmt(entries, &.{ .path, .directory_index, .LLVM_source })) blk: {
        const path = try read_value_string(arena.allocator(), reader, entries[0], directories, line_str, format, endian);
        const directory = try read_value_string(arena.allocator(), reader, entries[1], directories, line_str, format, endian);
        const llvm_source = try read_value_string(arena.allocator(), reader, entries[2], directories, line_str, format, endian);
        std.log.debug("llvm_source: {s}", .{llvm_source});
        break :blk std.fs.path.join(gpa, &.{ directory, path });
    } else blk: {
        std.log.err("unrecognized content type format: {any}", .{entries});
        break :blk error.UnrecognizedContentTypeFormat;
    };
}

fn read_entry_format(gpa: Allocator, reader: *std.Io.Reader, count: u8) ![]FormatEntry {
    var entries: std.ArrayList(FormatEntry) = .{};
    defer entries.deinit(gpa);

    for (0..count) |_| {
        try entries.append(gpa, .{
            .content_type = @enumFromInt(try reader.takeLeb128(u128)),
            .form = @enumFromInt(try reader.takeLeb128(u128)),
        });
    }

    return entries.toOwnedSlice(gpa);
}

fn read_and_format_paths(
    gpa: Allocator,
    reader: *std.Io.Reader,
    format_entries: []const FormatEntry,
    directories: []const []const u8,
    count: u128,
    line_str: []const u8,
    format: dwarf.Format,
    endian: Endian,
) ![][]u8 {
    var paths: std.ArrayList([]u8) = .{};
    defer paths.deinit(gpa);

    errdefer for (paths.items) |path| gpa.free(path);

    for (0..@intCast(count)) |_| {
        const path = try read_and_format(gpa, reader, format_entries, directories, line_str, format, endian);
        try paths.append(gpa, path);
    }

    return paths.toOwnedSlice(gpa);
}

pub const Program = struct {
    pub const Header = struct {
        gpa: Allocator,
        format: dwarf.Format,
        /// The size in bytes of the line number information for this
        /// compilation unit, not including the length field itself
        unit_length: u64,
        version: u16,
        address_size: u8,
        segment_selector_size: u8,
        header_length: u64,
        minimum_instruction_length: u8,
        maximum_operations_per_instruction: u8,
        default_is_stmt: u8,
        line_base: i8,
        line_range: u8,
        opcode_base: u8,
        standard_opcode_lengths: []u8,
        directories: []const []const u8,
        file_names: []const []const u8,

        pub fn from_reader(gpa: Allocator, reader: *std.Io.Reader, line_str: []const u8, endian: Endian) !Header {
            const unit_length, const format = try dwarf.read_unit_length_and_format(reader, endian);
            const version = try reader.takeInt(u16, endian);
            const address_size = try reader.takeByte();
            const segment_selector_size = try reader.takeByte();
            const header_length = try dwarf.read_format_usize(reader, format, endian);
            const minimum_instruction_length = try reader.takeByte();
            const maximum_operations_per_instruction = try reader.takeByte();
            const default_is_stmt = try reader.takeByte();
            const line_base = try reader.takeInt(i8, endian);
            const line_range = try reader.takeByte();
            const opcode_base = try reader.takeByte();
            const standard_opcode_lengths = try reader.readAlloc(gpa, opcode_base - 1);
            errdefer gpa.free(standard_opcode_lengths);

            const directory_entry_format_count = try reader.takeByte();
            std.log.debug("directory_entry_format_count: {}", .{directory_entry_format_count});
            const directory_entry_format = try read_entry_format(gpa, reader, directory_entry_format_count);
            defer gpa.free(directory_entry_format);

            std.log.debug("directory_entry_format: {any}", .{directory_entry_format});

            const directories_count = try reader.takeLeb128(u128);
            std.log.debug("directories_count: {}", .{directories_count});
            const directories = try read_and_format_paths(gpa, reader, directory_entry_format, &.{}, directories_count, line_str, format, endian);
            errdefer {
                for (directories) |path| gpa.free(path);
                gpa.free(directories);
            }

            for (directories) |directory|
                std.log.debug("  directory: {s}", .{directory});

            const file_name_entry_format_count = try reader.takeByte();
            std.log.debug("file_name_entry_format_count: {}", .{file_name_entry_format_count});
            const file_name_entry_format = try read_entry_format(gpa, reader, file_name_entry_format_count);
            defer gpa.free(file_name_entry_format);

            std.log.debug("file_name_entry_format: {any}", .{file_name_entry_format});

            const file_names_count = try reader.takeLeb128(u128);
            std.log.debug("file_names_count: {}", .{file_names_count});
            const file_names = try read_and_format_paths(gpa, reader, file_name_entry_format, directories, file_names_count, line_str, format, endian);
            errdefer {
                for (file_names) |path| gpa.free(path);
                gpa.free(file_names);
            }

            for (file_names) |file_name|
                std.log.debug("  file_name: {s}", .{file_name});

            return Header{
                .gpa = gpa,
                .unit_length = unit_length,
                .format = format,
                .version = version,
                .address_size = address_size,
                .segment_selector_size = segment_selector_size,
                .header_length = header_length,
                .minimum_instruction_length = minimum_instruction_length,
                .maximum_operations_per_instruction = maximum_operations_per_instruction,
                .default_is_stmt = default_is_stmt,
                .line_base = line_base,
                .line_range = line_range,
                .opcode_base = opcode_base,
                .standard_opcode_lengths = standard_opcode_lengths,
                .directories = directories,
                .file_names = file_names,
            };
        }

        pub fn deinit(h: *Header) void {
            for (h.directories) |dir| h.gpa.free(dir);
            for (h.file_names) |file_name| h.gpa.free(file_name);

            h.gpa.free(h.directories);
            h.gpa.free(h.file_names);
            h.gpa.free(h.standard_opcode_lengths);
        }

        pub fn get_program_offset(h: *const Header) u64 {
            var count: u64 = 0;
            // unit_length
            switch (h.format) {
                .@"32-bit" => count += @sizeOf(u32),
                .@"64-bit" => count += @sizeOf(u32) + @sizeOf(u64),
            }

            // version
            count += @sizeOf(u16);
            // address_size
            count += @sizeOf(u8);
            // segment_selector_size
            count += @sizeOf(u8);
            // header_length
            switch (h.format) {
                .@"32-bit" => count += 4,
                .@"64-bit" => count += 8,
            }

            // The program begins `header_length` bytes after the header_length field
            return count + h.header_length;
        }

        pub fn get_program_size(h: *const Header) u64 {
            var header_fields_size: u64 = 0;
            // version
            header_fields_size += @sizeOf(u16);
            // address_size
            header_fields_size += @sizeOf(u8);
            // segment_selector_size
            header_fields_size += @sizeOf(u8);
            // header_length field
            switch (h.format) {
                .@"32-bit" => header_fields_size += @sizeOf(u32),
                .@"64-bit" => header_fields_size += @sizeOf(u64),
            }

            return h.unit_length - header_fields_size - h.header_length;
        }
    };

    pub const StateMachine = struct {
        header: *const Header,

        address: u64,
        op_index: u32,
        file: u32,
        line: u32,
        column: u32,
        isa: u32,
        discriminator: u32,
        is_stmt: bool,
        basic_block: bool,
        end_sequence: bool,
        prologue_end: bool,
        epilogue_begin: bool,

        /// Create state machine, and put it in the initial state as defined by
        /// the standard.
        pub fn init(header: *const Header) StateMachine {
            return StateMachine{
                .header = header,
                .address = 0,
                .op_index = 0,
                .file = 1,
                .line = 1,
                .column = 0,
                .is_stmt = (0 != header.default_is_stmt),
                .basic_block = false,
                .end_sequence = false,
                .prologue_end = false,
                .epilogue_begin = false,
                .isa = 0,
                .discriminator = 0,
            };
        }

        pub const TableEntryResult = union(enum) {
            done,
            entry: TableEntry,
        };

        pub fn execute_insn(sm: *StateMachine, reader: *std.Io.Reader, endian: Endian) !?TableEntryResult {
            // - read opcodes sequentially
            // - for each opcode:
            //   - decode opcode byte
            //   - read any required operands based on opcode type
            //   - execute operation
            //   - if the opcode indicates "push row" emit state as line table entry
            //   - continue until you reach end of the line program

            const program_addr = reader.seek;
            const opcode: dwarf.line.StandardOpcode = @enumFromInt(reader.takeByte() catch |err| {
                if (err == error.EndOfStream)
                    return .done;

                return err;
            });
            std.log.debug("0x{X}: first opcode: {f}", .{ program_addr, opcode });
            switch (opcode) {
                .extended_op => return try sm.execute_extended_insn(reader, endian),
                .copy => {
                    defer {
                        sm.basic_block = false;
                        sm.prologue_end = false;
                        sm.epilogue_begin = false;
                        sm.discriminator = 0;
                    }

                    return .{ .entry = sm.push() };
                },
                .advance_pc => {
                    const operation_advance = try reader.takeLeb128(u32);
                    const old_address = sm.address;
                    const old_op_index = sm.op_index;

                    sm.address += sm.header.minimum_instruction_length *
                        ((sm.op_index + operation_advance) / sm.header.maximum_operations_per_instruction);
                    sm.op_index = (sm.op_index + operation_advance) % sm.header.maximum_operations_per_instruction;

                    std.log.debug("  address += {}", .{sm.address - old_address});
                    std.log.debug("  op_index += {}", .{sm.op_index - old_op_index});
                },
                .advance_line => {
                    const line: i64 = sm.line;
                    const offset = try reader.takeLeb128(i64);
                    const result = line + offset;
                    sm.line = @intCast(result);
                    std.log.debug("  line: {}", .{sm.line});
                },
                .set_file => {
                    sm.file = try reader.takeLeb128(u32);
                    std.log.debug("  set_file: {}", .{sm.file});
                },
                .set_column => {
                    sm.column = try reader.takeLeb128(u32);
                    std.log.debug("  column: {}", .{sm.column});
                },

                .negate_stmt => {
                    sm.is_stmt = !sm.is_stmt;
                    std.log.debug("  stmt: {}", .{sm.is_stmt});
                },
                .const_add_pc => {
                    const operation_advance = (255 - sm.header.opcode_base) / sm.header.line_range;
                    const old_address = sm.address;
                    const old_op_index = sm.op_index;
                    sm.address += sm.header.minimum_instruction_length *
                        ((sm.op_index + operation_advance) / sm.header.maximum_operations_per_instruction);
                    sm.op_index = (sm.op_index + operation_advance) % sm.header.maximum_operations_per_instruction;

                    std.log.debug("  address += 0x{X}", .{sm.address - old_address});
                    std.log.debug("  op_index += {}", .{sm.op_index - old_op_index});
                },
                .set_isa => {
                    sm.isa = try reader.takeLeb128(u32);
                    std.log.debug("  isa: {}", .{sm.isa});
                },
                .fixed_advance_pc => {
                    const offset = try reader.takeInt(u16, endian);
                    sm.address += offset;
                    sm.op_index = 0;
                    std.log.debug("  address: 0x{X}", .{sm.address});
                    std.log.debug("  op_index: 0x{X}", .{sm.op_index});
                },
                .set_prologue_end => sm.prologue_end = true,
                .set_epilogue_begin => sm.epilogue_begin = true,
                .set_basic_block => sm.basic_block = true,

                _ => return sm.execute_special_opcode(@intFromEnum(opcode)),
            }

            return null;
        }

        fn execute_special_opcode(sm: *StateMachine, opcode: u8) TableEntryResult {
            std.debug.assert(opcode >= sm.header.opcode_base);
            const old_address = sm.address;
            const old_op_index = sm.op_index;
            const old_line: i64 = sm.line;

            const adjusted_opcode: u8 = opcode - sm.header.opcode_base;
            const operation_advance = adjusted_opcode / sm.header.line_range;
            sm.address += sm.header.minimum_instruction_length *
                ((sm.op_index + operation_advance) / sm.header.maximum_operations_per_instruction);
            sm.op_index = (sm.op_index + operation_advance) % sm.header.maximum_operations_per_instruction;

            const line_base: i64 = sm.header.line_base;
            const line_range: i64 = sm.header.line_range;
            const line_increment: i32 = @intCast(line_base + @rem(adjusted_opcode, line_range));

            if (line_increment < 0)
                sm.line -= @abs(line_increment)
            else
                sm.line += @abs(line_increment);

            std.log.debug("  address += {}", .{sm.address - old_address});
            std.log.debug("  line += {}", .{@as(i64, sm.line) - old_line});
            std.log.debug("  op_index += {}", .{sm.op_index - old_op_index});

            defer {
                sm.basic_block = false;
                sm.prologue_end = false;
                sm.epilogue_begin = false;
                sm.discriminator = 0;
            }

            return .{ .entry = sm.push() };
        }

        fn execute_extended_insn(sm: *StateMachine, reader: *std.Io.Reader, endian: Endian) !?TableEntryResult {
            const len = try reader.takeLeb128(u64);
            const start_seek = reader.seek;
            defer std.debug.assert(start_seek + len == reader.seek);

            const extended_opcode: dwarf.line.ExtendedOpcode = @enumFromInt(try reader.takeByte());
            std.log.debug("extended_opcode: {f}", .{extended_opcode});

            return switch (extended_opcode) {
                .set_address => blk: {
                    sm.address = try reader.takeVarInt(u64, endian, sm.header.address_size);
                    std.log.debug("  address: 0x{X}", .{sm.address});
                    break :blk null;
                },
                .end_sequence => blk: {
                    sm.end_sequence = true;
                    const entry = sm.push();
                    sm.* = .init(sm.header);
                    break :blk .{ .entry = entry };
                },
                .padding => blk: {
                    try reader.discardAll(len - 1);
                    break :blk null;
                },
                else => blk: {
                    std.log.warn("unhandled extended opcode: {f}", .{extended_opcode});
                    // extended_opcode is included in the length, so subtract it from the discarded bytes
                    try reader.discardAll(len - 1);
                    break :blk null;
                },
            };
        }

        fn push(sm: *const StateMachine) TableEntry {
            return .{
                .address = sm.address,
                .line = sm.line,
                .column = sm.column,
                .file = sm.file,
                .discriminator = sm.discriminator,
                .op_index = sm.op_index,
                .isa = sm.isa,

                .is_stmt = sm.is_stmt,
                .prologue_end = sm.prologue_end,
                .epilogue_begin = sm.epilogue_begin,
                .end_sequence = sm.end_sequence,
            };
        }
    };
};

/// The path is a reference, you do not own it.
pub const TableEntry = struct {
    address: u64,
    line: u32,
    column: u32,
    file: u32,
    isa: u32,
    discriminator: u32,
    op_index: u32,

    // flags
    is_stmt: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    end_sequence: bool,

    pub fn format(te: TableEntry, writer: *std.Io.Writer) !void {
        try writer.print("0x{X} {} {} {} {} {} {}", .{ te.address, te.line, te.column, te.file, te.isa, te.discriminator, te.op_index });
        if (te.is_stmt)
            try writer.print(" is_stmt", .{});
        if (te.prologue_end)
            try writer.print(" prologue_end", .{});
        if (te.epilogue_begin)
            try writer.print(" epilogue_begin", .{});
        if (te.end_sequence)
            try writer.print(" end_sequence", .{});
    }
};

pub const TableBuilder = struct {
    sm: Program.StateMachine,
    reader: *std.Io.Reader,

    pub fn init(header: *const Program.Header, reader: *std.Io.Reader) TableBuilder {
        return TableBuilder{
            .sm = .init(header),
            .reader = reader,
        };
    }

    pub fn next(ltb: *TableBuilder) !?TableEntry {
        return ltb.sm.execute_insn(ltb.reader);
    }
};
