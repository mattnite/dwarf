//! DWARF 5
const std = @import("std");
const Allocator = std.mem.Allocator;
const Endian = std.builtin.Endian;

const dwarf = @This();

pub const line = @import("line.zig");
pub const utilities = @import("utilities.zig");

pub const DebugInfoEntry = struct {
    code: abbrev.Code,
    attributes: []DebugInfoEntry.Attribute,

    pub const Attribute = struct {
        name: dwarf.Attribute(u128),
        value: AttributeValue,
    };

    pub fn from_reader(
        gpa: Allocator,
        reader: *std.Io.Reader,
        cu_hdr: *const CU_Header,
        table: *const dwarf.abbrev.Table,
        endian: Endian,
    ) !?dwarf.DebugInfoEntry {
        const code = try reader.takeLeb128(u128);
        std.log.info("  abbrev_code: {}", .{code});
        if (code == 0) {
            return null;
        }

        var attributes: std.ArrayList(DebugInfoEntry.Attribute) = .{};
        errdefer attributes.deinit(gpa);

        const abbrev_entry = table.get(code) orelse return error.AbbrevEntryNotFound;
        std.log.debug("abbrev_entry: {}", .{abbrev_entry});
        for (abbrev_entry.specifications) |spec| {
            std.log.debug("  reading attr={f} form={f}", .{ spec.name, spec.form });
            var value = try read_attr_value(gpa, reader, cu_hdr.format, spec.form, cu_hdr.address_size, endian);
            defer value.deinit(gpa);
            std.log.debug("    value={}", .{value});
            const name = spec.name;

            try attributes.append(gpa, .{
                .name = name,
                .value = value,
            });
        }

        return dwarf.DebugInfoEntry{
            .code = code,
            .attributes = try attributes.toOwnedSlice(gpa),
        };
    }

    pub fn deinit(d: *DebugInfoEntry, gpa: Allocator) void {
        gpa.free(d.attributes);
    }
};

pub const abbrev = struct {
    pub const Code = u128;
    pub const Tag = dwarf.Tag(u128);
    pub const Table = std.AutoArrayHashMapUnmanaged(Code, Declaration);
    pub const Tables = std.AutoArrayHashMapUnmanaged(usize, Table);
    pub const Specification = struct {
        name: dwarf.Attribute(u128),
        form: dwarf.Form(u128),
    };

    pub const Declaration = struct {
        code: Code,
        tag: abbrev.Tag,
        children: bool,
        specifications: []const Specification,
    };
};

pub const Format = enum {
    @"32-bit",
    @"64-bit",
};

pub const sections: []const []const u8 = &.{
    ".debug_abbrev",
    ".debug_line",
    ".debug_info",
    ".debug_addr",
    ".debug_aranges",
    ".debug_frame",
    ".eh_frame",
    ".debug_line_str",
    ".debug_loc",
    ".debug_loclists",
    ".debug_names",
    ".debug_macinfo",
    ".debug_macro",
    ".debug_pubnames",
    ".debug_pubtypes",
    ".debug_ranges",
    ".debug_rnglists",
    ".debug_str",
    ".debug_str_offsets",
    ".debug_types",
};

pub const CompilationUnitHeader = struct {
    length: u64,
    version: u16,
    unit_type: u8,
    address_size: u8,
    debug_abbrev_offset: u64,
};

pub fn Attribute(comptime T: type) type {
    const dw = std.dwarf;
    return enum(T) {
        /// - Debugging information entry relationship
        sibling = dw.AT.sibling,
        /// - Data object location
        location = dw.AT.location,
        /// - Name of declaration
        /// - Path name of compilation source
        name = dw.AT.name,
        /// - Array row/column ordering
        ordering = dw.AT.ordering,
        /// - Size of a data object or data type in bytes
        byte_size = dw.AT.byte_size,
        bit_offset = dw.AT.bit_offset,
        /// - Size of a base type in bits
        /// - Size of a data member in bits
        bit_size = dw.AT.bit_size,
        element_list = dw.AT.element_list,
        /// - Line number information for unit
        stmt_list = dw.AT.stmt_list,
        /// - Code address or range of addresses
        /// - Base address of scope
        low_pc = dw.AT.low_pc,
        /// - Contiguous range of code addresses
        high_pc = dw.AT.high_pc,
        /// - Programming language
        language = dw.AT.language,
        member = dw.AT.member,
        /// - Discriminant of variant part
        discr = dw.AT.discr,
        /// - Discriminant value
        discr_value = dw.AT.discr_value,
        /// - Visibility of declaration
        visibility = dw.AT.visibility,
        /// - Imported declaration
        /// - Imported unit
        /// - Namespace alias
        /// - Namespace using declaration
        /// - Namespace using directive
        import = dw.AT.import,
        /// - String length of string type
        string_length = dw.AT.string_length,
        /// - Common block usage
        common_reference = dw.AT.common_reference,
        /// - Compilation directory
        comp_dir = dw.AT.comp_dir,
        /// - Compile-time constant function
        /// - Constant object
        /// - Enumeration literal value
        const_value = dw.AT.const_value,
        /// - Template value parameter
        /// - Containing type of pointer to member type
        containing_type = dw.AT.containing_type,
        /// - Default value of parameter
        default_value = dw.AT.default_value,
        /// - Abstract instance
        /// - Inlined subroutine
        @"inline" = dw.AT.@"inline",
        /// - Optional parameter
        is_optional = dw.AT.is_optional,
        lower_bound = dw.AT.lower_bound,
        /// - Compiler identification
        producer = dw.AT.producer,
        /// - Subroutine prototype
        prototyped = dw.AT.prototyped,
        /// - Subroutine return address save location
        return_addr = dw.AT.return_addr,
        /// - Reduced scope of declaration
        start_scope = dw.AT.start_scope,
        /// - Array element stride (of array type)
        /// - Subrange stride (dimension of array type)
        /// - Enumeration stride (dimension of array type)
        bit_stride = dw.AT.bit_stride,
        /// - Upper bound of subrange
        upper_bound = dw.AT.upper_bound,
        /// - Inline instances of inline subprograms
        /// - Out-of-line instances of inline subprograms
        abstract_origin = dw.AT.abstract_origin,
        /// - Access declaration (C++, Ada)
        /// - Accessibility of base or inherited class (C++)
        /// - Accessibility of data member or member function
        accessibility = dw.AT.accessibility,
        /// - Pointer or reference types
        /// - Subroutine or subroutine type
        address_class = dw.AT.address_class,
        /// - Objects or types that are not actually declared in the source
        artificial = dw.AT.artificial,
        /// - Primitive data types of compilation unit
        base_types = dw.AT.base_types,
        /// - Calling convention for subprograms Calling convention for types
        calling_convention = dw.AT.calling_convention,
        /// - Elements of subrange type
        count = dw.AT.count,
        /// - Data member location
        /// - Inherited member location
        data_member_location = dw.AT.data_member_location,
        /// - Column position of source declaration
        decl_column = dw.AT.decl_column,
        /// - File containing source declaration
        decl_file = dw.AT.decl_file,
        /// - Line number of source declaration
        decl_line = dw.AT.decl_line,
        /// - Incomplete, non-defining, or separate entity declaration
        declaration = dw.AT.declaration,
        /// - List of discriminant values
        discr_list = dw.AT.discr_list,
        /// - Encoding of base type
        encoding = dw.AT.encoding,
        /// - External subroutine
        /// - External variable
        external = dw.AT.external,
        /// - Subroutine frame base address
        frame_base = dw.AT.frame_base,
        /// - Friend relationship
        friend = dw.AT.friend,
        /// - Identifier case rule
        identifier_case = dw.AT.identifier_case,
        /// - Macro preprocessor information (legacy) DW_AT_macros (reserved
        ///   for coexistence with DWARF Version 4 and earlier)
        macro_info = dw.AT.macro_info,
        namelist_items = dw.AT.namelist_items,
        /// - Module priority
        priority = dw.AT.priority,
        /// - Addressing information
        segment = dw.AT.segment,
        /// - Incomplete, non-defining, or separate declaration corresponding to a declaration
        specification = dw.AT.specification,
        /// - Location of uplevel frame
        static_link = dw.AT.static_link,
        /// - Type of call site
        /// - Type of string type components
        /// - Type of subroutine return
        /// - Type of declaration
        type = dw.AT.type,
        /// - Member location for pointer to member type
        use_location = dw.AT.use_location,
        /// - Non-constant parameter flag
        variable_parameter = dw.AT.variable_parameter,
        /// - virtuality attribute
        virtuality = dw.AT.virtuality,
        /// - Virtual function vtable slot
        vtable_elem_location = dw.AT.vtable_elem_location,
        /// - Allocation status of types
        allocated = dw.AT.allocated,
        /// - Association status of types
        associated = dw.AT.associated,
        /// - Indirection to actual data
        data_location = dw.AT.data_location,
        /// - Array element stride (of array type)
        /// - Subrange stride (dimension of array type)
        /// - Enumeration stride (dimension of array type)
        byte_stride = dw.AT.byte_stride,
        /// - Entry address of a scope (compilation unit, subprogram, and so on)
        entry_pc = dw.AT.entry_pc,
        /// - Compilation unit uses UTF-8 strings
        use_UTF8 = dw.AT.use_UTF8,
        /// - Previous namespace extension or original namespace
        extension = dw.AT.extension,
        /// - Non-contiguous range of code addresses
        ranges = dw.AT.ranges,
        /// - Target subroutine
        trampoline = dw.AT.trampoline,
        /// - Column position of inlined subroutine call
        /// - Column position of call site of non-inlined call
        call_column = dw.AT.call_column,
        /// - File containing inlined subroutine call
        /// - File containing call site of non-inlined call
        call_file = dw.AT.call_file,
        /// - Line number of inlined subroutine call
        /// - Line containing call site of non-inlined call
        call_line = dw.AT.call_line,
        /// - Artificial name or description
        description = dw.AT.description,
        /// - Binary scale factor for fixed-point type
        binary_scale = dw.AT.binary_scale,
        /// - Decimal scale factor
        decimal_scale = dw.AT.decimal_scale,
        /// - Scale factor for fixed-point type
        small = dw.AT.small,
        /// - Decimal sign representation
        decimal_sign = dw.AT.decimal_sign,
        /// - Digit count for packed decimal or numeric string type
        digit_count = dw.AT.digit_count,
        /// - Picture string for numeric string type
        picture_string = dw.AT.picture_string,
        /// - Mutable property of member data
        mutable = dw.AT.mutable,
        /// - Array bound THREADS scale factor (UPC)
        threads_scaled = dw.AT.threads_scaled,
        /// - Explicit property of member function
        explicit = dw.AT.explicit,
        /// - Object (this, self) pointer of member function
        object_pointer = dw.AT.object_pointer,
        /// - Endianity of data
        endianity = dw.AT.endianity,
        /// - Elemental property of a subroutine
        elemental = dw.AT.elemental,
        /// - Pure property of a subroutine
        pure = dw.AT.pure,
        /// - Recursive property of a subroutine
        recursive = dw.AT.recursive,
        /// - Type signature
        signature = dw.AT.signature,
        /// - Main or starting subprogram
        /// - Unit containing main or starting subprogram
        main_subprogram = dw.AT.main_subprogram,
        /// - Base type bit location
        /// - Data member bit location
        data_bit_offset = dw.AT.data_bit_offset,
        /// - Compile-time constant object
        const_expr = dw.AT.const_expr,
        /// - Type safe enumeration definition
        enum_class = dw.AT.enum_class,
        /// - Object file linkage name of an entity
        linkage_name = dw.AT.linkage_name,
        /// - Size of string length of string type
        string_length_bit_size = dw.AT.string_length_bit_size,
        /// - Size of string length of string type
        string_length_byte_size = dw.AT.string_length_byte_size,
        /// - Dynamic number of array dimensions
        rank = dw.AT.rank,
        /// - Base of string offsets table
        str_offsets_base = dw.AT.str_offsets_base,
        /// - Base offset for address table
        addr_base = dw.AT.addr_base,
        /// - Base offset for range lists
        rnglists_base = dw.AT.rnglists_base,
        /// - Name of split DWARF object file
        dwo_name = dw.AT.dwo_name,
        /// - &-qualified non-static member function (C++)
        reference = dw.AT.reference,
        /// - &&-qualified non-static member function (C++)
        rvalue_reference = dw.AT.rvalue_reference,
        /// - Macro preprocessor information (#define, #undef, and so on in C, C++ and similar languages)
        macros = dw.AT.macros,
        /// - All tail and normal calls in a subprogram are described by call site entries
        call_all_calls = dw.AT.call_all_calls,
        /// - All tail, normal and inlined calls in a subprogram are described by call site and inlined subprogram entries
        call_all_source_calls = dw.AT.call_all_source_calls,
        /// - All tail calls in a subprogram are described by call site entries
        call_all_tail_calls = dw.AT.call_all_tail_calls,
        /// - Return address from a call
        call_return_pc = dw.AT.call_return_pc,
        /// - Argument value passed in a call
        call_value = dw.AT.call_value,
        /// - Subprogram called in a call
        call_origin = dw.AT.call_origin,
        /// - Parameter entry in a call
        call_parameter = dw.AT.call_parameter,
        /// - Address of the call instruction in a call
        call_pc = dw.AT.call_pc,
        /// - Call is a tail call
        call_tail_call = dw.AT.call_tail_call,
        /// - Address of called routine in a call
        call_target = dw.AT.call_target,
        /// - Address of called routine, which may be clobbered, in a call
        call_target_clobbered = dw.AT.call_target_clobbered,
        /// - Address of the value pointed to by an argument passed in a call
        call_data_location = dw.AT.call_data_location,
        /// - Value pointed to by an argument passed in a call
        call_data_value = dw.AT.call_data_value,
        /// - “no return” property of a subprogram
        noreturn = dw.AT.noreturn,
        /// - Non-default alignment of type, subprogram or variable
        alignment = dw.AT.alignment,
        /// - Export (inline) symbols of namespace
        /// - Export symbols of a structure, union or class
        export_symbols = dw.AT.export_symbols,
        /// - Whether a member has been declared as deleted
        deleted = dw.AT.deleted,
        /// - Whether a member function has been declared as default
        defaulted = dw.AT.defaulted,
        /// - Location lists base
        loclists_base = dw.AT.loclists_base,
        lo_user = dw.AT.lo_user,
        hi_user = dw.AT.hi_user,
        MIPS_fde = dw.AT.MIPS_fde,
        MIPS_loop_begin = dw.AT.MIPS_loop_begin,
        MIPS_tail_loop_begin = dw.AT.MIPS_tail_loop_begin,
        MIPS_epilog_begin = dw.AT.MIPS_epilog_begin,
        MIPS_loop_unroll_factor = dw.AT.MIPS_loop_unroll_factor,
        MIPS_software_pipeline_depth = dw.AT.MIPS_software_pipeline_depth,
        MIPS_linkage_name = dw.AT.MIPS_linkage_name,
        MIPS_stride = dw.AT.MIPS_stride,
        MIPS_abstract_name = dw.AT.MIPS_abstract_name,
        MIPS_clone_origin = dw.AT.MIPS_clone_origin,
        MIPS_has_inlines = dw.AT.MIPS_has_inlines,
        sf_names = dw.AT.sf_names,
        src_info = dw.AT.src_info,
        mac_info = dw.AT.mac_info,
        src_coords = dw.AT.src_coords,
        body_begin = dw.AT.body_begin,
        body_end = dw.AT.body_end,
        GNU_vector = dw.AT.GNU_vector,
        GNU_guarded_by = dw.AT.GNU_guarded_by,
        GNU_pt_guarded_by = dw.AT.GNU_pt_guarded_by,
        GNU_guarded = dw.AT.GNU_guarded,
        GNU_pt_guarded = dw.AT.GNU_pt_guarded,
        GNU_locks_excluded = dw.AT.GNU_locks_excluded,
        GNU_exclusive_locks_required = dw.AT.GNU_exclusive_locks_required,
        GNU_shared_locks_required = dw.AT.GNU_shared_locks_required,
        GNU_odr_signature = dw.AT.GNU_odr_signature,
        GNU_template_name = dw.AT.GNU_template_name,
        GNU_call_site_value = dw.AT.GNU_call_site_value,
        GNU_call_site_data_value = dw.AT.GNU_call_site_data_value,
        GNU_call_site_target = dw.AT.GNU_call_site_target,
        GNU_call_site_target_clobbered = dw.AT.GNU_call_site_target_clobbered,
        GNU_tail_call = dw.AT.GNU_tail_call,
        GNU_all_tail_call_sites = dw.AT.GNU_all_tail_call_sites,
        GNU_all_call_sites = dw.AT.GNU_all_call_sites,
        GNU_all_source_call_sites = dw.AT.GNU_all_source_call_sites,
        GNU_macros = dw.AT.GNU_macros,
        GNU_dwo_name = dw.AT.GNU_dwo_name,
        GNU_dwo_id = dw.AT.GNU_dwo_id,
        GNU_ranges_base = dw.AT.GNU_ranges_base,
        GNU_addr_base = dw.AT.GNU_addr_base,
        GNU_pubnames = dw.AT.GNU_pubnames,
        GNU_pubtypes = dw.AT.GNU_pubtypes,
        VMS_rtnbeg_pd_address = dw.AT.VMS_rtnbeg_pd_address,
        use_GNAT_descriptive_type = dw.AT.use_GNAT_descriptive_type,
        GNAT_descriptive_type = dw.AT.GNAT_descriptive_type,
        ZIG_parent = dw.AT.ZIG_parent,
        ZIG_padding = dw.AT.ZIG_padding,
        ZIG_relative_decl = dw.AT.ZIG_relative_decl,
        ZIG_decl_line_relative = dw.AT.ZIG_decl_line_relative,
        ZIG_comptime_value = dw.AT.ZIG_comptime_value,
        ZIG_sentinel = dw.AT.ZIG_sentinel,
        upc_threads_scaled = dw.AT.upc_threads_scaled,
        PGI_lbase = dw.AT.PGI_lbase,
        PGI_soffset = dw.AT.PGI_soffset,
        PGI_lstride = dw.AT.PGI_lstride,
        _,

        pub fn format(at: @This(), writer: *std.Io.Writer) !void {
            inline for (@typeInfo(@This()).@"enum".fields) |field| {
                if (at == @field(@This(), field.name)) {
                    try writer.print("DW_AT_{s}", .{field.name});
                    return;
                }
            }

            try writer.print("DW_AT_<unknown>({})", .{@intFromEnum(at)});
        }
    };
}

pub fn Tag(comptime T: type) type {
    const dw = std.dwarf;
    return enum(T) {
        padding = dw.TAG.padding,
        array_type = dw.TAG.array_type,
        class_type = dw.TAG.class_type,
        entry_point = dw.TAG.entry_point,
        enumeration_type = dw.TAG.enumeration_type,
        formal_parameter = dw.TAG.formal_parameter,
        imported_declaration = dw.TAG.imported_declaration,
        label = dw.TAG.label,
        lexical_block = dw.TAG.lexical_block,
        member = dw.TAG.member,
        pointer_type = dw.TAG.pointer_type,
        reference_type = dw.TAG.reference_type,
        compile_unit = dw.TAG.compile_unit,
        string_type = dw.TAG.string_type,
        structure_type = dw.TAG.structure_type,
        subroutine = dw.TAG.subroutine,
        subroutine_type = dw.TAG.subroutine_type,
        typedef = dw.TAG.typedef,
        union_type = dw.TAG.union_type,
        unspecified_parameters = dw.TAG.unspecified_parameters,
        variant = dw.TAG.variant,
        common_block = dw.TAG.common_block,
        common_inclusion = dw.TAG.common_inclusion,
        inheritance = dw.TAG.inheritance,
        inlined_subroutine = dw.TAG.inlined_subroutine,
        module = dw.TAG.module,
        ptr_to_member_type = dw.TAG.ptr_to_member_type,
        set_type = dw.TAG.set_type,
        subrange_type = dw.TAG.subrange_type,
        with_stmt = dw.TAG.with_stmt,
        access_declaration = dw.TAG.access_declaration,
        base_type = dw.TAG.base_type,
        catch_block = dw.TAG.catch_block,
        const_type = dw.TAG.const_type,
        constant = dw.TAG.constant,
        enumerator = dw.TAG.enumerator,
        file_type = dw.TAG.file_type,
        friend = dw.TAG.friend,
        namelist = dw.TAG.namelist,
        /// Namelist item
        namelist_item = dw.TAG.namelist_item,
        packed_type = dw.TAG.packed_type,
        subprogram = dw.TAG.subprogram,
        template_type_param = dw.TAG.template_type_param,
        template_value_param = dw.TAG.template_value_param,
        thrown_type = dw.TAG.thrown_type,
        try_block = dw.TAG.try_block,
        variant_part = dw.TAG.variant_part,
        variable = dw.TAG.variable,
        volatile_type = dw.TAG.volatile_type,
        dwarf_procedure = dw.TAG.dwarf_procedure,
        restrict_type = dw.TAG.restrict_type,
        interface_type = dw.TAG.interface_type,
        namespace = dw.TAG.namespace,
        imported_module = dw.TAG.imported_module,
        unspecified_type = dw.TAG.unspecified_type,
        partial_unit = dw.TAG.partial_unit,
        imported_unit = dw.TAG.imported_unit,
        condition = dw.TAG.condition,
        shared_type = dw.TAG.shared_type,
        type_unit = dw.TAG.type_unit,
        rvalue_reference_type = dw.TAG.rvalue_reference_type,
        template_alias = dw.TAG.template_alias,
        coarray_type = dw.TAG.coarray_type,
        generic_subrange = dw.TAG.generic_subrange,
        dynamic_type = dw.TAG.dynamic_type,
        atomic_type = dw.TAG.atomic_type,
        call_site = dw.TAG.call_site,
        call_site_parameter = dw.TAG.call_site_parameter,
        skeleton_unit = dw.TAG.skeleton_unit,
        immutable_type = dw.TAG.immutable_type,
        lo_user = dw.TAG.lo_user,
        hi_user = dw.TAG.hi_user,
        MIPS_loop = dw.TAG.MIPS_loop,
        HP_array_descriptor = dw.TAG.HP_array_descriptor,
        HP_Bliss_field = dw.TAG.HP_Bliss_field,
        HP_Bliss_field_set = dw.TAG.HP_Bliss_field_set,
        format_label = dw.TAG.format_label,
        function_template = dw.TAG.function_template,
        class_template = dw.TAG.class_template,
        GNU_BINCL = dw.TAG.GNU_BINCL,
        GNU_EINCL = dw.TAG.GNU_EINCL,
        GNU_template_template_param = dw.TAG.GNU_template_template_param,
        GNU_template_parameter_pack = dw.TAG.GNU_template_parameter_pack,
        GNU_formal_parameter_pack = dw.TAG.GNU_formal_parameter_pack,
        GNU_call_site = dw.TAG.GNU_call_site,
        GNU_call_site_parameter = dw.TAG.GNU_call_site_parameter,
        upc_shared_type = dw.TAG.upc_shared_type,
        upc_strict_type = dw.TAG.upc_strict_type,
        upc_relaxed_type = dw.TAG.upc_relaxed_type,
        PGI_kanji_type = dw.TAG.PGI_kanji_type,
        PGI_interface_block = dw.TAG.PGI_interface_block,
        ZIG_padding = dw.TAG.ZIG_padding,
        ZIG_comptime_value = dw.TAG.ZIG_comptime_value,
        _,

        pub fn format(tag: @This(), writer: *std.Io.Writer) !void {
            inline for (@typeInfo(@This()).@"enum".fields) |field| {
                if (tag == @field(@This(), field.name)) {
                    try writer.print("DW_TAG_{s}", .{field.name});
                    return;
                }
            }

            try writer.print("DW_TAG_<unknown>({})", .{@intFromEnum(tag)});
        }
    };
}

pub fn Form(comptime T: type) type {
    const dw = std.dwarf;
    return enum(T) {
        /// Address of the target machine. The size of the address is encoded
        /// in the compilation unit header
        addr = dw.FORM.addr,
        block2 = dw.FORM.block2,
        block4 = dw.FORM.block4,
        // Fixed-length constant data. Encoded as two bytes
        data2 = dw.FORM.data2,
        // Fixed-length constant data. Encoded as four bytes
        data4 = dw.FORM.data4,
        // Fixed-length constant data. Encoded as eight bytes
        data8 = dw.FORM.data8,
        string = dw.FORM.string,
        block = dw.FORM.block,
        block1 = dw.FORM.block1,
        // Fixed-length constant data. Encoded as single byte
        data1 = dw.FORM.data1,
        flag = dw.FORM.flag,
        sdata = dw.FORM.sdata,
        /// An offset of a null-terminated string found in the .debug_str
        /// section. In 32-bit DWARF it is 4 bytes, in 64-bit it is 8 bytes.
        strp = dw.FORM.strp,
        udata = dw.FORM.udata,
        ref_addr = dw.FORM.ref_addr,
        ref1 = dw.FORM.ref1,
        ref2 = dw.FORM.ref2,
        ref4 = dw.FORM.ref4,
        ref8 = dw.FORM.ref8,
        ref_udata = dw.FORM.ref_udata,
        indirect = dw.FORM.indirect,
        sec_offset = dw.FORM.sec_offset,
        exprloc = dw.FORM.exprloc,
        flag_present = dw.FORM.flag_present,
        strx = dw.FORM.strx,
        /// A zero-based index into an array of addresses in the .debug_addr
        /// section. Index is relative to DW_AT_addr_base attribute of the
        /// compliation unit.
        ///
        /// Representation is ULEB128.
        addrx = dw.FORM.addrx,
        ref_sup4 = dw.FORM.ref_sup4,
        /// An offset of a null-terminated string found in the .debug_str
        /// section of a supplementary object file. In 32-bit DWARF it is 4
        /// bytes, in 64-bit it is 8 bytes.
        strp_sup = dw.FORM.strp_sup,
        data16 = dw.FORM.data16,
        /// An offset of a null-terminated string found in the .debug_line_str
        /// section. In 32-bit DWARF it is 4 bytes, in 64-bit it is 8 bytes.
        line_strp = dw.FORM.line_strp,
        ref_sig8 = dw.FORM.ref_sig8,
        implicit_const = dw.FORM.implicit_const,
        loclistx = dw.FORM.loclistx,
        rnglistx = dw.FORM.rnglistx,
        ref_sup8 = dw.FORM.ref_sup8,
        strx1 = dw.FORM.strx1,
        strx2 = dw.FORM.strx2,
        strx3 = dw.FORM.strx3,
        strx4 = dw.FORM.strx4,
        /// A zero-based index into an array of addresses in the .debug_addr
        /// section. Index is relative to DW_AT_addr_base attribute of the
        /// compliation unit.
        ///
        /// Representation is 1 byte.
        addrx1 = dw.FORM.addrx1,
        /// A zero-based index into an array of addresses in the .debug_addr
        /// section. Index is relative to DW_AT_addr_base attribute of the
        /// compliation unit.
        ///
        /// Representation is 2 bytes.
        addrx2 = dw.FORM.addrx2,
        /// A zero-based index into an array of addresses in the .debug_addr
        /// section. Index is relative to DW_AT_addr_base attribute of the
        /// compliation unit.
        ///
        /// Representation is 3 bytes.
        addrx3 = dw.FORM.addrx3,
        /// A zero-based index into an array of addresses in the .debug_addr
        /// section. Index is relative to DW_AT_addr_base attribute of the
        /// compliation unit.
        ///
        /// Representation is 4 bytes.
        addrx4 = dw.FORM.addrx4,
        GNU_addr_index = dw.FORM.GNU_addr_index,
        GNU_str_index = dw.FORM.GNU_str_index,
        GNU_ref_alt = dw.FORM.GNU_ref_alt,
        GNU_strp_alt = dw.FORM.GNU_strp_alt,
        _,

        pub fn format(form: @This(), writer: *std.Io.Writer) !void {
            inline for (@typeInfo(@This()).@"enum".fields) |field| {
                if (form == @field(@This(), field.name)) {
                    try writer.print("DW_FORM_{s}", .{field.name});
                    return;
                }
            }

            try writer.print("DW_FORM_<unknown>({})", .{@intFromEnum(form)});
        }

        /// This function allocates for variable-length data that is stored
        /// in-line vs. a reference to variable-length data in a debug section.
        pub fn read_value(form: @This(), gpa: Allocator, reader: *std.Io.Reader, fmt: Format, endian: Endian, address_size: u8) !FormValue {
            return switch (form) {
                .data1 => .{ .data1 = try reader.takeInt(u8, endian) },
                .data2 => .{ .data2 = try reader.takeInt(u16, endian) },
                .data4 => .{ .data4 = try reader.takeInt(u32, endian) },
                .data8 => .{ .data8 = try reader.takeInt(u64, endian) },
                .data16 => .{ .data16 = try reader.takeInt(u128, endian) },
                .udata => .{ .udata = try reader.takeLeb128(u128) },
                .sdata => .{ .sdata = try reader.takeLeb128(i128) },
                .strp => .{ .strp = try read_format_usize(reader, fmt, endian) },
                .line_strp => .{ .line_strp = try read_format_usize(reader, fmt, endian) },
                .ref_addr => .{ .ref_addr = try read_format_usize(reader, fmt, endian) },
                .sec_offset => .{ .sec_offset = try read_format_usize(reader, fmt, endian) },
                .rnglistx => .{ .rnglistx = try reader.takeLeb128(u128) },
                .addr => .{ .addr = try reader.takeVarInt(u64, endian, address_size) },
                .flag => .{ .flag = (0 != try reader.takeByte()) },
                .flag_present => .flag_present,
                .exprloc => .{ .exprloc = try read_leb128_prefix_block(gpa, reader) },
                .block1 => .{ .block1 = try read_len_prefix_block(u8, gpa, reader, endian) },
                .block2 => .{ .block2 = try read_len_prefix_block(u16, gpa, reader, endian) },
                .block4 => .{ .block4 = try read_len_prefix_block(u32, gpa, reader, endian) },
                .block => .{ .block = try read_leb128_prefix_block(gpa, reader) },
                .string => .{ .string = try read_immediate_string(gpa, reader) },
                else => {
                    std.log.info("Unimplemented form: {f}", .{form});
                    unreachable;
                },
            };
        }
    };
}

pub const FormValue = union(enum) {
    addr: u64,
    block2: []u8,
    block4: []u8,
    data2: u16,
    data4: u32,
    data8: u64,
    string: []u8,
    block: []u8,
    block1: []u8,
    data1: u8,
    flag: bool,
    sdata: i128,
    strp: u64,
    udata: u128,
    ref_addr: u64,
    ref1: void,
    ref2: void,
    ref4: void,
    ref8: void,
    ref_udata: void,
    indirect: void,
    sec_offset: u64,
    exprloc: []u8,
    flag_present,
    strx: void,
    addrx: void,
    ref_sup4: void,
    strp_sup: u64,
    data16: u128,
    line_strp: u64,
    ref_sig8: void,
    implicit_const: void,
    loclistx: void,
    rnglistx: u128,
    ref_sup8: void,
    strx1: void,
    strx2: void,
    strx3: void,
    strx4: void,
    addrx1: void,
    addrx2: void,
    addrx3: void,
    addrx4: void,
    GNU_addr_index: void,
    GNU_str_index: void,
    GNU_ref_alt: void,
    GNU_strp_alt: void,
};

/// In-memory DIE tree, every tree is expected to have a single root, which is
/// denoted in the ID enum. When you init this datastructure, you give it a
/// root DIE which will correspond to that special value.
pub const DIE_Tree = struct {
    gpa: Allocator,
    cu_hdr: CU_Header,
    entries: std.ArrayList(DIE) = .{},
    attributes: std.MultiArrayList(AttributeEntry) = .{},
    hierarchy: std.MultiArrayList(Hierarchy) = .{},

    pub const ID = enum(u32) {
        root = 0,
        _,
    };

    pub const DIE = struct {
        code: abbrev.Code,
    };

    pub const AttributeEntry = struct {
        entry_id: ID,
        attribute: DebugInfoEntry.Attribute,
    };

    pub const Hierarchy = struct {
        parent: ID,
        child: ID,
    };

    pub fn init(gpa: Allocator, cu_hdr: CU_Header, root: *const DebugInfoEntry) !DIE_Tree {
        var ret = DIE_Tree{
            .gpa = gpa,
            .cu_hdr = cu_hdr,
        };
        errdefer ret.deinit();

        const id = try ret.add_entry_no_parent(root);
        std.debug.assert(id == .root);

        return ret;
    }

    pub fn deinit(t: *DIE_Tree) void {
        t.entries.deinit(t.gpa);
        t.attributes.deinit(t.gpa);
        t.hierarchy.deinit(t.gpa);
    }

    fn add_entry_no_parent(t: *DIE_Tree, entry: *const DebugInfoEntry) !ID {
        const id: ID = @enumFromInt(t.entries.items.len);
        try t.entries.append(t.gpa, .{
            .code = entry.code,
        });

        for (entry.attributes) |attr| {
            try t.attributes.append(t.gpa, .{
                .entry_id = id,
                .attribute = .{
                    .name = attr.name,
                    .value = attr.value,
                },
            });
        }

        return id;
    }

    pub fn add_entry(t: *DIE_Tree, parent_id: ID, entry: *const DebugInfoEntry) !ID {
        const id = try t.add_entry_no_parent(entry);
        try t.hierarchy.append(t.gpa, .{ .parent = parent_id, .child = id });
        return id;
    }

    /// Get attributes of id as non-owned slice
    pub fn get_attributes(t: *const DIE_Tree, id: ID) []const DebugInfoEntry.Attribute {
        const ids = t.attributes.items(.entry_id);

        const start = std.mem.indexOfScalar(ID, ids, id) orelse return &.{};
        const end = (std.mem.lastIndexOfScalar(ID, ids, id) orelse unreachable) + 1;

        const attrs = t.attributes.items(.attribute);
        return attrs[start..end];
    }

    pub fn get_line_program_offset(t: *const DIE_Tree) !?u64 {
        const attrs = t.get_attributes(.root);

        // stmt_list contains the offset into the debug_line
        return for (attrs) |attr| {
            if (attr.name == .stmt_list)
                break switch (attr.value) {
                    .sec_offset => |sec_offset| sec_offset,
                    else => error.InvalidValueForm,
                };
        } else return null;
    }
};

pub fn read_abbrev_tables(gpa: Allocator, abbrev_text: []const u8) !dwarf.abbrev.Tables {
    var reader: std.Io.Reader = .fixed(abbrev_text);
    var tables: dwarf.abbrev.Tables = .{};

    while (true) {
        var table: dwarf.abbrev.Table = .{};
        errdefer table.deinit(gpa);

        const offset = reader.seek;
        if (offset == abbrev_text.len) {
            break;
        }

        while (true) {
            const code = try reader.takeLeb128(u128);
            if (code == 0)
                break;

            const tag: dwarf.abbrev.Tag = @enumFromInt(try reader.takeLeb128(u128));
            const children = try reader.takeByte();

            var specifications: std.ArrayList(dwarf.abbrev.Specification) = .{};
            defer specifications.deinit(gpa);

            std.log.info("code={} tag={f} children={}", .{ code, tag, children });
            while (true) {
                const name: dwarf.Attribute(u128) = @enumFromInt(try reader.takeLeb128(u128));
                const form: dwarf.Form(u128) = @enumFromInt(try reader.takeLeb128(u128));
                if (name == @as(dwarf.Attribute(u128), @enumFromInt(0)) and form == @as(dwarf.Form(u128), @enumFromInt(0)))
                    break;

                std.log.info("  name={f} form={f}", .{ name, form });
                try specifications.append(gpa, .{
                    .name = name,
                    .form = form,
                });
            }

            try table.put(gpa, code, .{
                .code = code,
                .tag = tag,
                .children = (children != 0),
                .specifications = try specifications.toOwnedSlice(gpa),
            });
        }

        std.log.info("abbrev table at offset 0x{X}: {} entries", .{ offset, table.count() });
        try tables.put(gpa, offset, table);
    }

    return tables;
}

// By reading the unit length, you also get the dwarf format
pub const UnitLengthAndFormat = struct { u64, Format };

pub fn read_unit_length_and_format(r: *std.Io.Reader, endian: Endian) !UnitLengthAndFormat {
    const prefix = try r.takeInt(u32, endian);
    return if (prefix == 0xFFFFFFFF)
        .{ try r.takeInt(u64, endian), .@"64-bit" }
    else
        .{ prefix, .@"32-bit" };
}

/// Compilation Unit Header
pub const CU_Header = struct {
    unit_length: u64,
    format: dwarf.Format,
    version: u16,
    unit_type: u8,
    address_size: u8,
    abbrev_offset: u64,

    pub fn from_reader(r: *std.Io.Reader, endian: Endian) !CU_Header {
        const unit_length, const format = try read_unit_length_and_format(r, endian);
        const version = try r.takeInt(u16, endian);
        const unit_type = try r.takeByte();
        const address_size = try r.takeByte();
        const abbrev_offset: u64 = switch (format) {
            .@"32-bit" => try r.takeInt(u32, endian),
            .@"64-bit" => try r.takeInt(u64, endian),
        };

        return CU_Header{
            .unit_length = unit_length,
            .format = format,
            .version = version,
            .unit_type = unit_type,
            .address_size = address_size,
            .abbrev_offset = abbrev_offset,
        };
    }
};

fn recursive_add_dies(
    gpa: Allocator,
    parent_id: DIE_Tree.ID,
    reader: *std.Io.Reader,
    cu_hdr: *const CU_Header,
    table: *const abbrev.Table,
    endian: Endian,
    tree: *DIE_Tree,
) !void {
    while (try DebugInfoEntry.from_reader(gpa, reader, cu_hdr, table, endian)) |die| {
        var die_copy = die;
        defer die_copy.deinit(gpa);

        const id = try tree.add_entry(parent_id, &die);
        const abbrev_entry = table.get(die.code).?;
        if (abbrev_entry.children) {
            try recursive_add_dies(gpa, id, reader, cu_hdr, table, endian, tree);
        }
    }

    std.log.debug("Finished adding children for ID={}", .{parent_id});
}

pub fn read_die_trees(gpa: Allocator, debug_info: []const u8, tables: *const dwarf.abbrev.Tables, endian: Endian) ![]DIE_Tree {
    var reader: std.Io.Reader = .fixed(debug_info);

    var trees: std.ArrayList(DIE_Tree) = .{};
    errdefer {
        for (trees.items) |*tree| tree.deinit();
        trees.deinit(gpa);
    }

    while (true) {
        const cu_hdr = try CU_Header.from_reader(&reader, endian);
        if (cu_hdr.unit_length == 0)
            break;

        std.log.info("cu_hdr: {}", .{cu_hdr});
        const table = tables.get(cu_hdr.abbrev_offset) orelse return error.FailedToFindAbbrevTable;

        const start_offset = reader.seek;
        var cu_reader: std.Io.Reader = .fixed(debug_info[start_offset .. start_offset + cu_hdr.unit_length]);
        _ = try reader.discard(@enumFromInt(cu_hdr.unit_length));

        var root = try DebugInfoEntry.from_reader(gpa, &cu_reader, &cu_hdr, &table, endian) orelse continue;
        defer root.deinit(gpa);

        var tree = try DIE_Tree.init(gpa, cu_hdr, &root);
        errdefer tree.deinit();

        try recursive_add_dies(gpa, .root, &cu_reader, &cu_hdr, &table, endian, &tree);
        try trees.append(gpa, tree);
    }

    return trees.toOwnedSlice(gpa);

    // parse DIEs until abbrev code is 0, that is the last one.
}

pub fn read_format_usize(reader: *std.Io.Reader, format: Format, endian: Endian) !u64 {
    return switch (format) {
        .@"32-bit" => try reader.takeInt(u32, endian),
        .@"64-bit" => try reader.takeInt(u64, endian),
    };
}

fn read_len_prefix_block(comptime T: type, gpa: Allocator, reader: *std.Io.Reader, endian: Endian) ![]u8 {
    const len = try reader.takeInt(T, endian);
    return reader.readAlloc(gpa, len);
}

fn read_leb128_prefix_block(gpa: Allocator, reader: *std.Io.Reader) ![]u8 {
    const len = try reader.takeLeb128(usize);
    return try reader.readAlloc(gpa, len);
}

fn read_immediate_string(gpa: Allocator, reader: *std.Io.Reader) ![]u8 {
    var str: std.ArrayList(u8) = .{};
    while (true) {
        const b = try reader.takeByte();
        if (b == 0)
            break;

        try str.append(gpa, b);
    }

    return try str.toOwnedSlice(gpa);
}

pub const AttributeValue = union(enum) {
    addr: u64,

    address: u64,
    address_index: u64,
    sec_offset: u64,

    constant_unsigned: u128,
    constant_signed: i128,

    string: []const u8,
    debug_line_str_offset: u64,
    debug_str_offset: u64,
    ref_addr: u64,

    addrptr: u64,
    rnglist_index: u128,
    rnglist_offset: u64,

    flag: bool,

    exprloc: []u8,
    block: []u8,

    pub fn deinit(v: *AttributeValue, gpa: Allocator) void {
        switch (v.*) {
            .exprloc => |exprloc| gpa.free(exprloc),
            .block => |block| gpa.free(block),
            else => {},
        }
    }
};

fn read_attr_value(
    gpa: Allocator,
    reader: *std.Io.Reader,
    class: dwarf.Format,
    form: dwarf.Form(u128),
    address_size: u8,
    endian: Endian,
) !AttributeValue {
    return switch (form) {
        .data1 => .{ .constant_unsigned = try reader.takeInt(u8, endian) },
        .data2 => .{ .constant_unsigned = try reader.takeInt(u16, endian) },
        .data4 => .{ .constant_unsigned = try reader.takeInt(u32, endian) },
        .data8 => .{ .constant_unsigned = try reader.takeInt(u64, endian) },
        .data16 => .{ .constant_unsigned = try reader.takeInt(u128, endian) },
        .udata => .{ .constant_unsigned = try reader.takeLeb128(u128) },
        .sdata => .{ .constant_signed = try reader.takeLeb128(i128) },
        .strp => .{ .debug_str_offset = try read_format_usize(reader, class, endian) },
        .line_strp => .{ .debug_line_str_offset = try read_format_usize(reader, class, endian) },
        .ref_addr => .{ .ref_addr = try read_format_usize(reader, class, endian) },
        .sec_offset => .{ .sec_offset = try read_format_usize(reader, class, endian) },
        .rnglistx => .{ .rnglist_index = try reader.takeLeb128(u128) },
        .addr => .{ .address = try reader.takeVarInt(u64, endian, address_size) },
        .flag => .{ .flag = (0 != try reader.takeByte()) },
        .flag_present => .{ .flag = true },
        .exprloc => .{ .exprloc = try read_leb128_prefix_block(gpa, reader) },
        .block1 => .{ .block = try read_len_prefix_block(u8, gpa, reader, endian) },
        .block2 => .{ .block = try read_len_prefix_block(u16, gpa, reader, endian) },
        .block4 => .{ .block = try read_len_prefix_block(u32, gpa, reader, endian) },
        .block => .{ .block = try read_leb128_prefix_block(gpa, reader) },
        .string => .{ .string = try read_immediate_string(gpa, reader) },
        else => {
            std.log.info("Unimplemented form: {f}", .{form});
            unreachable;
        },
    };
}
