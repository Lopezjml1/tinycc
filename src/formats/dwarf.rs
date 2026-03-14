//! DWARF (Debug With Arbitrary Record Formats) debug format constants.
//!
//! This module provides DWARF constant definitions translated from the original
//! `TinyCC` `dwarf.h` header (1,046 lines). These constants supplement the `gimli`
//! crate's DWARF support with the complete set of constants used by TCC's debug
//! info generation.
//!
//! The naming convention preserves the standard DWARF constant names from the
//! specification (e.g., `DW_TAG_compile_unit`, `DW_AT_name`) for compatibility
//! with the well-known DWARF standard and the original `TinyCC` C source.
//!
//! C equivalent: `dwarf.h`

// DWARF standard names use mixed-case identifiers matching the specification.
#![allow(non_upper_case_globals)]

// ---------------------------------------------------------------------------
// DWARF Unit Header Types (DWARF 5, Section 7.5.1)
// ---------------------------------------------------------------------------

/// Compilation unit header.
pub(crate) const DW_UT_compile: u8 = 0x01;
/// Type unit header.
pub(crate) const DW_UT_type: u8 = 0x02;
/// Partial unit header.
pub(crate) const DW_UT_partial: u8 = 0x03;
/// Skeleton unit header.
pub(crate) const DW_UT_skeleton: u8 = 0x04;
/// Split compilation unit header.
pub(crate) const DW_UT_split_compile: u8 = 0x05;
/// Split type unit header.
pub(crate) const DW_UT_split_type: u8 = 0x06;
/// Start of user-defined unit types.
pub(crate) const DW_UT_lo_user: u8 = 0x80;
/// End of user-defined unit types.
pub(crate) const DW_UT_hi_user: u8 = 0xff;

// ---------------------------------------------------------------------------
// DWARF Tags (Section 7.5.3)
// ---------------------------------------------------------------------------

pub(crate) const DW_TAG_array_type: u16 = 0x01;
pub(crate) const DW_TAG_class_type: u16 = 0x02;
pub(crate) const DW_TAG_entry_point: u16 = 0x03;
pub(crate) const DW_TAG_enumeration_type: u16 = 0x04;
pub(crate) const DW_TAG_formal_parameter: u16 = 0x05;
pub(crate) const DW_TAG_imported_declaration: u16 = 0x08;
pub(crate) const DW_TAG_label: u16 = 0x0a;
pub(crate) const DW_TAG_lexical_block: u16 = 0x0b;
pub(crate) const DW_TAG_member: u16 = 0x0d;
pub(crate) const DW_TAG_pointer_type: u16 = 0x0f;
pub(crate) const DW_TAG_reference_type: u16 = 0x10;
pub(crate) const DW_TAG_compile_unit: u16 = 0x11;
pub(crate) const DW_TAG_string_type: u16 = 0x12;
pub(crate) const DW_TAG_structure_type: u16 = 0x13;
pub(crate) const DW_TAG_subroutine_type: u16 = 0x15;
pub(crate) const DW_TAG_typedef: u16 = 0x16;
pub(crate) const DW_TAG_union_type: u16 = 0x17;
pub(crate) const DW_TAG_unspecified_parameters: u16 = 0x18;
pub(crate) const DW_TAG_variant: u16 = 0x19;
pub(crate) const DW_TAG_common_block: u16 = 0x1a;
pub(crate) const DW_TAG_common_inclusion: u16 = 0x1b;
pub(crate) const DW_TAG_inheritance: u16 = 0x1c;
pub(crate) const DW_TAG_inlined_subroutine: u16 = 0x1d;
pub(crate) const DW_TAG_module: u16 = 0x1e;
pub(crate) const DW_TAG_ptr_to_member_type: u16 = 0x1f;
pub(crate) const DW_TAG_set_type: u16 = 0x20;
pub(crate) const DW_TAG_subrange_type: u16 = 0x21;
pub(crate) const DW_TAG_with_stmt: u16 = 0x22;
pub(crate) const DW_TAG_access_declaration: u16 = 0x23;
pub(crate) const DW_TAG_base_type: u16 = 0x24;
pub(crate) const DW_TAG_catch_block: u16 = 0x25;
pub(crate) const DW_TAG_const_type: u16 = 0x26;
pub(crate) const DW_TAG_constant: u16 = 0x27;
pub(crate) const DW_TAG_enumerator: u16 = 0x28;
pub(crate) const DW_TAG_file_type: u16 = 0x29;
pub(crate) const DW_TAG_friend: u16 = 0x2a;
pub(crate) const DW_TAG_namelist: u16 = 0x2b;
pub(crate) const DW_TAG_namelist_item: u16 = 0x2c;
pub(crate) const DW_TAG_packed_type: u16 = 0x2d;
pub(crate) const DW_TAG_subprogram: u16 = 0x2e;
pub(crate) const DW_TAG_template_type_parameter: u16 = 0x2f;
pub(crate) const DW_TAG_template_value_parameter: u16 = 0x30;
pub(crate) const DW_TAG_thrown_type: u16 = 0x31;
pub(crate) const DW_TAG_try_block: u16 = 0x32;
pub(crate) const DW_TAG_variant_part: u16 = 0x33;
pub(crate) const DW_TAG_variable: u16 = 0x34;
pub(crate) const DW_TAG_volatile_type: u16 = 0x35;
pub(crate) const DW_TAG_dwarf_procedure: u16 = 0x36;
pub(crate) const DW_TAG_restrict_type: u16 = 0x37;
pub(crate) const DW_TAG_interface_type: u16 = 0x38;
pub(crate) const DW_TAG_namespace: u16 = 0x39;
pub(crate) const DW_TAG_imported_module: u16 = 0x3a;
pub(crate) const DW_TAG_unspecified_type: u16 = 0x3b;
pub(crate) const DW_TAG_partial_unit: u16 = 0x3c;
pub(crate) const DW_TAG_imported_unit: u16 = 0x3d;
pub(crate) const DW_TAG_condition: u16 = 0x3f;
pub(crate) const DW_TAG_shared_type: u16 = 0x40;
/// DWARF 4: Type unit tag.
pub(crate) const DW_TAG_type_unit: u16 = 0x41;
/// DWARF 4: Rvalue reference type.
pub(crate) const DW_TAG_rvalue_reference_type: u16 = 0x42;
/// DWARF 5: Template alias.
pub(crate) const DW_TAG_template_alias: u16 = 0x43;
/// DWARF 5: Coarray type.
pub(crate) const DW_TAG_coarray_type: u16 = 0x44;
/// DWARF 5: Generic subrange.
pub(crate) const DW_TAG_generic_subrange: u16 = 0x45;
/// DWARF 5: Dynamic type.
pub(crate) const DW_TAG_dynamic_type: u16 = 0x46;
/// DWARF 5: Atomic type.
pub(crate) const DW_TAG_atomic_type: u16 = 0x47;
/// DWARF 5: Call site.
pub(crate) const DW_TAG_call_site: u16 = 0x48;
/// DWARF 5: Call site parameter.
pub(crate) const DW_TAG_call_site_parameter: u16 = 0x49;
/// DWARF 5: Skeleton unit.
pub(crate) const DW_TAG_skeleton_unit: u16 = 0x4a;
/// DWARF 5: Immutable type.
pub(crate) const DW_TAG_immutable_type: u16 = 0x4b;

// Vendor / user-defined tag range
pub(crate) const DW_TAG_lo_user: u16 = 0x4080;
pub(crate) const DW_TAG_MIPS_loop: u16 = 0x4081;
pub(crate) const DW_TAG_format_label: u16 = 0x4101;
pub(crate) const DW_TAG_function_template: u16 = 0x4102;
pub(crate) const DW_TAG_class_template: u16 = 0x4103;
pub(crate) const DW_TAG_GNU_BINCL: u16 = 0x4104;
pub(crate) const DW_TAG_GNU_EINCL: u16 = 0x4105;
pub(crate) const DW_TAG_GNU_template_template_param: u16 = 0x4106;
pub(crate) const DW_TAG_GNU_template_parameter_pack: u16 = 0x4107;
pub(crate) const DW_TAG_GNU_formal_parameter_pack: u16 = 0x4108;
pub(crate) const DW_TAG_GNU_call_site: u16 = 0x4109;
pub(crate) const DW_TAG_GNU_call_site_parameter: u16 = 0x410a;
pub(crate) const DW_TAG_hi_user: u16 = 0xffff;

// ---------------------------------------------------------------------------
// Children Determination Encodings (Section 7.5.3)
// ---------------------------------------------------------------------------

/// DIE has no children.
pub(crate) const DW_CHILDREN_NO: u8 = 0;
/// DIE has children.
pub(crate) const DW_CHILDREN_YES: u8 = 1;

// ---------------------------------------------------------------------------
// DWARF Attribute Encodings (Section 7.5.4)
// ---------------------------------------------------------------------------

pub(crate) const DW_AT_sibling: u16 = 0x01;
pub(crate) const DW_AT_location: u16 = 0x02;
pub(crate) const DW_AT_name: u16 = 0x03;
pub(crate) const DW_AT_ordering: u16 = 0x09;
pub(crate) const DW_AT_byte_size: u16 = 0x0b;
/// Deprecated in DWARF 4.
pub(crate) const DW_AT_bit_offset: u16 = 0x0c;
pub(crate) const DW_AT_bit_size: u16 = 0x0d;
pub(crate) const DW_AT_stmt_list: u16 = 0x10;
pub(crate) const DW_AT_low_pc: u16 = 0x11;
pub(crate) const DW_AT_high_pc: u16 = 0x12;
pub(crate) const DW_AT_language: u16 = 0x13;
pub(crate) const DW_AT_discr: u16 = 0x15;
pub(crate) const DW_AT_discr_value: u16 = 0x16;
pub(crate) const DW_AT_visibility: u16 = 0x17;
pub(crate) const DW_AT_import: u16 = 0x18;
pub(crate) const DW_AT_string_length: u16 = 0x19;
pub(crate) const DW_AT_common_reference: u16 = 0x1a;
pub(crate) const DW_AT_comp_dir: u16 = 0x1b;
pub(crate) const DW_AT_const_value: u16 = 0x1c;
pub(crate) const DW_AT_containing_type: u16 = 0x1d;
pub(crate) const DW_AT_default_value: u16 = 0x1e;
pub(crate) const DW_AT_inline: u16 = 0x20;
pub(crate) const DW_AT_is_optional: u16 = 0x21;
pub(crate) const DW_AT_lower_bound: u16 = 0x22;
pub(crate) const DW_AT_producer: u16 = 0x25;
pub(crate) const DW_AT_prototyped: u16 = 0x27;
pub(crate) const DW_AT_return_addr: u16 = 0x2a;
pub(crate) const DW_AT_start_scope: u16 = 0x2c;
pub(crate) const DW_AT_bit_stride: u16 = 0x2e;
pub(crate) const DW_AT_upper_bound: u16 = 0x2f;
pub(crate) const DW_AT_abstract_origin: u16 = 0x31;
pub(crate) const DW_AT_accessibility: u16 = 0x32;
pub(crate) const DW_AT_address_class: u16 = 0x33;
pub(crate) const DW_AT_artificial: u16 = 0x34;
pub(crate) const DW_AT_base_types: u16 = 0x35;
pub(crate) const DW_AT_calling_convention: u16 = 0x36;
pub(crate) const DW_AT_count: u16 = 0x37;
pub(crate) const DW_AT_data_member_location: u16 = 0x38;
pub(crate) const DW_AT_decl_column: u16 = 0x39;
pub(crate) const DW_AT_decl_file: u16 = 0x3a;
pub(crate) const DW_AT_decl_line: u16 = 0x3b;
pub(crate) const DW_AT_declaration: u16 = 0x3c;
pub(crate) const DW_AT_discr_list: u16 = 0x3d;
pub(crate) const DW_AT_encoding: u16 = 0x3e;
pub(crate) const DW_AT_external: u16 = 0x3f;
pub(crate) const DW_AT_frame_base: u16 = 0x40;
pub(crate) const DW_AT_friend: u16 = 0x41;
pub(crate) const DW_AT_identifier_case: u16 = 0x42;
/// Deprecated in DWARF 5.
pub(crate) const DW_AT_macro_info: u16 = 0x43;
pub(crate) const DW_AT_namelist_item: u16 = 0x44;
pub(crate) const DW_AT_priority: u16 = 0x45;
pub(crate) const DW_AT_segment: u16 = 0x46;
pub(crate) const DW_AT_specification: u16 = 0x47;
pub(crate) const DW_AT_static_link: u16 = 0x48;
pub(crate) const DW_AT_type: u16 = 0x49;
pub(crate) const DW_AT_use_location: u16 = 0x4a;
pub(crate) const DW_AT_variable_parameter: u16 = 0x4b;
pub(crate) const DW_AT_virtuality: u16 = 0x4c;
pub(crate) const DW_AT_vtable_elem_location: u16 = 0x4d;
pub(crate) const DW_AT_allocated: u16 = 0x4e;
pub(crate) const DW_AT_associated: u16 = 0x4f;
pub(crate) const DW_AT_data_location: u16 = 0x50;
pub(crate) const DW_AT_byte_stride: u16 = 0x51;
pub(crate) const DW_AT_entry_pc: u16 = 0x52;
pub(crate) const DW_AT_use_UTF8: u16 = 0x53;
pub(crate) const DW_AT_extension: u16 = 0x54;
pub(crate) const DW_AT_ranges: u16 = 0x55;
pub(crate) const DW_AT_trampoline: u16 = 0x56;
pub(crate) const DW_AT_call_column: u16 = 0x57;
pub(crate) const DW_AT_call_file: u16 = 0x58;
pub(crate) const DW_AT_call_line: u16 = 0x59;
pub(crate) const DW_AT_description: u16 = 0x5a;
pub(crate) const DW_AT_binary_scale: u16 = 0x5b;
pub(crate) const DW_AT_decimal_scale: u16 = 0x5c;
pub(crate) const DW_AT_small: u16 = 0x5d;
pub(crate) const DW_AT_decimal_sign: u16 = 0x5e;
pub(crate) const DW_AT_digit_count: u16 = 0x5f;
pub(crate) const DW_AT_picture_string: u16 = 0x60;
pub(crate) const DW_AT_mutable: u16 = 0x61;
pub(crate) const DW_AT_threads_scaled: u16 = 0x62;
pub(crate) const DW_AT_explicit: u16 = 0x63;
pub(crate) const DW_AT_object_pointer: u16 = 0x64;
pub(crate) const DW_AT_endianity: u16 = 0x65;
pub(crate) const DW_AT_elemental: u16 = 0x66;
pub(crate) const DW_AT_pure: u16 = 0x67;
pub(crate) const DW_AT_recursive: u16 = 0x68;
pub(crate) const DW_AT_signature: u16 = 0x69;
pub(crate) const DW_AT_main_subprogram: u16 = 0x6a;
pub(crate) const DW_AT_data_bit_offset: u16 = 0x6b;
pub(crate) const DW_AT_const_expr: u16 = 0x6c;
pub(crate) const DW_AT_enum_class: u16 = 0x6d;
pub(crate) const DW_AT_linkage_name: u16 = 0x6e;
pub(crate) const DW_AT_string_length_bit_size: u16 = 0x6f;
pub(crate) const DW_AT_string_length_byte_size: u16 = 0x70;
pub(crate) const DW_AT_rank: u16 = 0x71;
pub(crate) const DW_AT_str_offsets_base: u16 = 0x72;
pub(crate) const DW_AT_addr_base: u16 = 0x73;
pub(crate) const DW_AT_rnglists_base: u16 = 0x74;
pub(crate) const DW_AT_dwo_name: u16 = 0x76;
pub(crate) const DW_AT_reference: u16 = 0x77;
pub(crate) const DW_AT_rvalue_reference: u16 = 0x78;
pub(crate) const DW_AT_macros: u16 = 0x79;
pub(crate) const DW_AT_call_all_calls: u16 = 0x7a;
pub(crate) const DW_AT_call_all_source_calls: u16 = 0x7b;
pub(crate) const DW_AT_call_all_tail_calls: u16 = 0x7c;
pub(crate) const DW_AT_call_return_pc: u16 = 0x7d;
pub(crate) const DW_AT_call_value: u16 = 0x7e;
pub(crate) const DW_AT_call_origin: u16 = 0x7f;
pub(crate) const DW_AT_call_parameter: u16 = 0x80;
pub(crate) const DW_AT_call_pc: u16 = 0x81;
pub(crate) const DW_AT_call_tail_call: u16 = 0x82;
pub(crate) const DW_AT_call_target: u16 = 0x83;
pub(crate) const DW_AT_call_target_clobbered: u16 = 0x84;
pub(crate) const DW_AT_call_data_location: u16 = 0x85;
pub(crate) const DW_AT_call_data_value: u16 = 0x86;
pub(crate) const DW_AT_noreturn: u16 = 0x87;
pub(crate) const DW_AT_alignment: u16 = 0x88;
pub(crate) const DW_AT_export_symbols: u16 = 0x89;
pub(crate) const DW_AT_deleted: u16 = 0x8a;
pub(crate) const DW_AT_defaulted: u16 = 0x8b;
pub(crate) const DW_AT_loclists_base: u16 = 0x8c;

// Vendor / user-defined attribute range
pub(crate) const DW_AT_lo_user: u16 = 0x2000;

// MIPS extensions
pub(crate) const DW_AT_MIPS_fde: u16 = 0x2001;
pub(crate) const DW_AT_MIPS_loop_begin: u16 = 0x2002;
pub(crate) const DW_AT_MIPS_tail_loop_begin: u16 = 0x2003;
pub(crate) const DW_AT_MIPS_epilog_begin: u16 = 0x2004;
pub(crate) const DW_AT_MIPS_loop_unroll_factor: u16 = 0x2005;
pub(crate) const DW_AT_MIPS_software_pipeline_depth: u16 = 0x2006;
pub(crate) const DW_AT_MIPS_linkage_name: u16 = 0x2007;
pub(crate) const DW_AT_MIPS_stride: u16 = 0x2008;
pub(crate) const DW_AT_MIPS_abstract_name: u16 = 0x2009;
pub(crate) const DW_AT_MIPS_clone_origin: u16 = 0x200a;
pub(crate) const DW_AT_MIPS_has_inlines: u16 = 0x200b;
pub(crate) const DW_AT_MIPS_stride_byte: u16 = 0x200c;
pub(crate) const DW_AT_MIPS_stride_elem: u16 = 0x200d;
pub(crate) const DW_AT_MIPS_ptr_dopetype: u16 = 0x200e;
pub(crate) const DW_AT_MIPS_allocatable_dopetype: u16 = 0x200f;
pub(crate) const DW_AT_MIPS_assumed_shape_dopetype: u16 = 0x2010;
pub(crate) const DW_AT_MIPS_assumed_size: u16 = 0x2011;

// GNU extensions
pub(crate) const DW_AT_sf_names: u16 = 0x2101;
pub(crate) const DW_AT_src_info: u16 = 0x2102;
pub(crate) const DW_AT_mac_info: u16 = 0x2103;
pub(crate) const DW_AT_src_coords: u16 = 0x2104;
pub(crate) const DW_AT_body_begin: u16 = 0x2105;
pub(crate) const DW_AT_body_end: u16 = 0x2106;
pub(crate) const DW_AT_GNU_vector: u16 = 0x2107;
pub(crate) const DW_AT_GNU_guarded_by: u16 = 0x2108;
pub(crate) const DW_AT_GNU_pt_guarded_by: u16 = 0x2109;
pub(crate) const DW_AT_GNU_guarded: u16 = 0x210a;
pub(crate) const DW_AT_GNU_pt_guarded: u16 = 0x210b;
pub(crate) const DW_AT_GNU_locks_excluded: u16 = 0x210c;
pub(crate) const DW_AT_GNU_exclusive_locks_required: u16 = 0x210d;
pub(crate) const DW_AT_GNU_shared_locks_required: u16 = 0x210e;
pub(crate) const DW_AT_GNU_odr_signature: u16 = 0x210f;
pub(crate) const DW_AT_GNU_template_name: u16 = 0x2110;
pub(crate) const DW_AT_GNU_call_site_value: u16 = 0x2111;
pub(crate) const DW_AT_GNU_call_site_data_value: u16 = 0x2112;
pub(crate) const DW_AT_GNU_call_site_target: u16 = 0x2113;
pub(crate) const DW_AT_GNU_call_site_target_clobbered: u16 = 0x2114;
pub(crate) const DW_AT_GNU_tail_call: u16 = 0x2115;
pub(crate) const DW_AT_GNU_all_tail_call_sites: u16 = 0x2116;
pub(crate) const DW_AT_GNU_all_call_sites: u16 = 0x2117;
pub(crate) const DW_AT_GNU_all_source_call_sites: u16 = 0x2118;
pub(crate) const DW_AT_GNU_macros: u16 = 0x2119;
pub(crate) const DW_AT_GNU_deleted: u16 = 0x211a;

// GNU Debug Fission extensions
pub(crate) const DW_AT_GNU_dwo_name: u16 = 0x2130;
pub(crate) const DW_AT_GNU_dwo_id: u16 = 0x2131;
pub(crate) const DW_AT_GNU_ranges_base: u16 = 0x2132;
pub(crate) const DW_AT_GNU_addr_base: u16 = 0x2133;
pub(crate) const DW_AT_GNU_pubnames: u16 = 0x2134;
pub(crate) const DW_AT_GNU_pubtypes: u16 = 0x2135;
pub(crate) const DW_AT_GNU_locviews: u16 = 0x2137;
pub(crate) const DW_AT_GNU_entry_view: u16 = 0x2138;

// GNU numerator/denominator/bias extensions
pub(crate) const DW_AT_GNU_numerator: u16 = 0x2303;
pub(crate) const DW_AT_GNU_denominator: u16 = 0x2304;
pub(crate) const DW_AT_GNU_bias: u16 = 0x2305;

pub(crate) const DW_AT_hi_user: u16 = 0x3fff;

// DWARF1 compatibility (old unofficial attribute names)
pub(crate) const DW_AT_subscr_data: u16 = 0x0a;
pub(crate) const DW_AT_element_list: u16 = 0x0f;
/// DWARF1: reference for variable to member structure, class or union.
pub(crate) const DW_AT_member: u16 = 0x14;

// ---------------------------------------------------------------------------
// DWARF Form Encodings (Section 7.5.5)
// ---------------------------------------------------------------------------

pub(crate) const DW_FORM_addr: u16 = 0x01;
pub(crate) const DW_FORM_block2: u16 = 0x03;
pub(crate) const DW_FORM_block4: u16 = 0x04;
pub(crate) const DW_FORM_data2: u16 = 0x05;
pub(crate) const DW_FORM_data4: u16 = 0x06;
pub(crate) const DW_FORM_data8: u16 = 0x07;
pub(crate) const DW_FORM_string: u16 = 0x08;
pub(crate) const DW_FORM_block: u16 = 0x09;
pub(crate) const DW_FORM_block1: u16 = 0x0a;
pub(crate) const DW_FORM_data1: u16 = 0x0b;
pub(crate) const DW_FORM_flag: u16 = 0x0c;
pub(crate) const DW_FORM_sdata: u16 = 0x0d;
pub(crate) const DW_FORM_strp: u16 = 0x0e;
pub(crate) const DW_FORM_udata: u16 = 0x0f;
pub(crate) const DW_FORM_ref_addr: u16 = 0x10;
pub(crate) const DW_FORM_ref1: u16 = 0x11;
pub(crate) const DW_FORM_ref2: u16 = 0x12;
pub(crate) const DW_FORM_ref4: u16 = 0x13;
pub(crate) const DW_FORM_ref8: u16 = 0x14;
pub(crate) const DW_FORM_ref_udata: u16 = 0x15;
pub(crate) const DW_FORM_indirect: u16 = 0x16;
/// DWARF 4: Section offset.
pub(crate) const DW_FORM_sec_offset: u16 = 0x17;
/// DWARF 4: Expression location.
pub(crate) const DW_FORM_exprloc: u16 = 0x18;
/// DWARF 4: Flag present (no data).
pub(crate) const DW_FORM_flag_present: u16 = 0x19;
/// DWARF 5: String index.
pub(crate) const DW_FORM_strx: u16 = 0x1a;
/// DWARF 5: Address index.
pub(crate) const DW_FORM_addrx: u16 = 0x1b;
/// DWARF 5: Reference in supplementary object file.
pub(crate) const DW_FORM_ref_sup4: u16 = 0x1c;
/// DWARF 5: String in supplementary object file.
pub(crate) const DW_FORM_strp_sup: u16 = 0x1d;
/// DWARF 5: 16-byte data.
pub(crate) const DW_FORM_data16: u16 = 0x1e;
/// DWARF 5: Offset in .`debug_line_str` section.
pub(crate) const DW_FORM_line_strp: u16 = 0x1f;
/// DWARF 4: Type signature reference.
pub(crate) const DW_FORM_ref_sig8: u16 = 0x20;
/// DWARF 5: Implicit constant.
pub(crate) const DW_FORM_implicit_const: u16 = 0x21;
/// DWARF 5: Location list index.
pub(crate) const DW_FORM_loclistx: u16 = 0x22;
/// DWARF 5: Range list index.
pub(crate) const DW_FORM_rnglistx: u16 = 0x23;
/// DWARF 5: 8-byte supplementary reference.
pub(crate) const DW_FORM_ref_sup8: u16 = 0x24;
/// DWARF 5: 1-byte string index.
pub(crate) const DW_FORM_strx1: u16 = 0x25;
/// DWARF 5: 2-byte string index.
pub(crate) const DW_FORM_strx2: u16 = 0x26;
/// DWARF 5: 3-byte string index.
pub(crate) const DW_FORM_strx3: u16 = 0x27;
/// DWARF 5: 4-byte string index.
pub(crate) const DW_FORM_strx4: u16 = 0x28;
/// DWARF 5: 1-byte address index.
pub(crate) const DW_FORM_addrx1: u16 = 0x29;
/// DWARF 5: 2-byte address index.
pub(crate) const DW_FORM_addrx2: u16 = 0x2a;
/// DWARF 5: 3-byte address index.
pub(crate) const DW_FORM_addrx3: u16 = 0x2b;
/// DWARF 5: 4-byte address index.
pub(crate) const DW_FORM_addrx4: u16 = 0x2c;

// GNU Debug Fission extensions
pub(crate) const DW_FORM_GNU_addr_index: u16 = 0x1f01;
pub(crate) const DW_FORM_GNU_str_index: u16 = 0x1f02;
/// Offset in alternate .debuginfo.
pub(crate) const DW_FORM_GNU_ref_alt: u16 = 0x1f20;
/// Offset in alternate .`debug_str`.
pub(crate) const DW_FORM_GNU_strp_alt: u16 = 0x1f21;

// ---------------------------------------------------------------------------
// DWARF Location Operation Encodings (Section 7.7)
// ---------------------------------------------------------------------------

/// Constant address.
pub(crate) const DW_OP_addr: u8 = 0x03;
pub(crate) const DW_OP_deref: u8 = 0x06;
/// Unsigned 1-byte constant.
pub(crate) const DW_OP_const1u: u8 = 0x08;
/// Signed 1-byte constant.
pub(crate) const DW_OP_const1s: u8 = 0x09;
/// Unsigned 2-byte constant.
pub(crate) const DW_OP_const2u: u8 = 0x0a;
/// Signed 2-byte constant.
pub(crate) const DW_OP_const2s: u8 = 0x0b;
/// Unsigned 4-byte constant.
pub(crate) const DW_OP_const4u: u8 = 0x0c;
/// Signed 4-byte constant.
pub(crate) const DW_OP_const4s: u8 = 0x0d;
/// Unsigned 8-byte constant.
pub(crate) const DW_OP_const8u: u8 = 0x0e;
/// Signed 8-byte constant.
pub(crate) const DW_OP_const8s: u8 = 0x0f;
/// Unsigned LEB128 constant.
pub(crate) const DW_OP_constu: u8 = 0x10;
/// Signed LEB128 constant.
pub(crate) const DW_OP_consts: u8 = 0x11;
pub(crate) const DW_OP_dup: u8 = 0x12;
pub(crate) const DW_OP_drop: u8 = 0x13;
pub(crate) const DW_OP_over: u8 = 0x14;
/// 1-byte stack index.
pub(crate) const DW_OP_pick: u8 = 0x15;
pub(crate) const DW_OP_swap: u8 = 0x16;
pub(crate) const DW_OP_rot: u8 = 0x17;
pub(crate) const DW_OP_xderef: u8 = 0x18;
pub(crate) const DW_OP_abs: u8 = 0x19;
pub(crate) const DW_OP_and: u8 = 0x1a;
pub(crate) const DW_OP_div: u8 = 0x1b;
pub(crate) const DW_OP_minus: u8 = 0x1c;
pub(crate) const DW_OP_mod: u8 = 0x1d;
pub(crate) const DW_OP_mul: u8 = 0x1e;
pub(crate) const DW_OP_neg: u8 = 0x1f;
pub(crate) const DW_OP_not: u8 = 0x20;
pub(crate) const DW_OP_or: u8 = 0x21;
pub(crate) const DW_OP_plus: u8 = 0x22;
/// Unsigned LEB128 addend.
pub(crate) const DW_OP_plus_uconst: u8 = 0x23;
pub(crate) const DW_OP_shl: u8 = 0x24;
pub(crate) const DW_OP_shr: u8 = 0x25;
pub(crate) const DW_OP_shra: u8 = 0x26;
pub(crate) const DW_OP_xor: u8 = 0x27;
/// Branch: signed 2-byte constant offset.
pub(crate) const DW_OP_bra: u8 = 0x28;
pub(crate) const DW_OP_eq: u8 = 0x29;
pub(crate) const DW_OP_ge: u8 = 0x2a;
pub(crate) const DW_OP_gt: u8 = 0x2b;
pub(crate) const DW_OP_le: u8 = 0x2c;
pub(crate) const DW_OP_lt: u8 = 0x2d;
pub(crate) const DW_OP_ne: u8 = 0x2e;
/// Skip: signed 2-byte constant offset.
pub(crate) const DW_OP_skip: u8 = 0x2f;

// Literal encodings: DW_OP_lit0 through DW_OP_lit31 (0x30 - 0x4f)
pub(crate) const DW_OP_lit0: u8 = 0x30;
pub(crate) const DW_OP_lit1: u8 = 0x31;
pub(crate) const DW_OP_lit2: u8 = 0x32;
pub(crate) const DW_OP_lit3: u8 = 0x33;
pub(crate) const DW_OP_lit4: u8 = 0x34;
pub(crate) const DW_OP_lit5: u8 = 0x35;
pub(crate) const DW_OP_lit6: u8 = 0x36;
pub(crate) const DW_OP_lit7: u8 = 0x37;
pub(crate) const DW_OP_lit8: u8 = 0x38;
pub(crate) const DW_OP_lit9: u8 = 0x39;
pub(crate) const DW_OP_lit10: u8 = 0x3a;
pub(crate) const DW_OP_lit11: u8 = 0x3b;
pub(crate) const DW_OP_lit12: u8 = 0x3c;
pub(crate) const DW_OP_lit13: u8 = 0x3d;
pub(crate) const DW_OP_lit14: u8 = 0x3e;
pub(crate) const DW_OP_lit15: u8 = 0x3f;
pub(crate) const DW_OP_lit16: u8 = 0x40;
pub(crate) const DW_OP_lit17: u8 = 0x41;
pub(crate) const DW_OP_lit18: u8 = 0x42;
pub(crate) const DW_OP_lit19: u8 = 0x43;
pub(crate) const DW_OP_lit20: u8 = 0x44;
pub(crate) const DW_OP_lit21: u8 = 0x45;
pub(crate) const DW_OP_lit22: u8 = 0x46;
pub(crate) const DW_OP_lit23: u8 = 0x47;
pub(crate) const DW_OP_lit24: u8 = 0x48;
pub(crate) const DW_OP_lit25: u8 = 0x49;
pub(crate) const DW_OP_lit26: u8 = 0x4a;
pub(crate) const DW_OP_lit27: u8 = 0x4b;
pub(crate) const DW_OP_lit28: u8 = 0x4c;
pub(crate) const DW_OP_lit29: u8 = 0x4d;
pub(crate) const DW_OP_lit30: u8 = 0x4e;
pub(crate) const DW_OP_lit31: u8 = 0x4f;

// Register encodings: DW_OP_reg0 through DW_OP_reg31 (0x50 - 0x6f)
pub(crate) const DW_OP_reg0: u8 = 0x50;
pub(crate) const DW_OP_reg1: u8 = 0x51;
pub(crate) const DW_OP_reg2: u8 = 0x52;
pub(crate) const DW_OP_reg3: u8 = 0x53;
pub(crate) const DW_OP_reg4: u8 = 0x54;
pub(crate) const DW_OP_reg5: u8 = 0x55;
pub(crate) const DW_OP_reg6: u8 = 0x56;
pub(crate) const DW_OP_reg7: u8 = 0x57;
pub(crate) const DW_OP_reg8: u8 = 0x58;
pub(crate) const DW_OP_reg9: u8 = 0x59;
pub(crate) const DW_OP_reg10: u8 = 0x5a;
pub(crate) const DW_OP_reg11: u8 = 0x5b;
pub(crate) const DW_OP_reg12: u8 = 0x5c;
pub(crate) const DW_OP_reg13: u8 = 0x5d;
pub(crate) const DW_OP_reg14: u8 = 0x5e;
pub(crate) const DW_OP_reg15: u8 = 0x5f;
pub(crate) const DW_OP_reg16: u8 = 0x60;
pub(crate) const DW_OP_reg17: u8 = 0x61;
pub(crate) const DW_OP_reg18: u8 = 0x62;
pub(crate) const DW_OP_reg19: u8 = 0x63;
pub(crate) const DW_OP_reg20: u8 = 0x64;
pub(crate) const DW_OP_reg21: u8 = 0x65;
pub(crate) const DW_OP_reg22: u8 = 0x66;
pub(crate) const DW_OP_reg23: u8 = 0x67;
pub(crate) const DW_OP_reg24: u8 = 0x68;
pub(crate) const DW_OP_reg25: u8 = 0x69;
pub(crate) const DW_OP_reg26: u8 = 0x6a;
pub(crate) const DW_OP_reg27: u8 = 0x6b;
pub(crate) const DW_OP_reg28: u8 = 0x6c;
pub(crate) const DW_OP_reg29: u8 = 0x6d;
pub(crate) const DW_OP_reg30: u8 = 0x6e;
pub(crate) const DW_OP_reg31: u8 = 0x6f;

// Base register encodings: DW_OP_breg0 through DW_OP_breg31 (0x70 - 0x8f)
pub(crate) const DW_OP_breg0: u8 = 0x70;
pub(crate) const DW_OP_breg1: u8 = 0x71;
pub(crate) const DW_OP_breg2: u8 = 0x72;
pub(crate) const DW_OP_breg3: u8 = 0x73;
pub(crate) const DW_OP_breg4: u8 = 0x74;
pub(crate) const DW_OP_breg5: u8 = 0x75;
pub(crate) const DW_OP_breg6: u8 = 0x76;
pub(crate) const DW_OP_breg7: u8 = 0x77;
pub(crate) const DW_OP_breg8: u8 = 0x78;
pub(crate) const DW_OP_breg9: u8 = 0x79;
pub(crate) const DW_OP_breg10: u8 = 0x7a;
pub(crate) const DW_OP_breg11: u8 = 0x7b;
pub(crate) const DW_OP_breg12: u8 = 0x7c;
pub(crate) const DW_OP_breg13: u8 = 0x7d;
pub(crate) const DW_OP_breg14: u8 = 0x7e;
pub(crate) const DW_OP_breg15: u8 = 0x7f;
pub(crate) const DW_OP_breg16: u8 = 0x80;
pub(crate) const DW_OP_breg17: u8 = 0x81;
pub(crate) const DW_OP_breg18: u8 = 0x82;
pub(crate) const DW_OP_breg19: u8 = 0x83;
pub(crate) const DW_OP_breg20: u8 = 0x84;
pub(crate) const DW_OP_breg21: u8 = 0x85;
pub(crate) const DW_OP_breg22: u8 = 0x86;
pub(crate) const DW_OP_breg23: u8 = 0x87;
pub(crate) const DW_OP_breg24: u8 = 0x88;
pub(crate) const DW_OP_breg25: u8 = 0x89;
pub(crate) const DW_OP_breg26: u8 = 0x8a;
pub(crate) const DW_OP_breg27: u8 = 0x8b;
pub(crate) const DW_OP_breg28: u8 = 0x8c;
pub(crate) const DW_OP_breg29: u8 = 0x8d;
pub(crate) const DW_OP_breg30: u8 = 0x8e;
pub(crate) const DW_OP_breg31: u8 = 0x8f;

/// Unsigned LEB128 register.
pub(crate) const DW_OP_regx: u8 = 0x90;
/// Signed LEB128 offset from frame base.
pub(crate) const DW_OP_fbreg: u8 = 0x91;
/// ULEB128 register followed by SLEB128 offset.
pub(crate) const DW_OP_bregx: u8 = 0x92;
/// ULEB128 size of piece addressed.
pub(crate) const DW_OP_piece: u8 = 0x93;
/// 1-byte size of data retrieved.
pub(crate) const DW_OP_deref_size: u8 = 0x94;
/// 1-byte size of data retrieved (extended deref).
pub(crate) const DW_OP_xderef_size: u8 = 0x95;
pub(crate) const DW_OP_nop: u8 = 0x96;
pub(crate) const DW_OP_push_object_address: u8 = 0x97;
pub(crate) const DW_OP_call2: u8 = 0x98;
pub(crate) const DW_OP_call4: u8 = 0x99;
pub(crate) const DW_OP_call_ref: u8 = 0x9a;
/// TLS offset to address in current thread.
pub(crate) const DW_OP_form_tls_address: u8 = 0x9b;
/// CFA as determined by CFI.
pub(crate) const DW_OP_call_frame_cfa: u8 = 0x9c;
/// ULEB128 size and ULEB128 offset in bits.
pub(crate) const DW_OP_bit_piece: u8 = 0x9d;
/// `DW_FORM_block` follows opcode.
pub(crate) const DW_OP_implicit_value: u8 = 0x9e;
/// No operands, special like `DW_OP_piece`.
pub(crate) const DW_OP_stack_value: u8 = 0x9f;

// DWARF 5 location operations
pub(crate) const DW_OP_implicit_pointer: u8 = 0xa0;
pub(crate) const DW_OP_addrx: u8 = 0xa1;
pub(crate) const DW_OP_constx: u8 = 0xa2;
pub(crate) const DW_OP_entry_value: u8 = 0xa3;
pub(crate) const DW_OP_const_type: u8 = 0xa4;
pub(crate) const DW_OP_regval_type: u8 = 0xa5;
pub(crate) const DW_OP_deref_type: u8 = 0xa6;
pub(crate) const DW_OP_xderef_type: u8 = 0xa7;
pub(crate) const DW_OP_convert: u8 = 0xa8;
pub(crate) const DW_OP_reinterpret: u8 = 0xa9;

// GNU extensions
pub(crate) const DW_OP_GNU_push_tls_address: u8 = 0xe0;
pub(crate) const DW_OP_GNU_uninit: u8 = 0xf0;
pub(crate) const DW_OP_GNU_encoded_addr: u8 = 0xf1;
pub(crate) const DW_OP_GNU_implicit_pointer: u8 = 0xf2;
pub(crate) const DW_OP_GNU_entry_value: u8 = 0xf3;
pub(crate) const DW_OP_GNU_const_type: u8 = 0xf4;
pub(crate) const DW_OP_GNU_regval_type: u8 = 0xf5;
pub(crate) const DW_OP_GNU_deref_type: u8 = 0xf6;
pub(crate) const DW_OP_GNU_convert: u8 = 0xf7;
pub(crate) const DW_OP_GNU_reinterpret: u8 = 0xf9;
pub(crate) const DW_OP_GNU_parameter_ref: u8 = 0xfa;

// GNU Debug Fission extensions
pub(crate) const DW_OP_GNU_addr_index: u8 = 0xfb;
pub(crate) const DW_OP_GNU_const_index: u8 = 0xfc;
pub(crate) const DW_OP_GNU_variable_value: u8 = 0xfd;

/// Implementation-defined range start.
pub(crate) const DW_OP_lo_user: u8 = 0xe0;
/// Implementation-defined range end.
pub(crate) const DW_OP_hi_user: u8 = 0xff;

// ---------------------------------------------------------------------------
// DWARF Base Type Attribute Encodings (Section 7.8)
// ---------------------------------------------------------------------------

pub(crate) const DW_ATE_void: u8 = 0x0;
pub(crate) const DW_ATE_address: u8 = 0x1;
pub(crate) const DW_ATE_boolean: u8 = 0x2;
pub(crate) const DW_ATE_complex_float: u8 = 0x3;
pub(crate) const DW_ATE_float: u8 = 0x4;
pub(crate) const DW_ATE_signed: u8 = 0x5;
pub(crate) const DW_ATE_signed_char: u8 = 0x6;
pub(crate) const DW_ATE_unsigned: u8 = 0x7;
pub(crate) const DW_ATE_unsigned_char: u8 = 0x8;
pub(crate) const DW_ATE_imaginary_float: u8 = 0x9;
pub(crate) const DW_ATE_packed_decimal: u8 = 0xa;
pub(crate) const DW_ATE_numeric_string: u8 = 0xb;
pub(crate) const DW_ATE_edited: u8 = 0xc;
pub(crate) const DW_ATE_signed_fixed: u8 = 0xd;
pub(crate) const DW_ATE_unsigned_fixed: u8 = 0xe;
pub(crate) const DW_ATE_decimal_float: u8 = 0xf;
/// DWARF 4: UTF character encoding.
pub(crate) const DW_ATE_UTF: u8 = 0x10;
/// DWARF 5: UCS character encoding.
pub(crate) const DW_ATE_UCS: u8 = 0x11;
/// DWARF 5: ASCII character encoding.
pub(crate) const DW_ATE_ASCII: u8 = 0x12;
pub(crate) const DW_ATE_lo_user: u8 = 0x80;
pub(crate) const DW_ATE_hi_user: u8 = 0xff;

// ---------------------------------------------------------------------------
// DWARF Decimal Sign Encodings (Section 7.8)
// ---------------------------------------------------------------------------

pub(crate) const DW_DS_unsigned: u8 = 1;
pub(crate) const DW_DS_leading_overpunch: u8 = 2;
pub(crate) const DW_DS_trailing_overpunch: u8 = 3;
pub(crate) const DW_DS_leading_separate: u8 = 4;
pub(crate) const DW_DS_trailing_separate: u8 = 5;

// ---------------------------------------------------------------------------
// DWARF Endianity Encodings (Section 7.8)
// ---------------------------------------------------------------------------

pub(crate) const DW_END_default: u8 = 0;
pub(crate) const DW_END_big: u8 = 1;
pub(crate) const DW_END_little: u8 = 2;
pub(crate) const DW_END_lo_user: u8 = 0x40;
pub(crate) const DW_END_hi_user: u8 = 0xff;

// ---------------------------------------------------------------------------
// DWARF Accessibility Encodings (Section 7.9)
// ---------------------------------------------------------------------------

pub(crate) const DW_ACCESS_public: u8 = 1;
pub(crate) const DW_ACCESS_protected: u8 = 2;
pub(crate) const DW_ACCESS_private: u8 = 3;

// ---------------------------------------------------------------------------
// DWARF Visibility Encodings (Section 7.10)
// ---------------------------------------------------------------------------

pub(crate) const DW_VIS_local: u8 = 1;
pub(crate) const DW_VIS_exported: u8 = 2;
pub(crate) const DW_VIS_qualified: u8 = 3;

// ---------------------------------------------------------------------------
// DWARF Virtuality Encodings (Section 7.11)
// ---------------------------------------------------------------------------

pub(crate) const DW_VIRTUALITY_none: u8 = 0;
pub(crate) const DW_VIRTUALITY_virtual: u8 = 1;
pub(crate) const DW_VIRTUALITY_pure_virtual: u8 = 2;

// ---------------------------------------------------------------------------
// DWARF Source Language Encodings (Section 7.12)
// ---------------------------------------------------------------------------

pub(crate) const DW_LANG_C89: u16 = 0x0001;
pub(crate) const DW_LANG_C: u16 = 0x0002;
pub(crate) const DW_LANG_Ada83: u16 = 0x0003;
pub(crate) const DW_LANG_C_plus_plus: u16 = 0x0004;
pub(crate) const DW_LANG_Cobol74: u16 = 0x0005;
pub(crate) const DW_LANG_Cobol85: u16 = 0x0006;
pub(crate) const DW_LANG_Fortran77: u16 = 0x0007;
pub(crate) const DW_LANG_Fortran90: u16 = 0x0008;
pub(crate) const DW_LANG_Pascal83: u16 = 0x0009;
pub(crate) const DW_LANG_Modula2: u16 = 0x000a;
pub(crate) const DW_LANG_Java: u16 = 0x000b;
/// ISO C:1999.
pub(crate) const DW_LANG_C99: u16 = 0x000c;
pub(crate) const DW_LANG_Ada95: u16 = 0x000d;
pub(crate) const DW_LANG_Fortran95: u16 = 0x000e;
pub(crate) const DW_LANG_PLI: u16 = 0x000f;
pub(crate) const DW_LANG_ObjC: u16 = 0x0010;
pub(crate) const DW_LANG_ObjC_plus_plus: u16 = 0x0011;
pub(crate) const DW_LANG_UPC: u16 = 0x0012;
pub(crate) const DW_LANG_D: u16 = 0x0013;
pub(crate) const DW_LANG_Python: u16 = 0x0014;
pub(crate) const DW_LANG_OpenCL: u16 = 0x0015;
pub(crate) const DW_LANG_Go: u16 = 0x0016;
pub(crate) const DW_LANG_Modula3: u16 = 0x0017;
pub(crate) const DW_LANG_Haskell: u16 = 0x0018;
pub(crate) const DW_LANG_C_plus_plus_03: u16 = 0x0019;
pub(crate) const DW_LANG_C_plus_plus_11: u16 = 0x001a;
pub(crate) const DW_LANG_OCaml: u16 = 0x001b;
pub(crate) const DW_LANG_Rust: u16 = 0x001c;
/// ISO C:2011.
pub(crate) const DW_LANG_C11: u16 = 0x001d;
pub(crate) const DW_LANG_Swift: u16 = 0x001e;
pub(crate) const DW_LANG_Julia: u16 = 0x001f;
pub(crate) const DW_LANG_Dylan: u16 = 0x0020;
pub(crate) const DW_LANG_C_plus_plus_14: u16 = 0x0021;
pub(crate) const DW_LANG_Fortran03: u16 = 0x0022;
pub(crate) const DW_LANG_Fortran08: u16 = 0x0023;
pub(crate) const DW_LANG_RenderScript: u16 = 0x0024;
pub(crate) const DW_LANG_BLISS: u16 = 0x0025;

pub(crate) const DW_LANG_lo_user: u16 = 0x8000;
pub(crate) const DW_LANG_Mips_Assembler: u16 = 0x8001;
pub(crate) const DW_LANG_hi_user: u16 = 0xffff;

// ---------------------------------------------------------------------------
// DWARF Identifier Case Encodings (Section 7.14)
// ---------------------------------------------------------------------------

pub(crate) const DW_ID_case_sensitive: u8 = 0;
pub(crate) const DW_ID_up_case: u8 = 1;
pub(crate) const DW_ID_down_case: u8 = 2;
pub(crate) const DW_ID_case_insensitive: u8 = 3;

// ---------------------------------------------------------------------------
// DWARF Calling Convention Encodings (Section 7.15)
// ---------------------------------------------------------------------------

pub(crate) const DW_CC_normal: u8 = 0x1;
pub(crate) const DW_CC_program: u8 = 0x2;
pub(crate) const DW_CC_nocall: u8 = 0x3;
/// DWARF 5: Pass by reference.
pub(crate) const DW_CC_pass_by_reference: u8 = 0x4;
/// DWARF 5: Pass by value.
pub(crate) const DW_CC_pass_by_value: u8 = 0x5;
pub(crate) const DW_CC_lo_user: u8 = 0x40;
pub(crate) const DW_CC_hi_user: u8 = 0xff;

// ---------------------------------------------------------------------------
// DWARF Inline Encodings (Section 7.16)
// ---------------------------------------------------------------------------

pub(crate) const DW_INL_not_inlined: u8 = 0;
pub(crate) const DW_INL_inlined: u8 = 1;
pub(crate) const DW_INL_declared_not_inlined: u8 = 2;
pub(crate) const DW_INL_declared_inlined: u8 = 3;

// ---------------------------------------------------------------------------
// DWARF Array Ordering Encodings (Section 7.17)
// ---------------------------------------------------------------------------

pub(crate) const DW_ORD_row_major: u8 = 0;
pub(crate) const DW_ORD_col_major: u8 = 1;

// ---------------------------------------------------------------------------
// DWARF Discriminant Descriptor Encodings (Section 7.18)
// ---------------------------------------------------------------------------

pub(crate) const DW_DSC_label: u8 = 0;
pub(crate) const DW_DSC_range: u8 = 1;

// ---------------------------------------------------------------------------
// DWARF Defaulted Member Function Encodings (DWARF 5)
// ---------------------------------------------------------------------------

pub(crate) const DW_DEFAULTED_no: u8 = 0;
pub(crate) const DW_DEFAULTED_in_class: u8 = 1;
pub(crate) const DW_DEFAULTED_out_of_class: u8 = 2;

// ---------------------------------------------------------------------------
// DWARF Line Content Descriptions (DWARF 5, Section 6.2.4.1)
// ---------------------------------------------------------------------------

pub(crate) const DW_LNCT_path: u16 = 0x1;
pub(crate) const DW_LNCT_directory_index: u16 = 0x2;
pub(crate) const DW_LNCT_timestamp: u16 = 0x3;
pub(crate) const DW_LNCT_size: u16 = 0x4;
pub(crate) const DW_LNCT_MD5: u16 = 0x5;
pub(crate) const DW_LNCT_lo_user: u16 = 0x2000;
pub(crate) const DW_LNCT_hi_user: u16 = 0x3fff;

// ---------------------------------------------------------------------------
// DWARF Line Number Standard Opcode Encodings (Section 6.2.5.2)
// ---------------------------------------------------------------------------

pub(crate) const DW_LNS_copy: u8 = 1;
pub(crate) const DW_LNS_advance_pc: u8 = 2;
pub(crate) const DW_LNS_advance_line: u8 = 3;
pub(crate) const DW_LNS_set_file: u8 = 4;
pub(crate) const DW_LNS_set_column: u8 = 5;
pub(crate) const DW_LNS_negate_stmt: u8 = 6;
pub(crate) const DW_LNS_set_basic_block: u8 = 7;
pub(crate) const DW_LNS_const_add_pc: u8 = 8;
pub(crate) const DW_LNS_fixed_advance_pc: u8 = 9;
/// DWARF 3: Mark the end of the function prologue.
pub(crate) const DW_LNS_set_prologue_end: u8 = 10;
/// DWARF 3: Mark the beginning of the function epilogue.
pub(crate) const DW_LNS_set_epilogue_begin: u8 = 11;
pub(crate) const DW_LNS_set_isa: u8 = 12;

// ---------------------------------------------------------------------------
// DWARF Line Number Extended Opcode Encodings (Section 6.2.5.3)
// ---------------------------------------------------------------------------

pub(crate) const DW_LNE_end_sequence: u8 = 1;
pub(crate) const DW_LNE_set_address: u8 = 2;
pub(crate) const DW_LNE_define_file: u8 = 3;
/// DWARF 4: Set discriminator for same file/line.
pub(crate) const DW_LNE_set_discriminator: u8 = 4;
pub(crate) const DW_LNE_lo_user: u8 = 128;
pub(crate) const DW_LNE_NVIDIA_inlined_call: u8 = 144;
pub(crate) const DW_LNE_NVIDIA_set_function_name: u8 = 145;
pub(crate) const DW_LNE_hi_user: u8 = 255;

// ---------------------------------------------------------------------------
// DWARF Macinfo Type Encodings (Section 6.3.2)
// ---------------------------------------------------------------------------

pub(crate) const DW_MACINFO_define: u8 = 1;
pub(crate) const DW_MACINFO_undef: u8 = 2;
pub(crate) const DW_MACINFO_start_file: u8 = 3;
pub(crate) const DW_MACINFO_end_file: u8 = 4;
pub(crate) const DW_MACINFO_vendor_ext: u8 = 255;

// ---------------------------------------------------------------------------
// DWARF 5 Macro Information Type Encodings (Section 6.3.1)
// ---------------------------------------------------------------------------

pub(crate) const DW_MACRO_define: u8 = 0x01;
pub(crate) const DW_MACRO_undef: u8 = 0x02;
pub(crate) const DW_MACRO_start_file: u8 = 0x03;
pub(crate) const DW_MACRO_end_file: u8 = 0x04;
pub(crate) const DW_MACRO_define_strp: u8 = 0x05;
pub(crate) const DW_MACRO_undef_strp: u8 = 0x06;
pub(crate) const DW_MACRO_import: u8 = 0x07;
pub(crate) const DW_MACRO_define_sup: u8 = 0x08;
pub(crate) const DW_MACRO_undef_sup: u8 = 0x09;
pub(crate) const DW_MACRO_import_sup: u8 = 0x0a;
pub(crate) const DW_MACRO_define_strx: u8 = 0x0b;
pub(crate) const DW_MACRO_undef_strx: u8 = 0x0c;
pub(crate) const DW_MACRO_lo_user: u8 = 0xe0;
pub(crate) const DW_MACRO_hi_user: u8 = 0xff;

// GNU compatibility aliases for DWARF5 debug_macro type encodings
pub(crate) const DW_MACRO_GNU_define: u8 = DW_MACRO_define;
pub(crate) const DW_MACRO_GNU_undef: u8 = DW_MACRO_undef;
pub(crate) const DW_MACRO_GNU_start_file: u8 = DW_MACRO_start_file;
pub(crate) const DW_MACRO_GNU_end_file: u8 = DW_MACRO_end_file;
pub(crate) const DW_MACRO_GNU_define_indirect: u8 = DW_MACRO_define_strp;
pub(crate) const DW_MACRO_GNU_undef_indirect: u8 = DW_MACRO_undef_strp;
pub(crate) const DW_MACRO_GNU_transparent_include: u8 = DW_MACRO_import;
pub(crate) const DW_MACRO_GNU_lo_user: u8 = DW_MACRO_lo_user;
pub(crate) const DW_MACRO_GNU_hi_user: u8 = DW_MACRO_hi_user;

// ---------------------------------------------------------------------------
// DWARF 5 Range List Entry Encodings (Section 2.17.3)
// ---------------------------------------------------------------------------

pub(crate) const DW_RLE_end_of_list: u8 = 0x0;
pub(crate) const DW_RLE_base_addressx: u8 = 0x1;
pub(crate) const DW_RLE_startx_endx: u8 = 0x2;
pub(crate) const DW_RLE_startx_length: u8 = 0x3;
pub(crate) const DW_RLE_offset_pair: u8 = 0x4;
pub(crate) const DW_RLE_base_address: u8 = 0x5;
pub(crate) const DW_RLE_start_end: u8 = 0x6;
pub(crate) const DW_RLE_start_length: u8 = 0x7;

// ---------------------------------------------------------------------------
// DWARF 5 Location List Entry Encodings (Section 2.6.2)
// ---------------------------------------------------------------------------

pub(crate) const DW_LLE_end_of_list: u8 = 0x0;
pub(crate) const DW_LLE_base_addressx: u8 = 0x1;
pub(crate) const DW_LLE_startx_endx: u8 = 0x2;
pub(crate) const DW_LLE_startx_length: u8 = 0x3;
pub(crate) const DW_LLE_offset_pair: u8 = 0x4;
pub(crate) const DW_LLE_default_location: u8 = 0x5;
pub(crate) const DW_LLE_base_address: u8 = 0x6;
pub(crate) const DW_LLE_start_end: u8 = 0x7;
pub(crate) const DW_LLE_start_length: u8 = 0x8;

// GNU DebugFission list entry encodings (.debug_loc.dwo)
pub(crate) const DW_LLE_GNU_end_of_list_entry: u8 = 0x0;
pub(crate) const DW_LLE_GNU_base_address_selection_entry: u8 = 0x1;
pub(crate) const DW_LLE_GNU_start_end_entry: u8 = 0x2;
pub(crate) const DW_LLE_GNU_start_length_entry: u8 = 0x3;

// ---------------------------------------------------------------------------
// DWARF 5 Package File Section Identifiers (Section 7.3.5.3)
// ---------------------------------------------------------------------------

pub(crate) const DW_SECT_INFO: u8 = 1;
pub(crate) const DW_SECT_ABBREV: u8 = 3;
pub(crate) const DW_SECT_LINE: u8 = 4;
pub(crate) const DW_SECT_LOCLISTS: u8 = 5;
pub(crate) const DW_SECT_STR_OFFSETS: u8 = 6;
pub(crate) const DW_SECT_MACRO: u8 = 7;
pub(crate) const DW_SECT_RNGLISTS: u8 = 8;

// ---------------------------------------------------------------------------
// DWARF Call Frame Instruction Encodings (Section 7.24)
// ---------------------------------------------------------------------------

/// High 2 bits: advance location (delta in low 6 bits).
pub(crate) const DW_CFA_advance_loc: u8 = 0x40;
/// High 2 bits: offset (register in low 6 bits).
pub(crate) const DW_CFA_offset: u8 = 0x80;
/// High 2 bits: restore (register in low 6 bits).
pub(crate) const DW_CFA_restore: u8 = 0xc0;
/// Extended opcode prefix (low 6 bits zero).
pub(crate) const DW_CFA_extended: u8 = 0;

pub(crate) const DW_CFA_nop: u8 = 0x00;
pub(crate) const DW_CFA_set_loc: u8 = 0x01;
pub(crate) const DW_CFA_advance_loc1: u8 = 0x02;
pub(crate) const DW_CFA_advance_loc2: u8 = 0x03;
pub(crate) const DW_CFA_advance_loc4: u8 = 0x04;
pub(crate) const DW_CFA_offset_extended: u8 = 0x05;
pub(crate) const DW_CFA_restore_extended: u8 = 0x06;
pub(crate) const DW_CFA_undefined: u8 = 0x07;
pub(crate) const DW_CFA_same_value: u8 = 0x08;
pub(crate) const DW_CFA_register: u8 = 0x09;
pub(crate) const DW_CFA_remember_state: u8 = 0x0a;
pub(crate) const DW_CFA_restore_state: u8 = 0x0b;
pub(crate) const DW_CFA_def_cfa: u8 = 0x0c;
pub(crate) const DW_CFA_def_cfa_register: u8 = 0x0d;
pub(crate) const DW_CFA_def_cfa_offset: u8 = 0x0e;
pub(crate) const DW_CFA_def_cfa_expression: u8 = 0x0f;
pub(crate) const DW_CFA_expression: u8 = 0x10;
pub(crate) const DW_CFA_offset_extended_sf: u8 = 0x11;
pub(crate) const DW_CFA_def_cfa_sf: u8 = 0x12;
pub(crate) const DW_CFA_def_cfa_offset_sf: u8 = 0x13;
pub(crate) const DW_CFA_val_offset: u8 = 0x14;
pub(crate) const DW_CFA_val_offset_sf: u8 = 0x15;
pub(crate) const DW_CFA_val_expression: u8 = 0x16;

// CFA vendor extensions
pub(crate) const DW_CFA_low_user: u8 = 0x1c;
pub(crate) const DW_CFA_MIPS_advance_loc8: u8 = 0x1d;
pub(crate) const DW_CFA_GNU_window_save: u8 = 0x2d;
pub(crate) const DW_CFA_AARCH64_negate_ra_state: u8 = 0x2d;
pub(crate) const DW_CFA_GNU_args_size: u8 = 0x2e;
pub(crate) const DW_CFA_GNU_negative_offset_extended: u8 = 0x2f;
pub(crate) const DW_CFA_high_user: u8 = 0x3f;

// ---------------------------------------------------------------------------
// CIE ID Constants (Section 7.24)
// ---------------------------------------------------------------------------

/// CIE identifier in 32-bit format CIE header.
pub(crate) const DW_CIE_ID_32: u32 = 0xffff_ffff;
/// CIE identifier in 64-bit format CIE header.
pub(crate) const DW_CIE_ID_64: u64 = 0xffff_ffff_ffff_ffff;

// ---------------------------------------------------------------------------
// Exception Handling Pointer Encoding (GNU .eh_frame)
// ---------------------------------------------------------------------------

/// Absolute pointer.
pub(crate) const DW_EH_PE_absptr: u8 = 0x00;
/// Omitted pointer.
pub(crate) const DW_EH_PE_omit: u8 = 0xff;

// FDE data encoding
/// Unsigned LEB128.
pub(crate) const DW_EH_PE_uleb128: u8 = 0x01;
/// Unsigned 2-byte.
pub(crate) const DW_EH_PE_udata2: u8 = 0x02;
/// Unsigned 4-byte.
pub(crate) const DW_EH_PE_udata4: u8 = 0x03;
/// Unsigned 8-byte.
pub(crate) const DW_EH_PE_udata8: u8 = 0x04;
/// Signed LEB128.
pub(crate) const DW_EH_PE_sleb128: u8 = 0x09;
/// Signed 2-byte.
pub(crate) const DW_EH_PE_sdata2: u8 = 0x0a;
/// Signed 4-byte.
pub(crate) const DW_EH_PE_sdata4: u8 = 0x0b;
/// Signed 8-byte.
pub(crate) const DW_EH_PE_sdata8: u8 = 0x0c;
/// Signed flag.
pub(crate) const DW_EH_PE_signed: u8 = 0x08;

// FDE flags (application bits, OR'd with data encoding)
/// PC-relative encoding.
pub(crate) const DW_EH_PE_pcrel: u8 = 0x10;
/// Text-relative encoding.
pub(crate) const DW_EH_PE_textrel: u8 = 0x20;
/// Data-relative encoding.
pub(crate) const DW_EH_PE_datarel: u8 = 0x30;
/// Function-relative encoding.
pub(crate) const DW_EH_PE_funcrel: u8 = 0x40;
/// Aligned encoding.
pub(crate) const DW_EH_PE_aligned: u8 = 0x50;
/// Indirect encoding (pointer to pointer).
pub(crate) const DW_EH_PE_indirect: u8 = 0x80;

// ---------------------------------------------------------------------------
// Miscellaneous DWARF Constants
// ---------------------------------------------------------------------------

/// No address.
pub(crate) const DW_ADDR_none: u8 = 0;

/// DWARF3 minimum length escape code (Section 7.2.2).
pub(crate) const DWARF3_LENGTH_MIN_ESCAPE_CODE: u32 = 0xffff_fff0;
/// DWARF3 maximum length escape code (indicates 64-bit format).
pub(crate) const DWARF3_LENGTH_MAX_ESCAPE_CODE: u32 = 0xffff_ffff;
/// DWARF3 64-bit format indicator (alias for max escape code).
pub(crate) const DWARF3_LENGTH_64_BIT: u32 = DWARF3_LENGTH_MAX_ESCAPE_CODE;
