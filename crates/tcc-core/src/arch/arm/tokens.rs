//! ARM register names, condition codes, and instruction token definitions.
//!
//! Port of `arm-tok.h` (406 lines) from the TCC C codebase.
//!
//! **WARNING**: Relative order of tokens is critically important.
//! Arithmetic is performed on token values for register parsing,
//! condition code extraction, and data processing opcode mapping.
//! Do NOT reorder any token constants without updating all dependent logic.

#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// ============================================================================
// Base offset for ARM assembly tokens
// ============================================================================

/// Base offset for ARM assembly tokens within the global token numbering system.
/// All ARM token constants are defined as sequential offsets from this base.
/// When integrating with the global token table, adjust this value to match
/// the assigned ARM token range start.
pub const TOK_ASM_ARM_BASE: i32 = 0;

// ============================================================================
// Core registers r0-r15 (offsets 0-15)
// ============================================================================

pub const TOK_ASM_r0: i32 = TOK_ASM_ARM_BASE;
pub const TOK_ASM_r1: i32 = TOK_ASM_ARM_BASE + 1;
pub const TOK_ASM_r2: i32 = TOK_ASM_ARM_BASE + 2;
pub const TOK_ASM_r3: i32 = TOK_ASM_ARM_BASE + 3;
pub const TOK_ASM_r4: i32 = TOK_ASM_ARM_BASE + 4;
pub const TOK_ASM_r5: i32 = TOK_ASM_ARM_BASE + 5;
pub const TOK_ASM_r6: i32 = TOK_ASM_ARM_BASE + 6;
pub const TOK_ASM_r7: i32 = TOK_ASM_ARM_BASE + 7;
pub const TOK_ASM_r8: i32 = TOK_ASM_ARM_BASE + 8;
pub const TOK_ASM_r9: i32 = TOK_ASM_ARM_BASE + 9;
pub const TOK_ASM_r10: i32 = TOK_ASM_ARM_BASE + 10;
pub const TOK_ASM_r11: i32 = TOK_ASM_ARM_BASE + 11; // fp
pub const TOK_ASM_r12: i32 = TOK_ASM_ARM_BASE + 12; // ip
pub const TOK_ASM_r13: i32 = TOK_ASM_ARM_BASE + 13; // sp
pub const TOK_ASM_r14: i32 = TOK_ASM_ARM_BASE + 14; // lr
pub const TOK_ASM_r15: i32 = TOK_ASM_ARM_BASE + 15; // pc

// ============================================================================
// Synonym register names: a1-a4 (alias r0-r3), v1-v8 (alias r4-r11)
// Offsets 16-27
// ============================================================================

pub const TOK_ASM_a1: i32 = TOK_ASM_ARM_BASE + 16; // alias for r0
pub const TOK_ASM_a2: i32 = TOK_ASM_ARM_BASE + 17; // alias for r1
pub const TOK_ASM_a3: i32 = TOK_ASM_ARM_BASE + 18; // alias for r2
pub const TOK_ASM_a4: i32 = TOK_ASM_ARM_BASE + 19; // alias for r3
pub const TOK_ASM_v1: i32 = TOK_ASM_ARM_BASE + 20; // alias for r4
pub const TOK_ASM_v2: i32 = TOK_ASM_ARM_BASE + 21; // alias for r5
pub const TOK_ASM_v3: i32 = TOK_ASM_ARM_BASE + 22; // alias for r6
pub const TOK_ASM_v4: i32 = TOK_ASM_ARM_BASE + 23; // alias for r7
pub const TOK_ASM_v5: i32 = TOK_ASM_ARM_BASE + 24; // alias for r8
pub const TOK_ASM_v6: i32 = TOK_ASM_ARM_BASE + 25; // alias for r9
pub const TOK_ASM_v7: i32 = TOK_ASM_ARM_BASE + 26; // alias for r10
pub const TOK_ASM_v8: i32 = TOK_ASM_ARM_BASE + 27; // alias for r11

// ============================================================================
// Special register names (offsets 28-34)
// ============================================================================

pub const TOK_ASM_sb: i32 = TOK_ASM_ARM_BASE + 28; // alias for r9
pub const TOK_ASM_sl: i32 = TOK_ASM_ARM_BASE + 29; // alias for r10
pub const TOK_ASM_fp: i32 = TOK_ASM_ARM_BASE + 30; // alias for r11
pub const TOK_ASM_ip: i32 = TOK_ASM_ARM_BASE + 31; // alias for r12
pub const TOK_ASM_sp: i32 = TOK_ASM_ARM_BASE + 32; // alias for r13
pub const TOK_ASM_lr: i32 = TOK_ASM_ARM_BASE + 33; // alias for r14
pub const TOK_ASM_pc: i32 = TOK_ASM_ARM_BASE + 34; // alias for r15

// ============================================================================
// Coprocessor names p0-p15 (offsets 35-50)
// ============================================================================

pub const TOK_ASM_p0: i32 = TOK_ASM_ARM_BASE + 35;
pub const TOK_ASM_p1: i32 = TOK_ASM_ARM_BASE + 36;
pub const TOK_ASM_p2: i32 = TOK_ASM_ARM_BASE + 37;
pub const TOK_ASM_p3: i32 = TOK_ASM_ARM_BASE + 38;
pub const TOK_ASM_p4: i32 = TOK_ASM_ARM_BASE + 39;
pub const TOK_ASM_p5: i32 = TOK_ASM_ARM_BASE + 40;
pub const TOK_ASM_p6: i32 = TOK_ASM_ARM_BASE + 41;
pub const TOK_ASM_p7: i32 = TOK_ASM_ARM_BASE + 42;
pub const TOK_ASM_p8: i32 = TOK_ASM_ARM_BASE + 43;
pub const TOK_ASM_p9: i32 = TOK_ASM_ARM_BASE + 44;
pub const TOK_ASM_p10: i32 = TOK_ASM_ARM_BASE + 45;
pub const TOK_ASM_p11: i32 = TOK_ASM_ARM_BASE + 46;
pub const TOK_ASM_p12: i32 = TOK_ASM_ARM_BASE + 47;
pub const TOK_ASM_p13: i32 = TOK_ASM_ARM_BASE + 48;
pub const TOK_ASM_p14: i32 = TOK_ASM_ARM_BASE + 49;
pub const TOK_ASM_p15: i32 = TOK_ASM_ARM_BASE + 50;

// ============================================================================
// Coprocessor registers c0-c15 (offsets 51-66)
// ============================================================================

pub const TOK_ASM_c0: i32 = TOK_ASM_ARM_BASE + 51;
pub const TOK_ASM_c1: i32 = TOK_ASM_ARM_BASE + 52;
pub const TOK_ASM_c2: i32 = TOK_ASM_ARM_BASE + 53;
pub const TOK_ASM_c3: i32 = TOK_ASM_ARM_BASE + 54;
pub const TOK_ASM_c4: i32 = TOK_ASM_ARM_BASE + 55;
pub const TOK_ASM_c5: i32 = TOK_ASM_ARM_BASE + 56;
pub const TOK_ASM_c6: i32 = TOK_ASM_ARM_BASE + 57;
pub const TOK_ASM_c7: i32 = TOK_ASM_ARM_BASE + 58;
pub const TOK_ASM_c8: i32 = TOK_ASM_ARM_BASE + 59;
pub const TOK_ASM_c9: i32 = TOK_ASM_ARM_BASE + 60;
pub const TOK_ASM_c10: i32 = TOK_ASM_ARM_BASE + 61;
pub const TOK_ASM_c11: i32 = TOK_ASM_ARM_BASE + 62;
pub const TOK_ASM_c12: i32 = TOK_ASM_ARM_BASE + 63;
pub const TOK_ASM_c13: i32 = TOK_ASM_ARM_BASE + 64;
pub const TOK_ASM_c14: i32 = TOK_ASM_ARM_BASE + 65;
pub const TOK_ASM_c15: i32 = TOK_ASM_ARM_BASE + 66;

// ============================================================================
// VFP single-precision registers s0-s31 (offsets 67-98)
// ============================================================================

pub const TOK_ASM_s0: i32 = TOK_ASM_ARM_BASE + 67;
pub const TOK_ASM_s1: i32 = TOK_ASM_ARM_BASE + 68;
pub const TOK_ASM_s2: i32 = TOK_ASM_ARM_BASE + 69;
pub const TOK_ASM_s3: i32 = TOK_ASM_ARM_BASE + 70;
pub const TOK_ASM_s4: i32 = TOK_ASM_ARM_BASE + 71;
pub const TOK_ASM_s5: i32 = TOK_ASM_ARM_BASE + 72;
pub const TOK_ASM_s6: i32 = TOK_ASM_ARM_BASE + 73;
pub const TOK_ASM_s7: i32 = TOK_ASM_ARM_BASE + 74;
pub const TOK_ASM_s8: i32 = TOK_ASM_ARM_BASE + 75;
pub const TOK_ASM_s9: i32 = TOK_ASM_ARM_BASE + 76;
pub const TOK_ASM_s10: i32 = TOK_ASM_ARM_BASE + 77;
pub const TOK_ASM_s11: i32 = TOK_ASM_ARM_BASE + 78;
pub const TOK_ASM_s12: i32 = TOK_ASM_ARM_BASE + 79;
pub const TOK_ASM_s13: i32 = TOK_ASM_ARM_BASE + 80;
pub const TOK_ASM_s14: i32 = TOK_ASM_ARM_BASE + 81;
pub const TOK_ASM_s15: i32 = TOK_ASM_ARM_BASE + 82;
pub const TOK_ASM_s16: i32 = TOK_ASM_ARM_BASE + 83;
pub const TOK_ASM_s17: i32 = TOK_ASM_ARM_BASE + 84;
pub const TOK_ASM_s18: i32 = TOK_ASM_ARM_BASE + 85;
pub const TOK_ASM_s19: i32 = TOK_ASM_ARM_BASE + 86;
pub const TOK_ASM_s20: i32 = TOK_ASM_ARM_BASE + 87;
pub const TOK_ASM_s21: i32 = TOK_ASM_ARM_BASE + 88;
pub const TOK_ASM_s22: i32 = TOK_ASM_ARM_BASE + 89;
pub const TOK_ASM_s23: i32 = TOK_ASM_ARM_BASE + 90;
pub const TOK_ASM_s24: i32 = TOK_ASM_ARM_BASE + 91;
pub const TOK_ASM_s25: i32 = TOK_ASM_ARM_BASE + 92;
pub const TOK_ASM_s26: i32 = TOK_ASM_ARM_BASE + 93;
pub const TOK_ASM_s27: i32 = TOK_ASM_ARM_BASE + 94;
pub const TOK_ASM_s28: i32 = TOK_ASM_ARM_BASE + 95;
pub const TOK_ASM_s29: i32 = TOK_ASM_ARM_BASE + 96;
pub const TOK_ASM_s30: i32 = TOK_ASM_ARM_BASE + 97;
pub const TOK_ASM_s31: i32 = TOK_ASM_ARM_BASE + 98;

// ============================================================================
// VFP double-precision registers d0-d15 (offsets 99-114)
// ============================================================================

pub const TOK_ASM_d0: i32 = TOK_ASM_ARM_BASE + 99;
pub const TOK_ASM_d1: i32 = TOK_ASM_ARM_BASE + 100;
pub const TOK_ASM_d2: i32 = TOK_ASM_ARM_BASE + 101;
pub const TOK_ASM_d3: i32 = TOK_ASM_ARM_BASE + 102;
pub const TOK_ASM_d4: i32 = TOK_ASM_ARM_BASE + 103;
pub const TOK_ASM_d5: i32 = TOK_ASM_ARM_BASE + 104;
pub const TOK_ASM_d6: i32 = TOK_ASM_ARM_BASE + 105;
pub const TOK_ASM_d7: i32 = TOK_ASM_ARM_BASE + 106;
pub const TOK_ASM_d8: i32 = TOK_ASM_ARM_BASE + 107;
pub const TOK_ASM_d9: i32 = TOK_ASM_ARM_BASE + 108;
pub const TOK_ASM_d10: i32 = TOK_ASM_ARM_BASE + 109;
pub const TOK_ASM_d11: i32 = TOK_ASM_ARM_BASE + 110;
pub const TOK_ASM_d12: i32 = TOK_ASM_ARM_BASE + 111;
pub const TOK_ASM_d13: i32 = TOK_ASM_ARM_BASE + 112;
pub const TOK_ASM_d14: i32 = TOK_ASM_ARM_BASE + 113;
pub const TOK_ASM_d15: i32 = TOK_ASM_ARM_BASE + 114;

// ============================================================================
// VFP status registers (offsets 115-117)
// ============================================================================

pub const TOK_ASM_fpsid: i32 = TOK_ASM_ARM_BASE + 115;
pub const TOK_ASM_fpscr: i32 = TOK_ASM_ARM_BASE + 116;
pub const TOK_ASM_fpexc: i32 = TOK_ASM_ARM_BASE + 117;

// ============================================================================
// Special tokens (offsets 118-119)
// ============================================================================

/// VFP magical ARM register for status flag transfer
pub const TOK_ASM_apsr_nzcv: i32 = TOK_ASM_ARM_BASE + 118;

/// Data processing directive (alias for LSL)
pub const TOK_ASM_asl: i32 = TOK_ASM_ARM_BASE + 119;

// ============================================================================
// Unconditional instructions — no condition code (offsets 120-124)
// These MUST be before TOK_ASM_nopeq.
// ============================================================================

pub const TOK_ASM_cdp2: i32 = TOK_ASM_ARM_BASE + 120;
pub const TOK_ASM_ldc2: i32 = TOK_ASM_ARM_BASE + 121;
pub const TOK_ASM_ldc2l: i32 = TOK_ASM_ARM_BASE + 122;
pub const TOK_ASM_stc2: i32 = TOK_ASM_ARM_BASE + 123;
pub const TOK_ASM_stc2l: i32 = TOK_ASM_ARM_BASE + 124;

// ============================================================================
// Conditioned instruction tokens
// ============================================================================
//
// Each conditioned instruction occupies 16 consecutive token slots:
//   Offset +0:  eq   (Equal, Z=1)
//   Offset +1:  ne   (Not equal, Z=0)
//   Offset +2:  cs   (Carry set, C=1) / hs
//   Offset +3:  cc   (Carry clear, C=0) / lo
//   Offset +4:  mi   (Minus/negative, N=1)
//   Offset +5:  pl   (Plus/positive, N=0)
//   Offset +6:  vs   (Overflow, V=1)
//   Offset +7:  vc   (No overflow, V=0)
//   Offset +8:  hi   (Unsigned higher, C=1 && Z=0)
//   Offset +9:  ls   (Unsigned lower or same, C=0 || Z=1)
//   Offset +10: ge   (Signed >=, N==V)
//   Offset +11: lt   (Signed <, N!=V)
//   Offset +12: gt   (Signed >, Z=0 && N==V)
//   Offset +13: le   (Signed <=, Z=1 || N!=V)
//   Offset +14: (unconditional — no suffix, always execute)
//   Offset +15: rsvd (reserved)
//
// Only the "eq" variant is defined as a named constant below.
// Other variants are computed: TOK_ASM_<name>eq + ConditionCode as i32
//
// CRITICAL: Do NOT change the order of these definitions.

// --- Nullary/System (groups 0-4) ---
pub const TOK_ASM_nopeq: i32 = TOK_ASM_ARM_BASE + 125;
pub const TOK_ASM_wfeeq: i32 = TOK_ASM_ARM_BASE + 141;
pub const TOK_ASM_wfieq: i32 = TOK_ASM_ARM_BASE + 157;
pub const TOK_ASM_swieq: i32 = TOK_ASM_ARM_BASE + 173;
pub const TOK_ASM_svceq: i32 = TOK_ASM_ARM_BASE + 189;

// --- Misc (groups 5-5) ---
pub const TOK_ASM_clzeq: i32 = TOK_ASM_ARM_BASE + 205;

// --- Size conversion (groups 6-11) ---
pub const TOK_ASM_sxtbeq: i32 = TOK_ASM_ARM_BASE + 221;
pub const TOK_ASM_sxtheq: i32 = TOK_ASM_ARM_BASE + 237;
pub const TOK_ASM_uxtbeq: i32 = TOK_ASM_ARM_BASE + 253;
pub const TOK_ASM_uxtheq: i32 = TOK_ASM_ARM_BASE + 269;
pub const TOK_ASM_movteq: i32 = TOK_ASM_ARM_BASE + 285;
pub const TOK_ASM_movweq: i32 = TOK_ASM_ARM_BASE + 301;

// --- Multiplication (groups 12-15) ---
pub const TOK_ASM_muleq: i32 = TOK_ASM_ARM_BASE + 317;
pub const TOK_ASM_mulseq: i32 = TOK_ASM_ARM_BASE + 333;
pub const TOK_ASM_mlaeq: i32 = TOK_ASM_ARM_BASE + 349;
pub const TOK_ASM_mlaseq: i32 = TOK_ASM_ARM_BASE + 365;

// --- Long multiplication (groups 16-23) ---
pub const TOK_ASM_smulleq: i32 = TOK_ASM_ARM_BASE + 381;
pub const TOK_ASM_smullseq: i32 = TOK_ASM_ARM_BASE + 397;
pub const TOK_ASM_umulleq: i32 = TOK_ASM_ARM_BASE + 413;
pub const TOK_ASM_umullseq: i32 = TOK_ASM_ARM_BASE + 429;
pub const TOK_ASM_smlaleq: i32 = TOK_ASM_ARM_BASE + 445;
pub const TOK_ASM_smlalseq: i32 = TOK_ASM_ARM_BASE + 461;
pub const TOK_ASM_umlaleq: i32 = TOK_ASM_ARM_BASE + 477;
pub const TOK_ASM_umlalseq: i32 = TOK_ASM_ARM_BASE + 493;

// --- More multiplication (groups 24-26) ---
pub const TOK_ASM_mlseq: i32 = TOK_ASM_ARM_BASE + 509;
pub const TOK_ASM_udiveq: i32 = TOK_ASM_ARM_BASE + 525;
pub const TOK_ASM_sdiveq: i32 = TOK_ASM_ARM_BASE + 541;

// --- Load/Store (groups 27-40) ---
pub const TOK_ASM_ldreq: i32 = TOK_ASM_ARM_BASE + 557;
pub const TOK_ASM_ldrbeq: i32 = TOK_ASM_ARM_BASE + 573;
pub const TOK_ASM_streq: i32 = TOK_ASM_ARM_BASE + 589;
pub const TOK_ASM_strbeq: i32 = TOK_ASM_ARM_BASE + 605;
pub const TOK_ASM_ldrexeq: i32 = TOK_ASM_ARM_BASE + 621;
pub const TOK_ASM_ldrexbeq: i32 = TOK_ASM_ARM_BASE + 637;
pub const TOK_ASM_ldrexheq: i32 = TOK_ASM_ARM_BASE + 653;
pub const TOK_ASM_strexeq: i32 = TOK_ASM_ARM_BASE + 669;
pub const TOK_ASM_strexbeq: i32 = TOK_ASM_ARM_BASE + 685;
pub const TOK_ASM_strexheq: i32 = TOK_ASM_ARM_BASE + 701;
pub const TOK_ASM_ldrheq: i32 = TOK_ASM_ARM_BASE + 717;
pub const TOK_ASM_ldrsheq: i32 = TOK_ASM_ARM_BASE + 733;
pub const TOK_ASM_ldrsbeq: i32 = TOK_ASM_ARM_BASE + 749;
pub const TOK_ASM_strheq: i32 = TOK_ASM_ARM_BASE + 765;

// --- Block data transfer (groups 41-54) ---
pub const TOK_ASM_stmdaeq: i32 = TOK_ASM_ARM_BASE + 781;
pub const TOK_ASM_ldmdaeq: i32 = TOK_ASM_ARM_BASE + 797;
pub const TOK_ASM_stmeq: i32 = TOK_ASM_ARM_BASE + 813;
pub const TOK_ASM_ldmeq: i32 = TOK_ASM_ARM_BASE + 829;
pub const TOK_ASM_stmiaeq: i32 = TOK_ASM_ARM_BASE + 845;
pub const TOK_ASM_ldmiaeq: i32 = TOK_ASM_ARM_BASE + 861;
pub const TOK_ASM_stmdbeq: i32 = TOK_ASM_ARM_BASE + 877;
pub const TOK_ASM_ldmdbeq: i32 = TOK_ASM_ARM_BASE + 893;
pub const TOK_ASM_stmibeq: i32 = TOK_ASM_ARM_BASE + 909;
pub const TOK_ASM_ldmibeq: i32 = TOK_ASM_ARM_BASE + 925;
pub const TOK_ASM_ldceq: i32 = TOK_ASM_ARM_BASE + 941;
pub const TOK_ASM_ldcleq: i32 = TOK_ASM_ARM_BASE + 957;
pub const TOK_ASM_stceq: i32 = TOK_ASM_ARM_BASE + 973;
pub const TOK_ASM_stcleq: i32 = TOK_ASM_ARM_BASE + 989;

// --- Push/Pop (groups 55-56) ---
pub const TOK_ASM_pusheq: i32 = TOK_ASM_ARM_BASE + 1005;
pub const TOK_ASM_popeq: i32 = TOK_ASM_ARM_BASE + 1021;

// --- Branches (groups 57-60) ---
pub const TOK_ASM_beq: i32 = TOK_ASM_ARM_BASE + 1037;
pub const TOK_ASM_bleq: i32 = TOK_ASM_ARM_BASE + 1053;
pub const TOK_ASM_bxeq: i32 = TOK_ASM_ARM_BASE + 1069;
pub const TOK_ASM_blxeq: i32 = TOK_ASM_ARM_BASE + 1085;

// --- Data processing (opcode = ((group - 61) >> 1), interleaved with S variants) (groups 61-92) ---
pub const TOK_ASM_andeq: i32 = TOK_ASM_ARM_BASE + 1101;
pub const TOK_ASM_andseq: i32 = TOK_ASM_ARM_BASE + 1117;
pub const TOK_ASM_eoreq: i32 = TOK_ASM_ARM_BASE + 1133;
pub const TOK_ASM_eorseq: i32 = TOK_ASM_ARM_BASE + 1149;
pub const TOK_ASM_subeq: i32 = TOK_ASM_ARM_BASE + 1165;
pub const TOK_ASM_subseq: i32 = TOK_ASM_ARM_BASE + 1181;
pub const TOK_ASM_rsbeq: i32 = TOK_ASM_ARM_BASE + 1197;
pub const TOK_ASM_rsbseq: i32 = TOK_ASM_ARM_BASE + 1213;
pub const TOK_ASM_addeq: i32 = TOK_ASM_ARM_BASE + 1229;
pub const TOK_ASM_addseq: i32 = TOK_ASM_ARM_BASE + 1245;
pub const TOK_ASM_adceq: i32 = TOK_ASM_ARM_BASE + 1261;
pub const TOK_ASM_adcseq: i32 = TOK_ASM_ARM_BASE + 1277;
pub const TOK_ASM_sbceq: i32 = TOK_ASM_ARM_BASE + 1293;
pub const TOK_ASM_sbcseq: i32 = TOK_ASM_ARM_BASE + 1309;
pub const TOK_ASM_rsceq: i32 = TOK_ASM_ARM_BASE + 1325;
pub const TOK_ASM_rscseq: i32 = TOK_ASM_ARM_BASE + 1341;
pub const TOK_ASM_tsteq: i32 = TOK_ASM_ARM_BASE + 1357;
pub const TOK_ASM_tstseq: i32 = TOK_ASM_ARM_BASE + 1373;
pub const TOK_ASM_teqeq: i32 = TOK_ASM_ARM_BASE + 1389;
pub const TOK_ASM_teqseq: i32 = TOK_ASM_ARM_BASE + 1405;
pub const TOK_ASM_cmpeq: i32 = TOK_ASM_ARM_BASE + 1421;
pub const TOK_ASM_cmpseq: i32 = TOK_ASM_ARM_BASE + 1437;
pub const TOK_ASM_cmneq: i32 = TOK_ASM_ARM_BASE + 1453;
pub const TOK_ASM_cmnseq: i32 = TOK_ASM_ARM_BASE + 1469;
pub const TOK_ASM_orreq: i32 = TOK_ASM_ARM_BASE + 1485;
pub const TOK_ASM_orrseq: i32 = TOK_ASM_ARM_BASE + 1501;
pub const TOK_ASM_moveq: i32 = TOK_ASM_ARM_BASE + 1517;
pub const TOK_ASM_movseq: i32 = TOK_ASM_ARM_BASE + 1533;
pub const TOK_ASM_biceq: i32 = TOK_ASM_ARM_BASE + 1549;
pub const TOK_ASM_bicseq: i32 = TOK_ASM_ARM_BASE + 1565;
pub const TOK_ASM_mvneq: i32 = TOK_ASM_ARM_BASE + 1581;
pub const TOK_ASM_mvnseq: i32 = TOK_ASM_ARM_BASE + 1597;

// --- Shifts (groups 93-102) ---
pub const TOK_ASM_lsleq: i32 = TOK_ASM_ARM_BASE + 1613;
pub const TOK_ASM_lslseq: i32 = TOK_ASM_ARM_BASE + 1629;
pub const TOK_ASM_lsreq: i32 = TOK_ASM_ARM_BASE + 1645;
pub const TOK_ASM_lsrseq: i32 = TOK_ASM_ARM_BASE + 1661;
pub const TOK_ASM_asreq: i32 = TOK_ASM_ARM_BASE + 1677;
pub const TOK_ASM_asrseq: i32 = TOK_ASM_ARM_BASE + 1693;
pub const TOK_ASM_roreq: i32 = TOK_ASM_ARM_BASE + 1709;
pub const TOK_ASM_rorseq: i32 = TOK_ASM_ARM_BASE + 1725;
pub const TOK_ASM_rrxeq: i32 = TOK_ASM_ARM_BASE + 1741;
pub const TOK_ASM_rrxseq: i32 = TOK_ASM_ARM_BASE + 1757;

// --- Coprocessor (groups 103-105) ---
pub const TOK_ASM_cdpeq: i32 = TOK_ASM_ARM_BASE + 1773;
pub const TOK_ASM_mcreq: i32 = TOK_ASM_ARM_BASE + 1789;
pub const TOK_ASM_mrceq: i32 = TOK_ASM_ARM_BASE + 1805;

// --- VFP load/store (groups 106-107) ---
pub const TOK_ASM_vldreq: i32 = TOK_ASM_ARM_BASE + 1821;
pub const TOK_ASM_vstreq: i32 = TOK_ASM_ARM_BASE + 1837;

// --- VFP data processing f32/f64 (groups 108-137) ---
pub const TOK_ASM_vmla_f32eq: i32 = TOK_ASM_ARM_BASE + 1853;
pub const TOK_ASM_vmla_f64eq: i32 = TOK_ASM_ARM_BASE + 1869;
pub const TOK_ASM_vmls_f32eq: i32 = TOK_ASM_ARM_BASE + 1885;
pub const TOK_ASM_vmls_f64eq: i32 = TOK_ASM_ARM_BASE + 1901;
pub const TOK_ASM_vnmls_f32eq: i32 = TOK_ASM_ARM_BASE + 1917;
pub const TOK_ASM_vnmls_f64eq: i32 = TOK_ASM_ARM_BASE + 1933;
pub const TOK_ASM_vnmla_f32eq: i32 = TOK_ASM_ARM_BASE + 1949;
pub const TOK_ASM_vnmla_f64eq: i32 = TOK_ASM_ARM_BASE + 1965;
pub const TOK_ASM_vmul_f32eq: i32 = TOK_ASM_ARM_BASE + 1981;
pub const TOK_ASM_vmul_f64eq: i32 = TOK_ASM_ARM_BASE + 1997;
pub const TOK_ASM_vnmul_f32eq: i32 = TOK_ASM_ARM_BASE + 2013;
pub const TOK_ASM_vnmul_f64eq: i32 = TOK_ASM_ARM_BASE + 2029;
pub const TOK_ASM_vadd_f32eq: i32 = TOK_ASM_ARM_BASE + 2045;
pub const TOK_ASM_vadd_f64eq: i32 = TOK_ASM_ARM_BASE + 2061;
pub const TOK_ASM_vsub_f32eq: i32 = TOK_ASM_ARM_BASE + 2077;
pub const TOK_ASM_vsub_f64eq: i32 = TOK_ASM_ARM_BASE + 2093;
pub const TOK_ASM_vdiv_f32eq: i32 = TOK_ASM_ARM_BASE + 2109;
pub const TOK_ASM_vdiv_f64eq: i32 = TOK_ASM_ARM_BASE + 2125;
pub const TOK_ASM_vneg_f32eq: i32 = TOK_ASM_ARM_BASE + 2141;
pub const TOK_ASM_vneg_f64eq: i32 = TOK_ASM_ARM_BASE + 2157;
pub const TOK_ASM_vabs_f32eq: i32 = TOK_ASM_ARM_BASE + 2173;
pub const TOK_ASM_vabs_f64eq: i32 = TOK_ASM_ARM_BASE + 2189;
pub const TOK_ASM_vsqrt_f32eq: i32 = TOK_ASM_ARM_BASE + 2205;
pub const TOK_ASM_vsqrt_f64eq: i32 = TOK_ASM_ARM_BASE + 2221;
pub const TOK_ASM_vcmp_f32eq: i32 = TOK_ASM_ARM_BASE + 2237;
pub const TOK_ASM_vcmp_f64eq: i32 = TOK_ASM_ARM_BASE + 2253;
pub const TOK_ASM_vcmpe_f32eq: i32 = TOK_ASM_ARM_BASE + 2269;
pub const TOK_ASM_vcmpe_f64eq: i32 = TOK_ASM_ARM_BASE + 2285;
pub const TOK_ASM_vmov_f32eq: i32 = TOK_ASM_ARM_BASE + 2301;
pub const TOK_ASM_vmov_f64eq: i32 = TOK_ASM_ARM_BASE + 2317;

// --- VFP convert (two-suffix) (groups 138-151) ---
pub const TOK_ASM_vcvtr_s32_f64eq: i32 = TOK_ASM_ARM_BASE + 2333;
pub const TOK_ASM_vcvtr_s32_f32eq: i32 = TOK_ASM_ARM_BASE + 2349;
pub const TOK_ASM_vcvtr_u32_f64eq: i32 = TOK_ASM_ARM_BASE + 2365;
pub const TOK_ASM_vcvtr_u32_f32eq: i32 = TOK_ASM_ARM_BASE + 2381;
pub const TOK_ASM_vcvt_s32_f64eq: i32 = TOK_ASM_ARM_BASE + 2397;
pub const TOK_ASM_vcvt_s32_f32eq: i32 = TOK_ASM_ARM_BASE + 2413;
pub const TOK_ASM_vcvt_u32_f64eq: i32 = TOK_ASM_ARM_BASE + 2429;
pub const TOK_ASM_vcvt_u32_f32eq: i32 = TOK_ASM_ARM_BASE + 2445;
pub const TOK_ASM_vcvt_f64_s32eq: i32 = TOK_ASM_ARM_BASE + 2461;
pub const TOK_ASM_vcvt_f32_s32eq: i32 = TOK_ASM_ARM_BASE + 2477;
pub const TOK_ASM_vcvt_f64_u32eq: i32 = TOK_ASM_ARM_BASE + 2493;
pub const TOK_ASM_vcvt_f32_u32eq: i32 = TOK_ASM_ARM_BASE + 2509;
pub const TOK_ASM_vcvt_f64_f32eq: i32 = TOK_ASM_ARM_BASE + 2525;
pub const TOK_ASM_vcvt_f32_f64eq: i32 = TOK_ASM_ARM_BASE + 2541;

// --- VFP block transfer (groups 152-159) ---
pub const TOK_ASM_vpusheq: i32 = TOK_ASM_ARM_BASE + 2557;
pub const TOK_ASM_vpopeq: i32 = TOK_ASM_ARM_BASE + 2573;
pub const TOK_ASM_vldmeq: i32 = TOK_ASM_ARM_BASE + 2589;
pub const TOK_ASM_vldmiaeq: i32 = TOK_ASM_ARM_BASE + 2605;
pub const TOK_ASM_vldmdbeq: i32 = TOK_ASM_ARM_BASE + 2621;
pub const TOK_ASM_vstmeq: i32 = TOK_ASM_ARM_BASE + 2637;
pub const TOK_ASM_vstmiaeq: i32 = TOK_ASM_ARM_BASE + 2653;
pub const TOK_ASM_vstmdbeq: i32 = TOK_ASM_ARM_BASE + 2669;

// --- VFP status register (groups 160-161) ---
pub const TOK_ASM_vmsreq: i32 = TOK_ASM_ARM_BASE + 2685;
pub const TOK_ASM_vmrseq: i32 = TOK_ASM_ARM_BASE + 2701;

/// Total number of ARM assembly tokens (offsets 0-2716)
pub const ARM_TOKEN_COUNT: i32 = 2717;

// ============================================================================
// Enums
// ============================================================================

/// ARM 4-bit condition codes.
///
/// Each conditioned instruction has 16 variants indexed by these codes.
/// The condition code is embedded in bits [31:28] of the ARM instruction word.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConditionCode {
    /// Equal (Z=1)
    Eq = 0,
    /// Not equal (Z=0)
    Ne = 1,
    /// Carry set / unsigned higher or same (C=1)
    Cs = 2,
    /// Carry clear / unsigned lower (C=0)
    Cc = 3,
    /// Minus / negative (N=1)
    Mi = 4,
    /// Plus / positive or zero (N=0)
    Pl = 5,
    /// Overflow (V=1)
    Vs = 6,
    /// No overflow (V=0)
    Vc = 7,
    /// Unsigned higher (C=1 && Z=0)
    Hi = 8,
    /// Unsigned lower or same (C=0 || Z=1)
    Ls = 9,
    /// Signed greater than or equal (N==V)
    Ge = 10,
    /// Signed less than (N!=V)
    Lt = 11,
    /// Signed greater than (Z=0 && N==V)
    Gt = 12,
    /// Signed less than or equal (Z=1 || N!=V)
    Le = 13,
    /// Always (unconditional)
    Al = 14,
    /// Reserved
    Rsvd = 15,
}

impl ConditionCode {
    /// Convert a raw u8 value (0-15) to a ConditionCode.
    /// Returns None if the value is out of range.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(ConditionCode::Eq),
            1 => Some(ConditionCode::Ne),
            2 => Some(ConditionCode::Cs),
            3 => Some(ConditionCode::Cc),
            4 => Some(ConditionCode::Mi),
            5 => Some(ConditionCode::Pl),
            6 => Some(ConditionCode::Vs),
            7 => Some(ConditionCode::Vc),
            8 => Some(ConditionCode::Hi),
            9 => Some(ConditionCode::Ls),
            10 => Some(ConditionCode::Ge),
            11 => Some(ConditionCode::Lt),
            12 => Some(ConditionCode::Gt),
            13 => Some(ConditionCode::Le),
            14 => Some(ConditionCode::Al),
            15 => Some(ConditionCode::Rsvd),
            _ => None,
        }
    }

    /// Return the suffix string for this condition code.
    pub fn suffix(self) -> &'static str {
        match self {
            ConditionCode::Eq => "eq",
            ConditionCode::Ne => "ne",
            ConditionCode::Cs => "cs",
            ConditionCode::Cc => "cc",
            ConditionCode::Mi => "mi",
            ConditionCode::Pl => "pl",
            ConditionCode::Vs => "vs",
            ConditionCode::Vc => "vc",
            ConditionCode::Hi => "hi",
            ConditionCode::Ls => "ls",
            ConditionCode::Ge => "ge",
            ConditionCode::Lt => "lt",
            ConditionCode::Gt => "gt",
            ConditionCode::Le => "le",
            ConditionCode::Al => "",
            ConditionCode::Rsvd => "rsvd",
        }
    }
}

/// ARM core register (r0-r15).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmRegister {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    Sp = 13,
    Lr = 14,
    Pc = 15,
}

impl ArmRegister {
    /// Convert a raw u8 register number (0-15) to an ArmRegister.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(ArmRegister::R0),
            1 => Some(ArmRegister::R1),
            2 => Some(ArmRegister::R2),
            3 => Some(ArmRegister::R3),
            4 => Some(ArmRegister::R4),
            5 => Some(ArmRegister::R5),
            6 => Some(ArmRegister::R6),
            7 => Some(ArmRegister::R7),
            8 => Some(ArmRegister::R8),
            9 => Some(ArmRegister::R9),
            10 => Some(ArmRegister::R10),
            11 => Some(ArmRegister::R11),
            12 => Some(ArmRegister::R12),
            13 => Some(ArmRegister::Sp),
            14 => Some(ArmRegister::Lr),
            15 => Some(ArmRegister::Pc),
            _ => None,
        }
    }

    /// Return the register name string.
    pub fn name(self) -> &'static str {
        ARM_REG_NAMES[self as usize]
    }
}

/// VFP single-precision register (s0-s31).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VfpSingleReg {
    S0 = 0,
    S1 = 1,
    S2 = 2,
    S3 = 3,
    S4 = 4,
    S5 = 5,
    S6 = 6,
    S7 = 7,
    S8 = 8,
    S9 = 9,
    S10 = 10,
    S11 = 11,
    S12 = 12,
    S13 = 13,
    S14 = 14,
    S15 = 15,
    S16 = 16,
    S17 = 17,
    S18 = 18,
    S19 = 19,
    S20 = 20,
    S21 = 21,
    S22 = 22,
    S23 = 23,
    S24 = 24,
    S25 = 25,
    S26 = 26,
    S27 = 27,
    S28 = 28,
    S29 = 29,
    S30 = 30,
    S31 = 31,
}

impl VfpSingleReg {
    /// Convert a raw u8 register number (0-31) to a VfpSingleReg.
    pub fn from_u8(val: u8) -> Option<Self> {
        if val < 32 {
            // SAFETY: repr(u8) with contiguous values 0..31
            Some(unsafe { core::mem::transmute::<u8, VfpSingleReg>(val) })
        } else {
            None
        }
    }
}

/// VFP double-precision register (d0-d15).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VfpDoubleReg {
    D0 = 0,
    D1 = 1,
    D2 = 2,
    D3 = 3,
    D4 = 4,
    D5 = 5,
    D6 = 6,
    D7 = 7,
    D8 = 8,
    D9 = 9,
    D10 = 10,
    D11 = 11,
    D12 = 12,
    D13 = 13,
    D14 = 14,
    D15 = 15,
}

impl VfpDoubleReg {
    /// Convert a raw u8 register number (0-15) to a VfpDoubleReg.
    pub fn from_u8(val: u8) -> Option<Self> {
        if val < 16 {
            // SAFETY: repr(u8) with contiguous values 0..15
            Some(unsafe { core::mem::transmute::<u8, VfpDoubleReg>(val) })
        } else {
            None
        }
    }
}

/// Classification of ARM instructions for assembler dispatch.
///
/// Used by `asm_opcode()` to route each token to the appropriate encoding function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArmInstructionCategory {
    /// nop, wfe, wfi
    Nullary,
    /// swi, svc
    Unary,
    /// clz, sxtb, sxth, uxtb, uxth, movt, movw
    Binary,
    /// and..mvn + s variants
    DataProcessing,
    /// lsl, lsr, asr, ror, rrx + s variants
    Shift,
    /// mul, mla, mls, udiv, sdiv
    Multiplication,
    /// smull, umull, smlal, umlal
    LongMultiplication,
    /// ldr, str, ldrb, strb, ldrex, strex variants
    SingleDataTransfer,
    /// ldrh, ldrsh, ldrsb, strh
    MiscDataTransfer,
    /// push, pop, stm/ldm variants
    BlockDataTransfer,
    /// b, bl, bx, blx
    Branch,
    /// cdp, mcr, mrc
    Coprocessor,
    /// ldc, ldcl, stc, stcl
    CoprocessorDataTransfer,
    /// vldr, vstr
    VfpSingleDataTransfer,
    /// vmla..vmov f32/f64
    VfpDataProcessing,
    /// vcvt/vcvtr variants
    VfpConvert,
    /// vpush, vpop, vldm, vstm
    VfpBlockDataTransfer,
    /// vmsr, vmrs
    VfpStatusRegister,
    /// cdp2, ldc2, stc2 (no condition code)
    Unconditional,
}

// ============================================================================
// Lookup tables
// ============================================================================

/// ARM register name strings for disassembly and error messages.
pub const ARM_REG_NAMES: [&str; 16] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc",
];

/// VFP single-precision register name lookup table.
const VFP_SINGLE_REG_NAMES: [&str; 32] = [
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
];

/// VFP double-precision register name lookup table.
const VFP_DOUBLE_REG_NAMES: [&str; 16] = [
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
];

// ============================================================================
// Helper functions
// ============================================================================

/// Extract the instruction group from a conditioned token.
///
/// Each conditioned instruction has 16 variants (eq..rsvd).
/// This function strips the condition code bits to return the base "eq" token.
///
/// Equivalent to C macro:
///   `ARM_INSTRUCTION_GROUP(x) = (((x) - TOK_ASM_nopeq) & 0xFFFFFFF0) + TOK_ASM_nopeq`
#[inline]
pub fn arm_instruction_group(token: i32) -> i32 {
    ((token - TOK_ASM_nopeq) & !0xF) + TOK_ASM_nopeq
}

/// Extract the 4-bit condition code (0-15) from a conditioned instruction token.
///
/// The condition code is the lower 4 bits of `(token - TOK_ASM_nopeq)`.
/// Returns values 0-15 corresponding to `ConditionCode` enum values.
#[inline]
pub fn condition_code_from_token(token: i32) -> u8 {
    ((token - TOK_ASM_nopeq) & 0xF) as u8
}

/// Map an assembly token to a core register number (0-15).
///
/// Handles all register naming conventions:
/// - r0..r15: direct register numbers
/// - a1..a4: argument/result registers (alias r0..r3)
/// - v1..v8: variable registers (alias r4..r11)
/// - sb, sl, fp, ip, sp, lr, pc: special names (alias r9..r15)
///
/// Returns `None` if the token is not a valid register token.
/// Mirrors `asm_parse_regvar()` from `arm-asm.c`.
#[inline]
pub fn token_to_register(token: i32) -> Option<u8> {
    if (TOK_ASM_r0..=TOK_ASM_r15).contains(&token) {
        // r0..r15 → 0..15
        Some((token - TOK_ASM_r0) as u8)
    } else if (TOK_ASM_a1..=TOK_ASM_v8).contains(&token) {
        // a1..a4 → 0..3, v1..v8 → 4..11
        Some((token - TOK_ASM_a1) as u8)
    } else if (TOK_ASM_sb..=TOK_ASM_pc).contains(&token) {
        // sb(r9)..pc(r15) → 9..15
        Some(((token - TOK_ASM_sb) + 9) as u8)
    } else {
        None
    }
}

/// Look up VFP single-precision register name by number (0-31).
///
/// Returns "s?" for out-of-range values.
#[inline]
pub fn vfp_single_reg_name(reg: u8) -> &'static str {
    if (reg as usize) < VFP_SINGLE_REG_NAMES.len() {
        VFP_SINGLE_REG_NAMES[reg as usize]
    } else {
        "s?"
    }
}

/// Look up VFP double-precision register name by number (0-15).
///
/// Returns "d?" for out-of-range values.
#[inline]
pub fn vfp_double_reg_name(reg: u8) -> &'static str {
    if (reg as usize) < VFP_DOUBLE_REG_NAMES.len() {
        VFP_DOUBLE_REG_NAMES[reg as usize]
    } else {
        "d?"
    }
}

/// Check if a token is a VFP single-precision register (s0-s31).
#[inline]
pub fn is_vfp_single_reg(token: i32) -> bool {
    (TOK_ASM_s0..=TOK_ASM_s31).contains(&token)
}

/// Check if a token is a VFP double-precision register (d0-d15).
#[inline]
pub fn is_vfp_double_reg(token: i32) -> bool {
    (TOK_ASM_d0..=TOK_ASM_d15).contains(&token)
}

/// Check if a token is a coprocessor name (p0-p15).
#[inline]
pub fn is_coprocessor(token: i32) -> bool {
    (TOK_ASM_p0..=TOK_ASM_p15).contains(&token)
}

/// Check if a token is a coprocessor register (c0-c15).
#[inline]
pub fn is_coprocessor_reg(token: i32) -> bool {
    (TOK_ASM_c0..=TOK_ASM_c15).contains(&token)
}

/// Classify a conditioned instruction token into its dispatch category.
///
/// Takes the "eq" variant token (as returned by `arm_instruction_group()`).
/// Returns `None` for tokens that are not conditioned instructions.
pub fn instruction_category(group_eq_token: i32) -> Option<ArmInstructionCategory> {
    match group_eq_token {
        TOK_ASM_nopeq | TOK_ASM_wfeeq | TOK_ASM_wfieq => {
            Some(ArmInstructionCategory::Nullary)
        }
        TOK_ASM_swieq | TOK_ASM_svceq => {
            Some(ArmInstructionCategory::Unary)
        }
        TOK_ASM_clzeq | TOK_ASM_sxtbeq | TOK_ASM_sxtheq |
        TOK_ASM_uxtbeq | TOK_ASM_uxtheq | TOK_ASM_movteq | TOK_ASM_movweq => {
            Some(ArmInstructionCategory::Binary)
        }
        t if (TOK_ASM_andeq..=TOK_ASM_mvnseq).contains(&t) => {
            Some(ArmInstructionCategory::DataProcessing)
        }
        t if (TOK_ASM_lsleq..=TOK_ASM_rrxseq).contains(&t) => {
            Some(ArmInstructionCategory::Shift)
        }
        TOK_ASM_muleq | TOK_ASM_mulseq | TOK_ASM_mlaeq | TOK_ASM_mlaseq |
        TOK_ASM_mlseq | TOK_ASM_udiveq | TOK_ASM_sdiveq => {
            Some(ArmInstructionCategory::Multiplication)
        }
        TOK_ASM_smulleq | TOK_ASM_smullseq | TOK_ASM_umulleq | TOK_ASM_umullseq |
        TOK_ASM_smlaleq | TOK_ASM_smlalseq | TOK_ASM_umlaleq | TOK_ASM_umlalseq => {
            Some(ArmInstructionCategory::LongMultiplication)
        }
        TOK_ASM_ldreq | TOK_ASM_ldrbeq | TOK_ASM_streq | TOK_ASM_strbeq |
        TOK_ASM_ldrexeq | TOK_ASM_ldrexbeq | TOK_ASM_ldrexheq |
        TOK_ASM_strexeq | TOK_ASM_strexbeq | TOK_ASM_strexheq => {
            Some(ArmInstructionCategory::SingleDataTransfer)
        }
        TOK_ASM_ldrheq | TOK_ASM_ldrsheq | TOK_ASM_ldrsbeq | TOK_ASM_strheq => {
            Some(ArmInstructionCategory::MiscDataTransfer)
        }
        TOK_ASM_pusheq | TOK_ASM_popeq |
        TOK_ASM_stmdaeq | TOK_ASM_ldmdaeq | TOK_ASM_stmeq | TOK_ASM_ldmeq |
        TOK_ASM_stmiaeq | TOK_ASM_ldmiaeq | TOK_ASM_stmdbeq | TOK_ASM_ldmdbeq |
        TOK_ASM_stmibeq | TOK_ASM_ldmibeq => {
            Some(ArmInstructionCategory::BlockDataTransfer)
        }
        TOK_ASM_beq | TOK_ASM_bleq | TOK_ASM_bxeq | TOK_ASM_blxeq => {
            Some(ArmInstructionCategory::Branch)
        }
        TOK_ASM_cdpeq | TOK_ASM_mcreq | TOK_ASM_mrceq => {
            Some(ArmInstructionCategory::Coprocessor)
        }
        TOK_ASM_ldceq | TOK_ASM_ldcleq | TOK_ASM_stceq | TOK_ASM_stcleq => {
            Some(ArmInstructionCategory::CoprocessorDataTransfer)
        }
        TOK_ASM_vldreq | TOK_ASM_vstreq => {
            Some(ArmInstructionCategory::VfpSingleDataTransfer)
        }
        t if (TOK_ASM_vmla_f32eq..=TOK_ASM_vmov_f64eq).contains(&t) => {
            Some(ArmInstructionCategory::VfpDataProcessing)
        }
        t if (TOK_ASM_vcvtr_s32_f64eq..=TOK_ASM_vcvt_f32_f64eq).contains(&t) => {
            Some(ArmInstructionCategory::VfpConvert)
        }
        TOK_ASM_vpusheq | TOK_ASM_vpopeq | TOK_ASM_vldmeq | TOK_ASM_vldmiaeq |
        TOK_ASM_vldmdbeq | TOK_ASM_vstmeq | TOK_ASM_vstmiaeq | TOK_ASM_vstmdbeq => {
            Some(ArmInstructionCategory::VfpBlockDataTransfer)
        }
        TOK_ASM_vmsreq | TOK_ASM_vmrseq => {
            Some(ArmInstructionCategory::VfpStatusRegister)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_ordering() {
        // Core registers are sequential
        assert_eq!(TOK_ASM_r15 - TOK_ASM_r0, 15);
        // Synonyms follow registers
        assert_eq!(TOK_ASM_a1, TOK_ASM_r15 + 1);
        assert_eq!(TOK_ASM_v8 - TOK_ASM_a1, 11);
        // Special names follow synonyms
        assert_eq!(TOK_ASM_sb, TOK_ASM_v8 + 1);
        assert_eq!(TOK_ASM_pc, TOK_ASM_sb + 6);
        // Coprocessors follow special names
        assert_eq!(TOK_ASM_p0, TOK_ASM_pc + 1);
        assert_eq!(TOK_ASM_p15 - TOK_ASM_p0, 15);
        // Coprocessor registers follow coprocessors
        assert_eq!(TOK_ASM_c0, TOK_ASM_p15 + 1);
        assert_eq!(TOK_ASM_c15 - TOK_ASM_c0, 15);
        // VFP single follows coprocessor regs
        assert_eq!(TOK_ASM_s0, TOK_ASM_c15 + 1);
        assert_eq!(TOK_ASM_s31 - TOK_ASM_s0, 31);
        // VFP double follows single
        assert_eq!(TOK_ASM_d0, TOK_ASM_s31 + 1);
        assert_eq!(TOK_ASM_d15 - TOK_ASM_d0, 15);
        // Status regs follow VFP double
        assert_eq!(TOK_ASM_fpsid, TOK_ASM_d15 + 1);
        // Unconditional instructions before nopeq
        assert!(TOK_ASM_cdp2 < TOK_ASM_nopeq);
        assert!(TOK_ASM_stc2l < TOK_ASM_nopeq);
        assert_eq!(TOK_ASM_stc2l + 1, TOK_ASM_nopeq);
    }

    #[test]
    fn test_arm_instruction_group() {
        // The eq variant is its own group
        assert_eq!(arm_instruction_group(TOK_ASM_nopeq), TOK_ASM_nopeq);
        // ne variant (eq+1) maps back to eq
        assert_eq!(arm_instruction_group(TOK_ASM_nopeq + 1), TOK_ASM_nopeq);
        // al variant (eq+14) maps back to eq
        assert_eq!(arm_instruction_group(TOK_ASM_nopeq + 14), TOK_ASM_nopeq);
        // rsvd variant (eq+15) maps back to eq
        assert_eq!(arm_instruction_group(TOK_ASM_nopeq + 15), TOK_ASM_nopeq);
        // Different instruction group
        assert_eq!(arm_instruction_group(TOK_ASM_andeq), TOK_ASM_andeq);
        assert_eq!(arm_instruction_group(TOK_ASM_andeq + 5), TOK_ASM_andeq);
    }

    #[test]
    fn test_condition_code_from_token() {
        assert_eq!(condition_code_from_token(TOK_ASM_nopeq), 0); // eq
        assert_eq!(condition_code_from_token(TOK_ASM_nopeq + 1), 1); // ne
        assert_eq!(condition_code_from_token(TOK_ASM_nopeq + 14), 14); // al
        assert_eq!(condition_code_from_token(TOK_ASM_nopeq + 15), 15); // rsvd
    }

    #[test]
    fn test_token_to_register() {
        // Direct register names
        assert_eq!(token_to_register(TOK_ASM_r0), Some(0));
        assert_eq!(token_to_register(TOK_ASM_r15), Some(15));
        assert_eq!(token_to_register(TOK_ASM_r9), Some(9));
        // Argument registers
        assert_eq!(token_to_register(TOK_ASM_a1), Some(0));
        assert_eq!(token_to_register(TOK_ASM_a4), Some(3));
        // Variable registers
        assert_eq!(token_to_register(TOK_ASM_v1), Some(4));
        assert_eq!(token_to_register(TOK_ASM_v8), Some(11));
        // Special registers
        assert_eq!(token_to_register(TOK_ASM_sb), Some(9));
        assert_eq!(token_to_register(TOK_ASM_pc), Some(15));
        assert_eq!(token_to_register(TOK_ASM_sp), Some(13));
        assert_eq!(token_to_register(TOK_ASM_lr), Some(14));
        // Out of range
        assert_eq!(token_to_register(TOK_ASM_p0), None);
        assert_eq!(token_to_register(-1), None);
    }

    #[test]
    fn test_data_processing_opcode_mapping() {
        // Verify the critical data processing opcode ordering.
        // opcode_idx = (group_eq - TOK_ASM_andeq) / 16
        // opcode = opcode_idx >> 1
        assert_eq!((TOK_ASM_andeq - TOK_ASM_andeq) / 16, 0);  // AND = 0
        assert_eq!((TOK_ASM_andseq - TOK_ASM_andeq) / 16, 1); // ANDS = 1 (same opcode, S set)
        assert_eq!((TOK_ASM_eoreq - TOK_ASM_andeq) / 16, 2);  // EOR = 2
        assert_eq!((TOK_ASM_subeq - TOK_ASM_andeq) / 16, 4);  // SUB = 4
        assert_eq!((TOK_ASM_addeq - TOK_ASM_andeq) / 16, 8);  // ADD = 8
        assert_eq!((TOK_ASM_cmpeq - TOK_ASM_andeq) / 16, 20); // CMP = 20
        assert_eq!((TOK_ASM_moveq - TOK_ASM_andeq) / 16, 26); // MOV = 26
        assert_eq!((TOK_ASM_mvnseq - TOK_ASM_andeq) / 16, 31); // MVNS = 31

        // Verify opcode extraction: opcode = (idx >> 1)
        assert_eq!((0 >> 1), 0);   // AND opcode = 0000
        assert_eq!((2 >> 1), 1);   // EOR opcode = 0001
        assert_eq!((4 >> 1), 2);   // SUB opcode = 0010
        assert_eq!((8 >> 1), 4);   // ADD opcode = 0100
        assert_eq!((20 >> 1), 10); // CMP opcode = 1010
        assert_eq!((26 >> 1), 13); // MOV opcode = 1101
        assert_eq!((30 >> 1), 15); // MVN opcode = 1111
    }

    #[test]
    fn test_is_vfp_registers() {
        assert!(is_vfp_single_reg(TOK_ASM_s0));
        assert!(is_vfp_single_reg(TOK_ASM_s31));
        assert!(!is_vfp_single_reg(TOK_ASM_d0));
        assert!(is_vfp_double_reg(TOK_ASM_d0));
        assert!(is_vfp_double_reg(TOK_ASM_d15));
        assert!(!is_vfp_double_reg(TOK_ASM_s0));
    }

    #[test]
    fn test_is_coprocessor() {
        assert!(is_coprocessor(TOK_ASM_p0));
        assert!(is_coprocessor(TOK_ASM_p15));
        assert!(!is_coprocessor(TOK_ASM_c0));
        assert!(is_coprocessor_reg(TOK_ASM_c0));
        assert!(is_coprocessor_reg(TOK_ASM_c15));
        assert!(!is_coprocessor_reg(TOK_ASM_p0));
    }

    #[test]
    fn test_vfp_reg_names() {
        assert_eq!(vfp_single_reg_name(0), "s0");
        assert_eq!(vfp_single_reg_name(31), "s31");
        assert_eq!(vfp_single_reg_name(32), "s?");
        assert_eq!(vfp_double_reg_name(0), "d0");
        assert_eq!(vfp_double_reg_name(15), "d15");
        assert_eq!(vfp_double_reg_name(16), "d?");
    }

    #[test]
    fn test_condition_code_enum() {
        assert_eq!(ConditionCode::from_u8(0), Some(ConditionCode::Eq));
        assert_eq!(ConditionCode::from_u8(14), Some(ConditionCode::Al));
        assert_eq!(ConditionCode::from_u8(15), Some(ConditionCode::Rsvd));
        assert_eq!(ConditionCode::from_u8(16), None);
        assert_eq!(ConditionCode::Eq.suffix(), "eq");
        assert_eq!(ConditionCode::Al.suffix(), "");
    }

    #[test]
    fn test_total_token_count() {
        // 125 simple + 162 groups * 16 = 2717
        assert_eq!(ARM_TOKEN_COUNT, 2717);
    }
}
