//! Code coverage runtime for the TCC compiler.
//!
//! This module stores, merges, and outputs annotated coverage reports in
//! gcov-compatible format for programs compiled with the `-gcov` flag.
//!
//! C equivalent: `lib/tcov.c` (428 lines)
//!
//! ## Coverage Blob Binary Format
//!
//! All values are little-endian. The binary blob has the following structure:
//!
//! ```text
//! +0: 32-bit offset to coverage output filename
//! +4: filename \0
//!       function_name \0
//!       (align to 8-byte boundary)
//!       64-bit function start line
//!         line_record: 64-bit packed (end_line:28 | start_line:28 | flag=0xff:8)
//!                      64-bit execution counter
//!       \0 (end of function lines)
//!     \0 (end of file functions)
//!   \0 (end of all files)
//!   coverage_output_filename \0
//! ```
//!
//! ## Output Format
//!
//! The output file uses gcov-compatible format:
//!
//! ```text
//!         -:    0:Runs:N
//!         -:    0:All:cov_file Files:N Functions:N XX.XX%
//!         -:    0:File:source.c Functions:N XX.XX%
//!         -:    0:Function:func_name XX.XX%
//!     count:lineno:source_text
//!     #####:lineno:source_text        (uncovered)
//!     count*:lineno:source_text       (partial coverage)
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};

use crate::error::{TccError, TccResult};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Single coverage line record.
///
/// Represents one source-line range with its execution count.
///
/// C equivalent: `struct tcov_line` at `lib/tcov.c` lines 27–31.
#[derive(Debug, Clone)]
pub struct TcovLine {
    /// First (start) line number of this coverage block.
    pub fline: u32,
    /// Last (end) line number of this coverage block.
    pub lline: u32,
    /// Number of times this block was executed.
    pub count: u64,
}

/// Function coverage record.
///
/// Aggregates all coverage line records for a single function.
///
/// C equivalent: `struct tcov_function` at `lib/tcov.c` lines 33–39.
/// The C version uses `n_line`/`m_line` for manual dynamic-array management;
/// the Rust version uses `Vec<TcovLine>` with automatic growth.
#[derive(Debug, Clone)]
pub struct TcovFunction {
    /// Function name as it appears in the source.
    pub function: String,
    /// Line number where the function begins.
    pub first_line: u32,
    /// Line coverage records for this function.
    pub lines: Vec<TcovLine>,
}

/// File coverage record.
///
/// Aggregates all function coverage records for a single source file.
///
/// C equivalent: `struct tcov_file` at `lib/tcov.c` lines 41–47.
/// The C linked list (`next` pointer) is replaced by `Vec<TcovFile>` in the
/// parent container; `n_func`/`m_func` are replaced by `Vec<TcovFunction>`.
#[derive(Debug, Clone)]
pub struct TcovFile {
    /// Source filename.
    pub filename: String,
    /// Function coverage records for this file.
    pub functions: Vec<TcovFunction>,
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated C string from a byte slice, advancing the position
/// past the null terminator.
///
/// Returns an error if the slice is exhausted before a null terminator is
/// found, using [`TccError::Parse`] to report the malformed blob.
fn read_cstring(data: &[u8], pos: &mut usize) -> TccResult<String> {
    let start = *pos;
    while *pos < data.len() {
        if data[*pos] == 0 {
            let s = String::from_utf8_lossy(&data[start..*pos]).into_owned();
            *pos += 1; // skip null terminator
            return Ok(s);
        }
        *pos += 1;
    }
    Err(TccError::Parse {
        msg: "unterminated string in coverage blob".to_string(),
        line: 0,
        file: String::new(),
    })
}

/// Read a little-endian integer of the given byte width from a byte slice.
///
/// C equivalent: `get_value(unsigned char *p, int size)` at `lib/tcov.c`
/// lines 79–87.
///
/// Reads `size` bytes starting at `data[offset]` in little-endian order.
/// Out-of-bounds bytes are silently treated as zero (bounds-checked access).
fn get_value(data: &[u8], offset: usize, size: usize) -> u64 {
    let mut value: u64 = 0;
    for i in (0..size).rev() {
        let idx = offset.saturating_add(i);
        let byte = if idx < data.len() {
            u64::from(data[idx])
        } else {
            0
        };
        value = (value << 8) | byte;
    }
    value
}

/// Open a coverage output file for reading and writing.
///
/// C equivalent: `open_tcov_file(char *cov_filename)` at `lib/tcov.c`
/// lines 49–77.
///
/// The C version applies platform-specific exclusive file locks (Unix
/// `fcntl` with `F_SETLKW`/`F_WRLCK`, or Windows `LockFileEx`). In this
/// Rust port, platform-specific locking is not applied because the standard
/// library does not expose advisory locks; callers requiring multi-process
/// safety should use external coordination (e.g. the `fs2` crate).
fn open_tcov_file(filename: &str) -> TccResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(filename)
        .map_err(TccError::Io)
}

/// Sort functions within each file by `first_line`, and lines within each
/// function by `fline` (ascending) then `count` (descending).
///
/// C equivalent: `qsort` calls at `lib/tcov.c` lines 206–213 using
/// `sort_func` (lines 89–96) and `sort_line` (lines 98–107).
fn sort_coverage(files: &mut [TcovFile]) {
    for file in files.iter_mut() {
        file.functions
            .sort_by(|a, b| a.first_line.cmp(&b.first_line));
        for func in file.functions.iter_mut() {
            func.lines.sort_by(|a, b| {
                a.fline
                    .cmp(&b.fline)
                    .then_with(|| b.count.cmp(&a.count))
            });
        }
    }
}

/// Attempt to parse a count value and trailing character from a coverage
/// output line.
///
/// Parses lines of the form:
///   - `"        1:    2:source"` → `Some((1, ':'))`
///   - `"       1*:    2:source"` → `Some((1, '*'))`
///   - `"    #####:    2:source"` → `None` (no leading digits)
///   - `"        -:    2:source"` → `None` (no leading digits)
///
/// C equivalent: `sscanf(str, "%llu%c\n", &count, &c)` in
/// `merge_test_coverage()` at `lib/tcov.c` line 260.
fn parse_count_line(line: &str) -> Option<(u64, char)> {
    let trimmed = line.trim_start();
    let digit_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    if digit_end == 0 {
        return None;
    }
    let count: u64 = trimmed[..digit_end].parse().ok()?;
    let next_char = trimmed[digit_end..].chars().next()?;
    Some((count, next_char))
}

/// Compute aggregate coverage statistics across all files.
///
/// Returns `(total_files, total_functions, total_blocks, blocks_run)`.
///
/// C equivalent: the counting loop at `lib/tcov.c` lines 296–314.
fn compute_summary(files: &[TcovFile]) -> (u32, u32, u32, u32) {
    let mut total_files: u32 = 0;
    let mut total_funcs: u32 = 0;
    let mut total_blocks: u32 = 0;
    let mut total_run: u32 = 0;

    for file in files {
        total_files = total_files.saturating_add(1);
        for func in &file.functions {
            total_funcs = total_funcs.saturating_add(1);
            for line in &func.lines {
                total_blocks = total_blocks.saturating_add(1);
                if line.count != 0 {
                    total_run = total_run.saturating_add(1);
                }
            }
        }
    }

    (total_files, total_funcs, total_blocks, total_run)
}

/// Compute per-file coverage statistics.
///
/// Returns `(functions, blocks, blocks_run)`.
fn compute_file_summary(file: &TcovFile) -> (u32, u32, u32) {
    let mut funcs: u32 = 0;
    let mut blocks: u32 = 0;
    let mut blocks_run: u32 = 0;

    for func in &file.functions {
        funcs = funcs.saturating_add(1);
        for line in &func.lines {
            blocks = blocks.saturating_add(1);
            if line.count != 0 {
                blocks_run = blocks_run.saturating_add(1);
            }
        }
    }

    (funcs, blocks, blocks_run)
}

/// Compute per-function coverage statistics.
///
/// Returns `(blocks, blocks_run)`.
fn compute_func_summary(func: &TcovFunction) -> (u32, u32) {
    let mut blocks: u32 = 0;
    let mut blocks_run: u32 = 0;

    for line in &func.lines {
        blocks = blocks.saturating_add(1);
        if line.count != 0 {
            blocks_run = blocks_run.saturating_add(1);
        }
    }

    (blocks, blocks_run)
}

/// Compute a coverage percentage, returning 100.0 if there are no blocks.
///
/// C equivalent: the `if (blocks == 0) blocks = 1;` guard followed by
/// `100.0 * (double) blocks_run / blocks` at `lib/tcov.c` lines 313–316.
fn coverage_pct(blocks: u32, blocks_run: u32) -> f64 {
    if blocks == 0 {
        100.0
    } else {
        100.0 * f64::from(blocks_run) / f64::from(blocks)
    }
}

/// Read the next line from a buffered reader into `buf`, preserving the
/// trailing newline character. Returns `true` if a line was successfully
/// read, `false` on EOF.
fn read_source_line(reader: &mut impl BufRead, buf: &mut String) -> io::Result<bool> {
    buf.clear();
    let n = reader.read_line(buf)?;
    Ok(n > 0)
}

/// Write the gcov-compatible coverage report to the given writer.
///
/// C equivalent: the output section of `__store_test_coverage()` at
/// `lib/tcov.c` lines 295–416. Produces:
///
/// - Global header with run count and aggregate statistics
/// - Per-file sections with interleaved source lines
/// - Per-function coverage summaries
/// - Per-line coverage annotations (`count`, `#####`, or `count*`)
fn write_coverage_report(
    fp: &mut impl Write,
    files: &[TcovFile],
    cov_filename: &str,
    runs: u32,
) -> TccResult<()> {
    // ---------- Global header ----------
    // C: fprintf(fp, "        -:    0:Runs:%u\n", runs);
    writeln!(fp, "        -:    0:Runs:{}", runs).map_err(TccError::Io)?;

    // Global summary statistics
    let (total_files, total_funcs, total_blocks, total_run) = compute_summary(files);
    let pct = coverage_pct(total_blocks, total_run);
    writeln!(
        fp,
        "        -:    0:All:{} Files:{} Functions:{} {:.02}%",
        cov_filename, total_files, total_funcs, pct
    )
    .map_err(TccError::Io)?;

    // ---------- Per-file output ----------
    for file in files {
        // Attempt to open the source file for interleaved output.
        // C: `FILE *src = fopen(nfile->filename, "r");`
        // C: `if (src == NULL) goto next;`
        let src_file = match File::open(&file.filename) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut src = io::BufReader::new(src_file);
        let mut source_line = String::new();
        let mut curline: u32 = 1;

        // Per-file summary
        let (funcs, blocks, blocks_run) = compute_file_summary(file);
        let pct = coverage_pct(blocks, blocks_run);
        writeln!(
            fp,
            "        -:    0:File:{} Functions:{} {:.02}%",
            file.filename, funcs, pct
        )
        .map_err(TccError::Io)?;

        // ---------- Per-function output ----------
        for func in &file.functions {
            // Write uncovered source lines before this function.
            // C: while(curline < func->first_line && fgets(...))
            //      fprintf(fp, "        -:%5u:%s", curline++, str);
            while curline < func.first_line {
                if !read_source_line(&mut src, &mut source_line)? {
                    break;
                }
                write!(fp, "        -:{:5}:{}", curline, source_line)
                    .map_err(TccError::Io)?;
                curline = curline.saturating_add(1);
            }

            // Per-function summary
            let (f_blocks, f_blocks_run) = compute_func_summary(func);
            let f_pct = coverage_pct(f_blocks, f_blocks_run);
            writeln!(
                fp,
                "        -:    0:Function:{} {:.02}%",
                func.function, f_pct
            )
            .map_err(TccError::Io)?;

            // Per-line output with same-fline grouping.
            // C equivalent: the j-loop at lib/tcov.c lines 365–408.
            let mut j: usize = 0;
            while j < func.lines.len() {
                let fline = func.lines[j].fline;
                let mut lline = func.lines[j].lline;
                let mut count = func.lines[j].count;
                let mut has_zero = false;
                let mut same_line = fline == lline;

                j += 1;

                // Group all entries sharing the same start line.
                // Take maximum non-zero count; track if any have zero count.
                while j < func.lines.len() && func.lines[j].fline == fline {
                    let ncount = func.lines[j].count;
                    let nlline = func.lines[j].lline;

                    if ncount == 0 {
                        has_zero = true;
                    } else if ncount > count {
                        count = ncount;
                    }
                    same_line = func.lines[j].fline == nlline;
                    lline = nlline;
                    j += 1;
                }

                // If the start and end lines are the same, extend by one
                // to cover the actual source line.
                // C: if (same_line) lline++;
                if same_line {
                    lline = lline.saturating_add(1);
                }

                // Write uncovered source lines before this coverage block.
                while curline < fline {
                    if !read_source_line(&mut src, &mut source_line)? {
                        break;
                    }
                    write!(fp, "        -:{:5}:{}", curline, source_line)
                        .map_err(TccError::Io)?;
                    curline = curline.saturating_add(1);
                }

                // Write lines within this coverage block.
                while curline < lline {
                    if !read_source_line(&mut src, &mut source_line)? {
                        break;
                    }
                    if count == 0 {
                        // Uncovered: C format "    #####:%5u:%s"
                        write!(fp, "    #####:{:5}:{}", curline, source_line)
                            .map_err(TccError::Io)?;
                    } else if has_zero {
                        // Partial coverage: C format "%8llu*:%5u:%s"
                        write!(fp, "{:8}*:{:5}:{}", count, curline, source_line)
                            .map_err(TccError::Io)?;
                    } else {
                        // Fully covered: C format "%9llu:%5u:%s"
                        write!(fp, "{:9}:{:5}:{}", count, curline, source_line)
                            .map_err(TccError::Io)?;
                    }
                    curline = curline.saturating_add(1);
                }
            }
        }

        // Write remaining source lines after the last function.
        // C: while(fgets(str,sizeof(str),src))
        //      fprintf(fp,"        -:%5u:%s",curline++,str);
        while read_source_line(&mut src, &mut source_line)? {
            write!(fp, "        -:{:5}:{}", curline, source_line)
                .map_err(TccError::Io)?;
            curline = curline.saturating_add(1);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a binary coverage blob into structured [`TcovFile`] records.
///
/// C equivalent: `sort_test_coverage(unsigned char *p)` at `lib/tcov.c`
/// lines 110–215.
///
/// The binary blob format is documented in the module-level comment.
/// This function:
/// 1. Skips the 4-byte offset header
/// 2. Iterates over nested filename → function → line record entries
/// 3. Deduplicates files by filename and functions by function name
///    using [`HashMap`] for O(1) lookup
/// 4. Sorts functions by `first_line`, lines by `fline` (then `count` desc)
///
/// All buffer access uses bounds-checked slice indexing via [`get_value()`]
/// and [`read_cstring()`], eliminating any possibility of out-of-bounds reads.
pub fn parse_coverage_blob(data: &[u8]) -> TccResult<Vec<TcovFile>> {
    if data.len() < 4 {
        return Err(TccError::Parse {
            msg: "coverage blob too short (< 4 bytes)".to_string(),
            line: 0,
            file: String::new(),
        });
    }

    let mut files: Vec<TcovFile> = Vec::new();

    // HashMap for O(1) file-name deduplication.
    // C equivalent: linear scan over linked list at tcov.c lines 122–147.
    let mut file_index: HashMap<String, usize> = HashMap::new();

    // HashMap for O(1) function-name deduplication (keyed by file index
    // and function name).
    // C equivalent: linear scan at tcov.c lines 157–161.
    let mut func_index: HashMap<(usize, String), usize> = HashMap::new();

    let mut pos: usize = 4; // Skip 32-bit offset to coverage filename

    // Outer loop: iterate over source files
    while pos < data.len() && data[pos] != 0 {
        let filename = read_cstring(data, &mut pos)?;

        // Deduplicate: find existing file entry or create a new one.
        // Uses HashMap::get() and HashMap::insert().
        let file_idx = if let Some(&idx) = file_index.get(&filename) {
            idx
        } else {
            let idx = files.len();
            files.push(TcovFile {
                filename: filename.clone(),
                functions: Vec::new(),
            });
            file_index.insert(filename, idx);
            idx
        };

        // Middle loop: iterate over functions within this file
        while pos < data.len() && data[pos] != 0 {
            let func_name = read_cstring(data, &mut pos)?;

            // Align position to 8-byte boundary relative to blob start.
            // C equivalent: `p += -(p - start) & 7;` at tcov.c line 156.
            pos = pos.wrapping_add(7) & !7;

            // Ensure enough data remains for the 8-byte first_line value
            if pos.saturating_add(8) > data.len() {
                return Err(TccError::Parse {
                    msg: "coverage blob truncated at function start line".to_string(),
                    line: 0,
                    file: String::new(),
                });
            }

            // Read 64-bit function start line
            let first_line_raw = get_value(data, pos, 8);
            pos += 8;

            // Safe truncation: line numbers fit in u32
            let first_line = u32::try_from(first_line_raw).unwrap_or(u32::MAX);

            // Deduplicate function entries using HashMap::entry().
            let func_key = (file_idx, func_name.clone());
            let func_idx = match func_index.entry(func_key) {
                std::collections::hash_map::Entry::Occupied(e) => *e.get(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let idx = files[file_idx].functions.len();
                    files[file_idx].functions.push(TcovFunction {
                        function: func_name,
                        first_line,
                        lines: Vec::new(),
                    });
                    *e.insert(idx)
                }
            };

            // Inner loop: iterate over line records within this function
            while pos < data.len() && data[pos] != 0 {
                if pos.saturating_add(16) > data.len() {
                    return Err(TccError::Parse {
                        msg: "coverage blob truncated at line record".to_string(),
                        line: 0,
                        file: String::new(),
                    });
                }

                let val = get_value(data, pos, 8);
                // Extract fields from packed 64-bit value:
                //   bits [7:0]   = flag (0xff)
                //   bits [35:8]  = start line (28 bits)
                //   bits [63:36] = end line (28 bits)
                let fline = u32::try_from((val >> 8) & 0x0FFF_FFFF).unwrap_or(0);
                let lline = u32::try_from(val >> 36).unwrap_or(0);
                let count = get_value(data, pos + 8, 8);
                pos += 16;

                files[file_idx].functions[func_idx]
                    .lines
                    .push(TcovLine { fline, lline, count });
            }

            // Skip null terminator for line records
            if pos < data.len() {
                pos += 1;
            }
        }

        // Skip null terminator for functions
        if pos < data.len() {
            pos += 1;
        }
    }

    // Sort: functions by first_line, lines by fline / count (descending)
    sort_coverage(&mut files);
    Ok(files)
}

/// Merge current coverage data with existing coverage data from a previous
/// run.
///
/// C equivalent: `merge_test_coverage(tcov_file *file, FILE *fp,
/// unsigned int *pruns)` at `lib/tcov.c` lines 218–269.
///
/// Reads the existing coverage report content line by line, matches file
/// and line-number headers, and adds previous execution counts to the
/// current data. Returns the updated run count (previous + 1, or 1 for
/// the first run).
///
/// # Arguments
///
/// * `files` — Mutable slice of coverage file records to update in place.
/// * `existing_content` — Full text content of the previous `.tcov` file
///   (may be empty for a first run).
///
/// # Returns
///
/// The new run count to write in the output header.
pub fn merge_coverage(files: &mut [TcovFile], existing_content: &str) -> u32 {
    // C: *pruns = 1; if (fp == NULL) return;
    if existing_content.is_empty() {
        return 1;
    }

    let all_lines: Vec<&str> = existing_content.lines().collect();
    let mut line_idx: usize = 0;
    let mut runs: u32 = 1;

    // Parse run count from the first line: "        -:    0:Runs:N"
    // C: if (fgets(str,...) && (p = strrchr(str, ':')) &&
    //        (sscanf(p + 1, "%u", &runs) == 1))  *pruns = runs + 1;
    if let Some(&first) = all_lines.first() {
        if let Some(colon_pos) = first.rfind(':') {
            if let Ok(n) = first[colon_pos + 1..].trim().parse::<u32>() {
                runs = n.saturating_add(1);
            }
        }
        line_idx = 1;
    }

    // Iterate over each file, matching against existing output
    for file in files.iter_mut() {
        // Advance to the "0:File:<filename>" header.
        // C: while (fgets(str,...) && strstr(str,"0:File:")==NULL) {}
        let found = loop {
            if line_idx >= all_lines.len() {
                break false;
            }
            if all_lines[line_idx].contains("0:File:") {
                break true;
            }
            line_idx += 1;
        };

        if !found {
            break;
        }

        // Verify the filename matches exactly.
        // C: if ((p = strstr(str, "0:File:")) == NULL ||
        //        strncmp(p + 7, file->filename, len) != 0 ||
        //        p[7 + len] != ' ')  break;
        let header = all_lines[line_idx];
        let matched = if let Some(fpos) = header.find("0:File:") {
            let after = &header[fpos + 7..];
            after.starts_with(&file.filename)
                && (after.get(file.filename.len()..file.filename.len() + 1)
                    == Some(" "))
        } else {
            false
        };

        if !matched {
            break;
        }
        line_idx += 1;

        // For each function, merge line counts.
        for func in file.functions.iter_mut() {
            let mut next_zero = false;
            let mut curline: u32 = 0;

            for line_rec in func.lines.iter_mut() {
                let fline = line_rec.fline;

                // Advance through existing lines to find the matching line
                // number. Each line has format: <count_field>:<lineno>:<src>
                // C: while (curline < fline && fgets(str,...,fp))
                //      if ((p = strchr(str,':')) && sscanf(p+1,"%u",&tmp)==1)
                //          curline = tmp;
                while curline < fline && line_idx < all_lines.len() {
                    let s = all_lines[line_idx];
                    // Extract line number between first and second colons
                    if let Some(colon1) = s.find(':') {
                        let after = &s[colon1 + 1..];
                        if let Some(colon2_rel) = after.find(':') {
                            if let Ok(n) = after[..colon2_rel].trim().parse::<u32>() {
                                curline = n;
                            }
                        }
                    }
                    if curline < fline {
                        line_idx += 1;
                    }
                }

                // Parse count from the current line and merge.
                // C: if (sscanf(str, "%llu%c\n", &count, &c) == 2) {
                //        if (next_zero == 0) line->count += count;
                //        next_zero = c == '*';
                //    }
                if line_idx < all_lines.len() {
                    let s = all_lines[line_idx];
                    if let Some((existing_count, c)) = parse_count_line(s) {
                        if !next_zero {
                            line_rec.count =
                                line_rec.count.saturating_add(existing_count);
                        }
                        next_zero = c == '*';
                    } else {
                        next_zero = false;
                    }
                    line_idx += 1;
                }
            }
        }
    }

    runs
}

/// Store coverage data to file in gcov-compatible format.
///
/// C equivalent: `__store_test_coverage(unsigned char *p)` at `lib/tcov.c`
/// lines 272–428.
///
/// This is the main entry point for the coverage runtime. It:
/// 1. Extracts the coverage output filename from the binary blob
/// 2. Opens the output file (creating it if it does not exist)
/// 3. Parses the binary blob into structured coverage records
/// 4. Reads any existing coverage data and merges run counts
/// 5. Rewrites the file with the updated gcov-compatible report
///
/// # Arguments
///
/// * `data` — Raw binary coverage blob as emitted by the compiler.
///
/// # Errors
///
/// Returns [`TccError::Io`] if the coverage file cannot be opened or
/// written, or [`TccError::Parse`] if the binary blob is malformed.
pub fn store_test_coverage(data: &[u8]) -> TccResult<()> {
    if data.len() < 4 {
        return Err(TccError::Parse {
            msg: "coverage blob too short".to_string(),
            line: 0,
            file: String::new(),
        });
    }

    // 1. Extract coverage output filename from blob.
    //    The first 4 bytes are a little-endian offset to the filename.
    //    C: `char *cov_filename = (char *)p + get_value(p, 4);`
    let cov_filename_offset = usize::try_from(get_value(data, 0, 4)).map_err(|_| {
        TccError::Parse {
            msg: "coverage filename offset too large".to_string(),
            line: 0,
            file: String::new(),
        }
    })?;
    if cov_filename_offset >= data.len() {
        return Err(TccError::Parse {
            msg: "coverage filename offset out of range".to_string(),
            line: 0,
            file: String::new(),
        });
    }
    let mut fname_pos = cov_filename_offset;
    let cov_filename = read_cstring(data, &mut fname_pos)?;

    // 2. Open the coverage file for read + write (creating if needed).
    //    C: `fp = open_tcov_file(cov_filename);`
    let mut fp = open_tcov_file(&cov_filename)?;

    // 3. Parse the binary blob into structured records.
    //    C: `file = sort_test_coverage(p);`
    let mut files = parse_coverage_blob(data)?;

    // 4. Read existing file content for merging.
    let mut existing = String::new();
    fp.read_to_string(&mut existing).map_err(TccError::Io)?;

    // 5. Merge with existing coverage data (updates counts in place).
    //    C: `merge_test_coverage(file, fp, &runs);`
    let runs = merge_coverage(&mut files, &existing);

    // 6. Rewind and rewrite the coverage report.
    //    C: `fseek(fp, 0, SEEK_SET);`
    fp.seek(SeekFrom::Start(0)).map_err(TccError::Io)?;
    write_coverage_report(&mut fp, &files, &cov_filename, runs)?;

    // 7. Truncate the file to the current position to remove any leftover
    //    data from a previous (possibly longer) report.
    let final_pos = fp.stream_position().map_err(TccError::Io)?;
    fp.set_len(final_pos).map_err(TccError::Io)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-file single-function coverage blob for testing.
    fn build_test_blob() -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&[0u8; 4]); // offset placeholder
        blob.extend_from_slice(b"test.c\0");
        blob.extend_from_slice(b"main\0");
        while blob.len() % 8 != 0 { blob.push(0); }
        blob.extend_from_slice(&1u64.to_le_bytes()); // first_line=1
        // line record 1: fline=2, lline=2, count=5
        let packed1: u64 = (2u64 << 36) | (2u64 << 8) | 0xff;
        blob.extend_from_slice(&packed1.to_le_bytes());
        blob.extend_from_slice(&5u64.to_le_bytes());
        // line record 2: fline=3, lline=3, count=0
        let packed2: u64 = (3u64 << 36) | (3u64 << 8) | 0xff;
        blob.extend_from_slice(&packed2.to_le_bytes());
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.push(0); // end lines
        blob.push(0); // end functions
        blob.push(0); // end files
        let offset = blob.len();
        blob[0] = (offset & 0xFF) as u8;
        blob[1] = ((offset >> 8) & 0xFF) as u8;
        blob[2] = ((offset >> 16) & 0xFF) as u8;
        blob[3] = ((offset >> 24) & 0xFF) as u8;
        blob.extend_from_slice(b"output.tcov\0");
        blob
    }

    /// Build a multi-file blob with 2 source files and 3 functions.
    fn build_multi_file_blob() -> Vec<u8> {
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&[0u8; 4]);
        // --- File 1: alpha.c ---
        blob.extend_from_slice(b"alpha.c\0");
        blob.extend_from_slice(b"init\0");
        while blob.len() % 8 != 0 { blob.push(0); }
        blob.extend_from_slice(&10u64.to_le_bytes());
        let p = (10u64 << 36) | (10u64 << 8) | 0xff;
        blob.extend_from_slice(&p.to_le_bytes());
        blob.extend_from_slice(&3u64.to_le_bytes());
        blob.push(0); // end lines for init
        blob.extend_from_slice(b"run\0");
        while blob.len() % 8 != 0 { blob.push(0); }
        blob.extend_from_slice(&20u64.to_le_bytes());
        let p2 = (21u64 << 36) | (20u64 << 8) | 0xff;
        blob.extend_from_slice(&p2.to_le_bytes());
        blob.extend_from_slice(&7u64.to_le_bytes());
        blob.push(0); // end lines for run
        blob.push(0); // end functions for alpha.c
        // --- File 2: beta.c ---
        blob.extend_from_slice(b"beta.c\0");
        blob.extend_from_slice(b"cleanup\0");
        while blob.len() % 8 != 0 { blob.push(0); }
        blob.extend_from_slice(&5u64.to_le_bytes());
        let p3 = (6u64 << 36) | (5u64 << 8) | 0xff;
        blob.extend_from_slice(&p3.to_le_bytes());
        blob.extend_from_slice(&0u64.to_le_bytes());
        blob.push(0); // end lines
        blob.push(0); // end functions for beta.c
        blob.push(0); // end files
        let offset = blob.len();
        blob[0] = (offset & 0xFF) as u8;
        blob[1] = ((offset >> 8) & 0xFF) as u8;
        blob[2] = ((offset >> 16) & 0xFF) as u8;
        blob[3] = ((offset >> 24) & 0xFF) as u8;
        blob.extend_from_slice(b"multi.tcov\0");
        blob
    }

    // ===== get_value =====
    #[test]
    fn test_get_value_single_byte() { assert_eq!(get_value(&[0xAB], 0, 1), 0xAB); }
    #[test]
    fn test_get_value_two_bytes_le() { assert_eq!(get_value(&[0x01, 0x02], 0, 2), 0x0201); }
    #[test]
    fn test_get_value_four_bytes_le() {
        assert_eq!(get_value(&[0x78, 0x56, 0x34, 0x12], 0, 4), 0x1234_5678);
    }
    #[test]
    fn test_get_value_eight_bytes_le() {
        let data = 0x0102_0304_0506_0708u64.to_le_bytes();
        assert_eq!(get_value(&data, 0, 8), 0x0102_0304_0506_0708);
    }
    #[test]
    fn test_get_value_with_offset() {
        assert_eq!(get_value(&[0x00, 0x00, 0xAA, 0xBB], 2, 2), 0xBBAA);
    }
    #[test]
    fn test_get_value_partial_oob() {
        assert_eq!(get_value(&[0xFF, 0xAB], 0, 4), 0x0000_ABFF);
    }
    #[test]
    fn test_get_value_empty_slice() {
        let empty: [u8; 0] = [];
        assert_eq!(get_value(&empty, 0, 4), 0);
    }
    #[test]
    fn test_get_value_zero_size() { assert_eq!(get_value(&[0xFF], 0, 0), 0); }

    // ===== read_cstring =====
    #[test]
    fn test_read_cstring_basic() {
        let data = b"hello\0world\0";
        let mut pos = 0;
        assert_eq!(read_cstring(data, &mut pos).unwrap(), "hello");
        assert_eq!(pos, 6);
        assert_eq!(read_cstring(data, &mut pos).unwrap(), "world");
        assert_eq!(pos, 12);
    }
    #[test]
    fn test_read_cstring_empty_str() {
        let mut pos = 0;
        assert_eq!(read_cstring(b"\0rest", &mut pos).unwrap(), "");
        assert_eq!(pos, 1);
    }
    #[test]
    fn test_read_cstring_unterminated() {
        let mut pos = 0;
        assert!(read_cstring(b"no_null", &mut pos).is_err());
    }
    #[test]
    fn test_read_cstring_at_end() {
        let mut pos = 0;
        assert!(read_cstring(b"", &mut pos).is_err());
    }

    // ===== parse_coverage_blob =====
    #[test]
    fn test_parse_blob_single_file() {
        let blob = build_test_blob();
        let files = parse_coverage_blob(&blob).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "test.c");
        let func = &files[0].functions[0];
        assert_eq!(func.function, "main");
        assert_eq!(func.first_line, 1);
        assert_eq!(func.lines.len(), 2);
        assert_eq!(func.lines[0].fline, 2);
        assert_eq!(func.lines[0].count, 5);
        assert_eq!(func.lines[1].fline, 3);
        assert_eq!(func.lines[1].count, 0);
    }
    #[test]
    fn test_parse_blob_multi_file() {
        let blob = build_multi_file_blob();
        let files = parse_coverage_blob(&blob).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "alpha.c");
        assert_eq!(files[1].filename, "beta.c");
        assert_eq!(files[0].functions[0].function, "init");
        assert_eq!(files[0].functions[1].function, "run");
        assert_eq!(files[1].functions[0].function, "cleanup");
    }
    #[test]
    fn test_parse_blob_too_short() {
        assert!(parse_coverage_blob(&[0u8; 3]).is_err());
    }
    #[test]
    fn test_parse_blob_empty_after_header() {
        let data = [0x10, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_coverage_blob(&data).unwrap().len(), 0);
    }

    // ===== parse_count_line =====
    #[test]
    fn test_parse_count_line_normal() {
        assert_eq!(parse_count_line("        7:    2:source"), Some((7, ':')));
    }
    #[test]
    fn test_parse_count_line_partial() {
        assert_eq!(parse_count_line("       7*:    2:source"), Some((7, '*')));
    }
    #[test]
    fn test_parse_count_line_uncovered() {
        assert_eq!(parse_count_line("    #####:    2:source"), None);
    }
    #[test]
    fn test_parse_count_line_no_code() {
        assert_eq!(parse_count_line("        -:    2:source"), None);
    }
    #[test]
    fn test_parse_count_line_large() {
        assert_eq!(parse_count_line("123456789:    5:text"), Some((123_456_789, ':')));
    }

    // ===== coverage_pct =====
    #[test]
    fn test_coverage_pct_zero() {
        assert!((coverage_pct(0, 0) - 100.0).abs() < f64::EPSILON);
    }
    #[test]
    fn test_coverage_pct_half() {
        assert!((coverage_pct(2, 1) - 50.0).abs() < f64::EPSILON);
    }
    #[test]
    fn test_coverage_pct_full() {
        assert!((coverage_pct(4, 4) - 100.0).abs() < f64::EPSILON);
    }
    #[test]
    fn test_coverage_pct_none() {
        assert!(coverage_pct(10, 0).abs() < f64::EPSILON);
    }

    // ===== compute_*_summary =====
    #[test]
    fn test_compute_func_summary() {
        let func = TcovFunction {
            function: "f".into(), first_line: 1,
            lines: vec![
                TcovLine { fline: 1, lline: 1, count: 5 },
                TcovLine { fline: 2, lline: 2, count: 0 },
                TcovLine { fline: 3, lline: 3, count: 3 },
            ],
        };
        assert_eq!(compute_func_summary(&func), (3, 2));
    }
    #[test]
    fn test_compute_file_summary() {
        let file = TcovFile {
            filename: "a.c".into(),
            functions: vec![
                TcovFunction {
                    function: "f1".into(), first_line: 1,
                    lines: vec![
                        TcovLine { fline: 1, lline: 1, count: 5 },
                        TcovLine { fline: 2, lline: 2, count: 0 },
                    ],
                },
                TcovFunction {
                    function: "f2".into(), first_line: 10,
                    lines: vec![TcovLine { fline: 10, lline: 10, count: 1 }],
                },
            ],
        };
        assert_eq!(compute_file_summary(&file), (2, 3, 2));
    }
    #[test]
    fn test_compute_summary() {
        let files = vec![
            TcovFile {
                filename: "a.c".into(),
                functions: vec![TcovFunction {
                    function: "f1".into(), first_line: 1,
                    lines: vec![
                        TcovLine { fline: 1, lline: 1, count: 5 },
                        TcovLine { fline: 2, lline: 2, count: 0 },
                    ],
                }],
            },
            TcovFile { filename: "b.c".into(), functions: vec![] },
        ];
        assert_eq!(compute_summary(&files), (2, 1, 2, 1));
    }

    // ===== sort_coverage =====
    #[test]
    fn test_sort_functions_by_first_line() {
        let mut files = vec![TcovFile {
            filename: "t.c".into(),
            functions: vec![
                TcovFunction { function: "b".into(), first_line: 20, lines: vec![] },
                TcovFunction { function: "a".into(), first_line: 1, lines: vec![] },
            ],
        }];
        sort_coverage(&mut files);
        assert_eq!(files[0].functions[0].function, "a");
        assert_eq!(files[0].functions[1].function, "b");
    }
    #[test]
    fn test_sort_lines_fline_then_count_desc() {
        let mut files = vec![TcovFile {
            filename: "t.c".into(),
            functions: vec![TcovFunction {
                function: "f".into(), first_line: 1,
                lines: vec![
                    TcovLine { fline: 5, lline: 5, count: 1 },
                    TcovLine { fline: 3, lline: 3, count: 2 },
                    TcovLine { fline: 3, lline: 3, count: 10 },
                ],
            }],
        }];
        sort_coverage(&mut files);
        let lines = &files[0].functions[0].lines;
        assert_eq!((lines[0].fline, lines[0].count), (3, 10));
        assert_eq!((lines[1].fline, lines[1].count), (3, 2));
        assert_eq!((lines[2].fline, lines[2].count), (5, 1));
    }

    // ===== merge_coverage =====
    #[test]
    fn test_merge_empty_existing() {
        let mut files = vec![TcovFile {
            filename: "t.c".into(),
            functions: vec![TcovFunction {
                function: "m".into(), first_line: 1,
                lines: vec![TcovLine { fline: 2, lline: 2, count: 1 }],
            }],
        }];
        assert_eq!(merge_coverage(&mut files, ""), 1);
        assert_eq!(files[0].functions[0].lines[0].count, 1);
    }
    #[test]
    fn test_merge_increments_runs() {
        let mut files = vec![TcovFile {
            filename: "t.c".into(),
            functions: vec![TcovFunction {
                function: "m".into(), first_line: 1,
                lines: vec![
                    TcovLine { fline: 2, lline: 2, count: 1 },
                    TcovLine { fline: 3, lline: 3, count: 0 },
                ],
            }],
        }];
        // Existing content must include proper gcov headers for merge to find
        let existing = "\
        -:    0:Runs:3\n\
        -:    0:All:out.tcov Files:1 Functions:1 50.00%\n\
        -:    0:File:t.c Functions:1 50.00%\n\
        -:    0:Function:m 50.00%\n\
        7:    2:    int x = 1;\n\
    #####:    3:    int y = 2;\n";
        let runs = merge_coverage(&mut files, existing);
        assert_eq!(runs, 4);
        assert_eq!(files[0].functions[0].lines[0].count, 8);
        assert_eq!(files[0].functions[0].lines[1].count, 0);
    }
    #[test]
    fn test_merge_partial_marker() {
        let mut files = vec![TcovFile {
            filename: "t.c".into(),
            functions: vec![TcovFunction {
                function: "m".into(), first_line: 1,
                lines: vec![TcovLine { fline: 5, lline: 5, count: 2 }],
            }],
        }];
        let existing = "\
        -:    0:Runs:1\n\
        -:    0:All:out.tcov Files:1 Functions:1 100.00%\n\
        -:    0:File:t.c Functions:1 100.00%\n\
        -:    0:Function:m 100.00%\n\
       10*:    5:    x++;\n";
        assert_eq!(merge_coverage(&mut files, existing), 2);
        assert_eq!(files[0].functions[0].lines[0].count, 12);
    }

    // ===== write_coverage_report =====
    #[test]
    fn test_write_report_empty() {
        let mut buf: Vec<u8> = Vec::new();
        write_coverage_report(&mut buf, &[], "out.tcov", 3).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Runs:3"));
        assert!(out.contains("All:out.tcov Files:0 Functions:0 100.00%"));
    }
    #[test]
    fn test_write_report_with_data() {
        use std::io::Write as _;

        // Create a temporary source file so write_coverage_report can open it
        let tmpdir = std::env::temp_dir();
        let src_path = tmpdir.join("blitzy_adhoc_test_tcov_src.c");
        {
            let mut f = File::create(&src_path).unwrap();
            writeln!(f, "int main() {{").unwrap();
            writeln!(f, "    return 0;").unwrap();
            writeln!(f, "}}").unwrap();
        }
        let src_str = src_path.to_string_lossy().to_string();

        let files = vec![TcovFile {
            filename: src_str.clone(),
            functions: vec![TcovFunction {
                function: "main".into(), first_line: 1,
                lines: vec![
                    TcovLine { fline: 1, lline: 1, count: 5 },
                    TcovLine { fline: 2, lline: 2, count: 0 },
                ],
            }],
        }];
        let mut buf: Vec<u8> = Vec::new();
        write_coverage_report(&mut buf, &files, "out.tcov", 1).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Runs:1"), "output: {}", out);
        assert!(out.contains("Files:1 Functions:1"), "output: {}", out);
        assert!(out.contains(&format!("File:{}", src_str)), "output: {}", out);
        assert!(out.contains("Function:main"), "output: {}", out);

        let _ = std::fs::remove_file(&src_path);
    }

    // ===== store_test_coverage integration =====
    #[test]
    fn test_store_roundtrip() {
        use std::io::Read;
        let tmpdir = std::env::temp_dir();
        let cov_path = tmpdir.join("blitzy_adhoc_test_tcov_out.tcov");
        let cov_str = cov_path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&cov_path);

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&[0u8; 4]);
        blob.extend_from_slice(b"test.c\0");
        blob.extend_from_slice(b"main\0");
        while blob.len() % 8 != 0 { blob.push(0); }
        blob.extend_from_slice(&1u64.to_le_bytes());
        let packed = (2u64 << 36) | (2u64 << 8) | 0xff;
        blob.extend_from_slice(&packed.to_le_bytes());
        blob.extend_from_slice(&10u64.to_le_bytes());
        blob.push(0);
        blob.push(0);
        blob.push(0);
        let offset = blob.len();
        blob[0] = (offset & 0xFF) as u8;
        blob[1] = ((offset >> 8) & 0xFF) as u8;
        blob[2] = ((offset >> 16) & 0xFF) as u8;
        blob[3] = ((offset >> 24) & 0xFF) as u8;
        blob.extend_from_slice(cov_str.as_bytes());
        blob.push(0);

        // Run 1
        store_test_coverage(&blob).unwrap();
        let mut c1 = String::new();
        File::open(&cov_path).unwrap().read_to_string(&mut c1).unwrap();
        assert!(c1.contains("Runs:1"), "first run: {}", c1);

        // Run 2 — merge
        store_test_coverage(&blob).unwrap();
        let mut c2 = String::new();
        File::open(&cov_path).unwrap().read_to_string(&mut c2).unwrap();
        assert!(c2.contains("Runs:2"), "second run: {}", c2);

        let _ = std::fs::remove_file(&cov_path);
    }
}
