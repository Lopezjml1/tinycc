//! DSO (Dynamic Shared Object) handle symbol.
//!
//! Provides the `__dso_handle` symbol with hidden visibility required for
//! destructor registration in shared libraries. The original C implementation
//! is a single-line self-referential pointer:
//!
//! ```c
//! void * __dso_handle __attribute((visibility("hidden"))) = &__dso_handle;
//! ```
//!
//! # Background
//!
//! In ELF shared objects, `__dso_handle` is a hidden symbol whose value is its
//! own address. The C runtime uses it as a unique "cookie" to identify which
//! shared library registered a particular `__cxa_atexit` destructor. When the
//! shared library is unloaded via `dlclose()`, the dynamic linker invokes only
//! those destructors whose DSO handle matches the library being unloaded.
//!
//! The symbol must have **hidden visibility** so that each shared object gets
//! its own private copy rather than interposing on a single global instance.
//!
//! # Rust Translation
//!
//! Since `TinyCC` is a compiler that *emits* code (rather than linking itself as
//! a shared library), this module provides a helper struct [`DsoHandle`] that
//! generates the appropriate zero-initialized bytes for the `__dso_handle`
//! symbol in the compiled output's data section. The actual address resolution
//! (making `__dso_handle` point to itself) is performed by the linker backend
//! during relocation processing.
//!
//! C equivalent: `lib/dsohandle.c` (1 line)

/// Name of the DSO handle symbol as it appears in ELF symbol tables.
pub(crate) const DSO_HANDLE_SYMBOL_NAME: &str = "__dso_handle";

/// DSO handle symbol emitter.
///
/// In the C original, `__dso_handle` is a self-referential `void*` pointer
/// with hidden visibility. This struct provides the Rust-side representation
/// and helper for emitting the symbol data into the compiled output's data
/// section.
///
/// C equivalent: `void * __dso_handle __attribute((visibility("hidden"))) = &__dso_handle;`
///
/// # Usage
///
/// The linker backend uses [`DsoHandle::emit_dso_handle_bytes`] when generating
/// shared objects to create the initial zero-filled placeholder. A relocation
/// entry is then added so the dynamic linker resolves the pointer to the
/// symbol's own address at load time.
///
/// ```rust,ignore
/// let bytes = DsoHandle::emit_dso_handle_bytes(8); // 64-bit pointer
/// assert_eq!(bytes.len(), 8);
/// // All bytes are zero — the self-referential address is resolved at link time
/// assert!(bytes.iter().all(|&b| b == 0));
/// ```
pub(crate) struct DsoHandle;

impl DsoHandle {
    /// Emit the `__dso_handle` symbol bytes for the target output.
    ///
    /// Generates a zero-initialized byte vector of the given pointer size.
    /// In ELF shared objects, `__dso_handle` is a hidden symbol that points
    /// to itself. The zero bytes serve as a placeholder; the self-referential
    /// address is resolved at link time through a relocation entry.
    ///
    /// # Arguments
    ///
    /// * `pointer_size` — Size of a pointer on the target architecture in bytes.
    ///   Typically 4 for 32-bit targets (i386, ARM) or 8 for 64-bit targets
    ///   (`x86_64`, `AArch64`, RISC-V 64).
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` of length `pointer_size`, filled with zero bytes. The caller
    /// (linker backend) writes these bytes into the output's data section and
    /// emits a relocation that will cause the dynamic linker to fill in the
    /// symbol's own address at load time.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // 32-bit target: 4-byte pointer
    /// let bytes_32 = DsoHandle::emit_dso_handle_bytes(4);
    /// assert_eq!(bytes_32, vec![0u8; 4]);
    ///
    /// // 64-bit target: 8-byte pointer
    /// let bytes_64 = DsoHandle::emit_dso_handle_bytes(8);
    /// assert_eq!(bytes_64, vec![0u8; 8]);
    /// ```
    pub(crate) fn emit_dso_handle_bytes(pointer_size: usize) -> Vec<u8> {
        // Self-referential pointer: the initial value is zero because the actual
        // address of __dso_handle is not known until link time. The linker backend
        // emits a relocation entry (e.g., R_X86_64_RELATIVE for x86_64 ELF) that
        // instructs the dynamic linker to patch this location with the symbol's
        // runtime address.
        //
        // This is safe by construction: Vec<u8> is bounds-checked, and the size is
        // determined by the target architecture's pointer width — no buffer overflows
        // are possible regardless of input.
        vec![0u8; pointer_size]
    }

    /// Returns the standard symbol name for the DSO handle.
    ///
    /// This is always `"__dso_handle"` per the ELF/C runtime ABI convention.
    /// Provided as a method for convenience when the linker backend needs to
    /// register the symbol in the output's symbol table.
    pub(crate) fn symbol_name() -> &'static str {
        DSO_HANDLE_SYMBOL_NAME
    }

    /// Returns whether the DSO handle symbol should have hidden visibility.
    ///
    /// Per the ELF ABI, `__dso_handle` must have `STV_HIDDEN` visibility so
    /// that each shared object receives its own private copy. This ensures
    /// that `__cxa_atexit` destructors are correctly associated with their
    /// originating shared library.
    ///
    /// Always returns `true`.
    pub(crate) fn is_hidden() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_dso_handle_bytes_32bit() {
        let bytes = DsoHandle::emit_dso_handle_bytes(4);
        assert_eq!(bytes.len(), 4);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn emit_dso_handle_bytes_64bit() {
        let bytes = DsoHandle::emit_dso_handle_bytes(8);
        assert_eq!(bytes.len(), 8);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn emit_dso_handle_bytes_zero() {
        let bytes = DsoHandle::emit_dso_handle_bytes(0);
        assert!(bytes.is_empty());
    }

    #[test]
    fn symbol_name_is_correct() {
        assert_eq!(DsoHandle::symbol_name(), "__dso_handle");
        assert_eq!(DSO_HANDLE_SYMBOL_NAME, "__dso_handle");
    }

    #[test]
    fn visibility_is_hidden() {
        assert!(DsoHandle::is_hidden());
    }
}
