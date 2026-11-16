//! # `pii-veil-ffi`
//!
//! C-ABI Foreign Function Interface (`cdylib` / `staticlib`) for embedding `pii-veil`
//! inside Go (`cgo`), C/C++, Zig, C#, or Ruby applications.

use pii_veil_core::{RedactionMode, Vault, VeilEngine};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// Opaque handle holding a [`VeilEngine`] and its session [`Vault`].
pub struct VeilHandle {
    engine: VeilEngine,
    vault: Vault,
}

fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

fn string_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Creates a new [`VeilHandle`].
///
/// - `mode`: `0` = Placeholder, `1` = Synthetic, `2` = Mask.
/// - `secret_key`: Optional null-terminated C string for synthetic seed.
///
/// # Safety
/// `secret_key` must be either `NULL` or a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn veil_new(mode: u32, secret_key: *const c_char) -> *mut VeilHandle {
    let redaction_mode = match mode {
        1 => RedactionMode::Synthetic,
        2 => RedactionMode::Mask,
        _ => RedactionMode::Placeholder,
    };

    let mut engine = VeilEngine::new(redaction_mode);
    if let Some(key) = cstr_to_str(secret_key) {
        if !key.is_empty() {
            engine = engine.with_secret_key(key.as_bytes());
        }
    }

    Box::into_raw(Box::new(VeilHandle {
        engine,
        vault: Vault::new(),
    }))
}

/// Frees a [`VeilHandle`] previously allocated with [`veil_new`].
///
/// # Safety
/// `handle` must be either `NULL` or a valid pointer returned by [`veil_new`].
#[no_mangle]
pub unsafe extern "C" fn veil_free(handle: *mut VeilHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Redacts sensitive PII and secrets in `input_utf8` and records mappings in `handle`'s vault.
///
/// # Safety
/// `handle` must be a valid pointer from [`veil_new`], and `input_utf8` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn veil_redact(
    handle: *mut VeilHandle,
    input_utf8: *const c_char,
) -> *mut c_char {
    let Some(h) = handle.as_mut() else {
        return ptr::null_mut();
    };
    let Some(text) = cstr_to_str(input_utf8) else {
        return ptr::null_mut();
    };

    let redacted = h.engine.redact_with_vault(text, &mut h.vault);
    string_to_c_char(redacted)
}

/// Restores placeholders in `sanitized_utf8` back to original values using `handle`'s vault.
///
/// # Safety
/// `handle` must be a valid pointer from [`veil_new`], and `sanitized_utf8` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn veil_restore(
    handle: *mut VeilHandle,
    sanitized_utf8: *const c_char,
) -> *mut c_char {
    let Some(h) = handle.as_ref() else {
        return ptr::null_mut();
    };
    let Some(text) = cstr_to_str(sanitized_utf8) else {
        return ptr::null_mut();
    };

    let restored = h.vault.restore(text);
    string_to_c_char(restored)
}

/// Sanitizes a JSON string while preserving structure and redacting sensitive keys.
///
/// # Safety
/// `handle` must be a valid pointer from [`veil_new`], and `json_utf8` must be a valid null-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn veil_redact_json(
    handle: *mut VeilHandle,
    json_utf8: *const c_char,
) -> *mut c_char {
    let Some(h) = handle.as_mut() else {
        return ptr::null_mut();
    };
    let Some(json_str) = cstr_to_str(json_utf8) else {
        return ptr::null_mut();
    };

    match h.engine.redact_json_str(json_str, &mut h.vault) {
        Ok(sanitized) => string_to_c_char(sanitized),
        Err(_) => ptr::null_mut(),
    }
}

/// Frees a C string returned by [`veil_redact`], [`veil_restore`], or [`veil_redact_json`].
///
/// # Safety
/// `ptr` must be either `NULL` or a pointer returned by one of this crate's functions.
#[no_mangle]
pub unsafe extern "C" fn veil_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Returns the number of redacted entity mappings currently stored in `handle`'s vault.
///
/// # Safety
/// `handle` must be either `NULL` or a valid pointer to a [`VeilHandle`].
#[no_mangle]
pub unsafe extern "C" fn veil_vault_len(handle: *const VeilHandle) -> usize {
    handle.as_ref().map(|h| h.vault.len()).unwrap_or(0)
}

/// Clears all stored entity mappings in `handle`'s vault.
///
/// # Safety
/// `handle` must be either `NULL` or a valid pointer to a [`VeilHandle`].
#[no_mangle]
pub unsafe extern "C" fn veil_vault_clear(handle: *mut VeilHandle) {
    if let Some(h) = handle.as_mut() {
        h.vault.clear();
    }
}

/// Opaque handle for an active [`StreamingRestorer`].
pub struct VeilStreamingRestorer {
    restorer: pii_veil_core::StreamingRestorer,
}

/// Creates a new [`VeilStreamingRestorer`] bound to the current snapshot of `handle`'s vault.
///
/// # Safety
/// `handle` must be either `NULL` or a valid pointer to a [`VeilHandle`].
#[no_mangle]
pub unsafe extern "C" fn veil_streaming_restorer_new(
    handle: *const VeilHandle,
) -> *mut VeilStreamingRestorer {
    let Some(h) = handle.as_ref() else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(VeilStreamingRestorer {
        restorer: h.vault.streaming_restorer(),
    }))
}

/// Pushes a streaming token chunk through the restorer.
/// Returns restored text (or empty string if a placeholder is currently incomplete).
/// The returned string must be freed with [`veil_string_free`].
///
/// # Safety
/// `restorer` must be a valid pointer to a [`VeilStreamingRestorer`].
/// `chunk_utf8` must be either `NULL` or a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn veil_streaming_restorer_push(
    restorer: *mut VeilStreamingRestorer,
    chunk_utf8: *const c_char,
) -> *mut c_char {
    let Some(r) = restorer.as_mut() else {
        return ptr::null_mut();
    };
    let Some(chunk) = cstr_to_str(chunk_utf8) else {
        return ptr::null_mut();
    };
    let restored = r.restorer.push_chunk(chunk);
    string_to_c_char(restored)
}

/// Flushes any pending buffered tokens at the end of an LLM stream.
/// The returned string must be freed with [`veil_string_free`].
///
/// # Safety
/// `restorer` must be a valid pointer to a [`VeilStreamingRestorer`].
#[no_mangle]
pub unsafe extern "C" fn veil_streaming_restorer_finish(
    restorer: *mut VeilStreamingRestorer,
) -> *mut c_char {
    let Some(r) = restorer.as_mut() else {
        return ptr::null_mut();
    };
    let tail = r.restorer.finish();
    string_to_c_char(tail)
}

/// Frees a [`VeilStreamingRestorer`] allocated with [`veil_streaming_restorer_new`].
///
/// # Safety
/// `restorer` must be either `NULL` or a pointer returned by [`veil_streaming_restorer_new`].
#[no_mangle]
pub unsafe extern "C" fn veil_streaming_restorer_free(restorer: *mut VeilStreamingRestorer) {
    if !restorer.is_null() {
        drop(Box::from_raw(restorer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_abi_roundtrip() {
        unsafe {
            let handle = veil_new(0, ptr::null());
            assert!(!handle.is_null());

            let raw_input =
                CString::new("Contactar a carlos@fintech.mx o cobrar en 4532-0151-1283-0366")
                    .unwrap();
            let redacted_ptr = veil_redact(handle, raw_input.as_ptr());
            assert!(!redacted_ptr.is_null());

            let redacted_str = CStr::from_ptr(redacted_ptr).to_str().unwrap().to_string();
            assert!(redacted_str.contains("[EMAIL_1]"));
            assert!(redacted_str.contains("[CREDIT_CARD_1]"));
            veil_string_free(redacted_ptr);

            let reply = CString::new("Enviado a [EMAIL_1] con cargo a [CREDIT_CARD_1].").unwrap();
            let restored_ptr = veil_restore(handle, reply.as_ptr());
            let restored_str = CStr::from_ptr(restored_ptr).to_str().unwrap().to_string();
            assert_eq!(
                restored_str,
                "Enviado a carlos@fintech.mx con cargo a 4532-0151-1283-0366."
            );

            veil_string_free(restored_ptr);
            veil_free(handle);
        }
    }

    #[test]
    fn test_c_abi_streaming_roundtrip() {
        unsafe {
            let handle = veil_new(0, ptr::null());
            let prompt = CString::new("Mi mail es dev@acme.org y mi pin es 1234").unwrap();
            let redacted_ptr = veil_redact(handle, prompt.as_ptr());
            veil_string_free(redacted_ptr);

            assert_eq!(veil_vault_len(handle), 1);

            let restorer = veil_streaming_restorer_new(handle);
            assert!(!restorer.is_null());

            // Simulate split token: "[EMA" then "IL_1] verificado"
            let chunk1 = CString::new("Confirmado para [EMA").unwrap();
            let out1_ptr = veil_streaming_restorer_push(restorer, chunk1.as_ptr());
            let out1 = CStr::from_ptr(out1_ptr).to_str().unwrap().to_string();
            veil_string_free(out1_ptr);

            let chunk2 = CString::new("IL_1] ahora mismo.").unwrap();
            let out2_ptr = veil_streaming_restorer_push(restorer, chunk2.as_ptr());
            let out2 = CStr::from_ptr(out2_ptr).to_str().unwrap().to_string();
            veil_string_free(out2_ptr);

            let finish_ptr = veil_streaming_restorer_finish(restorer);
            let finish_tail = CStr::from_ptr(finish_ptr).to_str().unwrap().to_string();
            veil_string_free(finish_ptr);

            veil_streaming_restorer_free(restorer);
            veil_free(handle);

            let full_out = format!("{}{}{}", out1, out2, finish_tail);
            assert_eq!(full_out, "Confirmado para dev@acme.org ahora mismo.");
        }
    }
}
