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
}
