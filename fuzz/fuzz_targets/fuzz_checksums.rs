#![no_main]
use libfuzzer_sys::fuzz_target;
use pii_veil_core::{
    is_valid_arg_cuit, is_valid_chilean_rut, is_valid_iban, is_valid_ipv4, is_valid_luhn,
    is_valid_national_id, is_valid_spanish_dni_nie,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = is_valid_luhn(s);
        let _ = is_valid_iban(s);
        let _ = is_valid_national_id(s);
        let _ = is_valid_spanish_dni_nie(s);
        let _ = is_valid_arg_cuit(s);
        let _ = is_valid_chilean_rut(s);
        let _ = is_valid_ipv4(s);
    }
});
