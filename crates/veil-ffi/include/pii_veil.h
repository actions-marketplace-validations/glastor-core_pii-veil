#ifndef PII_VEIL_H
#define PII_VEIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VeilHandle VeilHandle;

/**
 * Creates a new `VeilHandle` instance.
 * `mode`: 0 = Placeholder, 1 = Synthetic, 2 = Mask.
 * `secret_key`: Optional null-terminated UTF-8 string (may be NULL).
 */
VeilHandle* veil_new(uint32_t mode, const char* secret_key);

/**
 * Frees a `VeilHandle` created by `veil_new`.
 */
void veil_free(VeilHandle* handle);

/**
 * Redacts PII and secrets in `input_utf8` and records mappings in the handle's session vault.
 * Returns a newly allocated null-terminated UTF-8 C string that must be freed with `veil_string_free`.
 */
char* veil_redact(VeilHandle* handle, const char* input_utf8);

/**
 * Restores placeholders/tokens in `sanitized_utf8` using the handle's session vault.
 * Returns a newly allocated null-terminated UTF-8 C string that must be freed with `veil_string_free`.
 */
char* veil_restore(VeilHandle* handle, const char* sanitized_utf8);

/**
 * Sanitizes a JSON string while preserving structure and redacting sensitive keys.
 * Returns a newly allocated null-terminated UTF-8 C string that must be freed with `veil_string_free`.
 */
char* veil_redact_json(VeilHandle* handle, const char* json_utf8);

/**
 * Frees a C string returned by `veil_redact`, `veil_restore`, or `veil_redact_json`.
 */
void veil_string_free(char* ptr);

/**
 * Returns the number of entity mappings currently stored in the handle's vault.
 */
size_t veil_vault_len(const VeilHandle* handle);

/**
 * Clears all entity mappings currently stored in the handle's vault.
 */
void veil_vault_clear(VeilHandle* handle);

typedef struct VeilStreamingRestorer VeilStreamingRestorer;

/**
 * Creates a new streaming restorer bound to the handle's current vault snapshot.
 */
VeilStreamingRestorer* veil_streaming_restorer_new(const VeilHandle* handle);

/**
 * Pushes a token chunk into the streaming restorer.
 * Returns newly restored text (or empty string). Must be freed with `veil_string_free`.
 */
char* veil_streaming_restorer_push(VeilStreamingRestorer* restorer, const char* chunk_utf8);

/**
 * Flushes any pending buffered tokens at the end of the stream.
 * Must be freed with `veil_string_free`.
 */
char* veil_streaming_restorer_finish(VeilStreamingRestorer* restorer);

/**
 * Frees a streaming restorer created with `veil_streaming_restorer_new`.
 */
void veil_streaming_restorer_free(VeilStreamingRestorer* restorer);

#ifdef __cplusplus
}
#endif

#endif /* PII_VEIL_H */
