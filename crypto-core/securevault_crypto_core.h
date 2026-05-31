#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct KdfParams KdfParams;



/**
 * Derive a master key via Argon2id.
 *
 * # Safety
 * `password` and `salt_b64` must be valid null-terminated C strings.
 * Returns base64-encoded master key — must be freed with `securevault_free_string`.
 */
char *securevault_derive_master_key(const char *password,
                                    const char *salt_b64,
                                    int32_t iterations,
                                    int32_t memory,
                                    int32_t parallelism);

/**
 * Derive an auth hash from a master key.
 *
 * # Safety
 * `master_key_b64` must be a valid null-terminated base64 C string.
 */
char *securevault_derive_auth_hash(const char *master_key_b64);

/**
 * Derive a KEK from a master key.
 *
 * # Safety
 * `master_key_b64` must be a valid null-terminated base64 C string.
 */
char *securevault_derive_kek(const char *master_key_b64);

/**
 * Wrap a vault key with a KEK using AES-256-GCM.
 * Returns base64( nonce[12] || ciphertext || tag[16] ) — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `kek_b64` and `vault_key_b64` must be valid null-terminated base64 C strings.
 */
char *securevault_wrap_vault_key(const char *kek_b64,
                                 const char *vault_key_b64);

/**
 * Unwrap a vault key with a KEK using AES-256-GCM.
 * Returns base64 of the vault key — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `kek_b64` and `wrapped_b64` must be valid null-terminated base64 C strings.
 */
char *securevault_unwrap_vault_key(const char *kek_b64, const char *wrapped_b64);

/**
 * Encrypt a vault entry with AES-256-GCM.
 * Returns JSON `{"encryptedData":"v1:...","iv":"..."}` — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `vault_key_b64` and `plaintext_json` must be valid null-terminated C strings.
 */
char *securevault_encrypt_entry(const char *vault_key_b64,
                                const char *plaintext_json);

/**
 * Decrypt a vault entry with AES-256-GCM.
 * Returns the plaintext JSON string — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `vault_key_b64`, `encrypted_data`, and `iv` must be valid null-terminated C strings.
 */
char *securevault_decrypt_entry(const char *vault_key_b64,
                                const char *encrypted_data,
                                const char *iv);

/**
 * Encrypt a local field with AES-256-GCM.
 * Returns `"v1:" + base64(nonce || ciphertext || tag)` — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `vault_key_b64` and `plaintext` must be valid null-terminated C strings.
 */
char *securevault_encrypt_field(const char *vault_key_b64,
                                const char *plaintext);

/**
 * Decrypt a local field with AES-256-GCM.
 * Returns the plaintext — must be freed with `securevault_free_string`.
 *
 * # Safety
 * `vault_key_b64` and `ciphertext` must be valid null-terminated C strings.
 */
char *securevault_decrypt_field(const char *vault_key_b64, const char *ciphertext);

/**
 * Free a string returned by any `securevault_*` function.
 *
 * # Safety
 * `ptr` must be a pointer previously returned by a `securevault_*` function,
 * or null (which is safely handled).
 */
void securevault_free_string(char *ptr);
