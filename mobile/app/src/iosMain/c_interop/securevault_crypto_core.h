#ifndef SECUREVAULT_CRYPTO_CORE_H
#define SECUREVAULT_CRYPTO_CORE_H

#include <stdint.h>

char* securevault_derive_auth_hash(const char* password, const char* salt, int32_t iterations, int32_t memory, int32_t parallelism);
char* securevault_derive_kek(const char* password, const char* salt_b64, int32_t iterations, int32_t memory, int32_t parallelism);
char* securevault_wrap_vault_key(const char* kek_b64, const char* vault_key_b64);
char* securevault_unwrap_vault_key(const char* kek_b64, const char* wrapped_b64);
char* securevault_encrypt_entry(const char* vault_key_b64, const char* plaintext_json);
char* securevault_decrypt_entry(const char* vault_key_b64, const char* encrypted_data, const char* iv);
char* securevault_encrypt_field(const char* vault_key_b64, const char* plaintext);
char* securevault_decrypt_field(const char* vault_key_b64, const char* ciphertext);
void securevault_free_string(char* ptr);

#endif
