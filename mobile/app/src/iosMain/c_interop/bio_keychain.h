#ifndef BIO_KEYCHAIN_H
#define BIO_KEYCHAIN_H

#include <stdint.h>

// Write vault key to Keychain with biometric protection (Secure Enclave).
// Returns 0 on success, non-zero on error.
int32_t bio_write(const char* key, const char* value);

// Read vault key from Keychain — requires biometric scan (Face ID / Touch ID).
// Returns allocated string (caller must free with bio_free), or NULL.
char* bio_read(const char* key, const char* prompt_reason);

// Free a string returned by bio_read.
void bio_free(char* ptr);

#endif
