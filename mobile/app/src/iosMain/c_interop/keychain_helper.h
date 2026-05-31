#ifndef KEYCHAIN_HELPER_H
#define KEYCHAIN_HELPER_H

#include <stdint.h>

// Write a value to the Keychain. Returns 0 on success, non-zero on error.
int32_t keychain_write(const char* service, const char* key, const char* value);

// Write a value to the Keychain with biometric protection (Face ID / Touch ID required to read).
int32_t keychain_write_biometric(const char* service, const char* key, const char* value);

// Read a value from the Keychain. Returns allocated string (caller must free with keychain_free_string).
char* keychain_read(const char* service, const char* key);

// Read a value from the Keychain with biometric authentication prompt.
char* keychain_read_biometric(const char* service, const char* key, const char* prompt_reason);

// Delete a value from the Keychain.
int32_t keychain_delete(const char* service, const char* key);

// Delete all values for a service.
int32_t keychain_clear(const char* service);

// Free a string returned by keychain_read*.
void keychain_free_string(char* ptr);

#endif
