#import "keychain_helper.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

int32_t keychain_write(const char* service, const char* key, const char* value) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* valueStr = [NSString stringWithUTF8String:value];
    NSData* data = [valueStr dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary* deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

    NSDictionary* addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    return (int32_t)status;
}

int32_t keychain_write_biometric(const char* service, const char* key, const char* value) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* valueStr = [NSString stringWithUTF8String:value];
    NSData* data = [valueStr dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary* deleteQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
    };
    SecItemDelete((__bridge CFDictionaryRef)deleteQuery);

    // Create access control with biometric protection
    SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        NULL
    );

    NSDictionary* addQuery = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessControl: (__bridge id)accessControl,
    };
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);

    if (accessControl) CFRelease(accessControl);
    return (int32_t)status;
}

char* keychain_read(const char* service, const char* key) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];
    NSString* keyStr = [NSString stringWithUTF8String:key];

    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecSuccess && result != NULL) {
        NSData* data = (__bridge_transfer NSData*)result;
        NSString* str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (str != nil) {
            const char* utf8 = [str UTF8String];
            if (utf8 != NULL) {
                char* copy = strdup(utf8);
                return copy;
            }
        }
    }
    return NULL;
}

char* keychain_read_biometric(const char* service, const char* key, const char* prompt_reason) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* reason = [NSString stringWithUTF8String:prompt_reason];

    LAContext* context = [[LAContext alloc] init];
    context.localizedReason = reason;
    context.interactionNotAllowed = NO;

    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecUseAuthenticationContext: context,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecSuccess && result != NULL) {
        NSData* data = (__bridge_transfer NSData*)result;
        NSString* str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (str != nil) {
            const char* utf8 = [str UTF8String];
            if (utf8 != NULL) {
                char* copy = strdup(utf8);
                return copy;
            }
        }
    }
    return NULL;
}

int32_t keychain_delete(const char* service, const char* key) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];
    NSString* keyStr = [NSString stringWithUTF8String:key];

    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (int32_t)status;
}

int32_t keychain_clear(const char* service) {
    NSString* serviceStr = [NSString stringWithUTF8String:service];

    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
    };
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return (int32_t)status;
}

void keychain_free_string(char* ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}
