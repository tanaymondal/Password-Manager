#import "bio_keychain.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>

static const char* SERVICE = "com.securevault.bio";

int32_t bio_write(const char* key, const char* value) {
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* valueStr = [NSString stringWithUTF8String:value];
    NSData* data = [valueStr dataUsingEncoding:NSUTF8StringEncoding];
    NSString* serviceStr = [NSString stringWithUTF8String:SERVICE];

    // Delete existing
    SecItemDelete((__bridge CFDictionaryRef)@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
    });

    // Create with biometric protection — Secure Enclave enforces Face ID / Touch ID
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet,
        NULL
    );

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessControl: (__bridge id)access,
    }, NULL);

    if (access) CFRelease(access);
    return (int32_t)status;
}

int32_t bio_exists(const char* key) {
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* serviceStr = [NSString stringWithUTF8String:SERVICE];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecReturnData: @NO,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
    }, &result);

    return (status == errSecSuccess) ? 1 : 0;
}

char* bio_read(const char* key, const char* prompt_reason) {
    NSString* keyStr = [NSString stringWithUTF8String:key];
    NSString* reason = [NSString stringWithUTF8String:prompt_reason];
    NSString* serviceStr = [NSString stringWithUTF8String:SERVICE];

    LAContext* context = [[LAContext alloc] init];
    context.localizedReason = reason;
    context.interactionNotAllowed = NO;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: serviceStr,
        (__bridge id)kSecAttrAccount: keyStr,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecUseAuthenticationContext: context,
    }, &result);

    if (status == errSecSuccess && result != NULL) {
        NSData* data = (__bridge_transfer NSData*)result;
        NSString* str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (str) return strdup([str UTF8String]);
    }
    return NULL;
}

void bio_free(char* ptr) {
    if (ptr) free(ptr);
}
