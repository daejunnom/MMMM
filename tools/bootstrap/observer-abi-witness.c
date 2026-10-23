// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors
/*
 * Independent C ABI witness for the private Rust JDK 25 observer subset.
 * Include the selected JDK's actual headers; do not copy generated headers.
 * The owned build helper selects profile 1/2/3 and records compiler, header,
 * source and invocation provenance separately. This program starts no VM,
 * obtains no interface, calls no table entry, and grants no target/source policy.
 *
 * C11 or C17 is required, with incompatible-pointer and other warnings fatal.
 * The independently declared function pointers deliberately omit JNICALL:
 * their compatibility with the actual headers checks the required C convention.
 * ClassLoader.defineClass0/1/2 native symbols are not declared by these headers
 * and are outside this witness's signature claims.
 * Selected OS headers also check the module-retention ABI. Function addresses
 * appear only in unevaluated _Generic operands; no loader operation is called.
 */

/* GNU Dl_info/RTLD_NOLOAD/RTLD_NODELETE are public GNU extensions. Select their
 * declarations before any header can include glibc's feature selection. */
#if defined(MMMM_OBSERVER_ABI_PROFILE) && MMMM_OBSERVER_ABI_PROFILE == 2
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#elif defined(MMMM_OBSERVER_ABI_PROFILE) && MMMM_OBSERVER_ABI_PROFILE == 3
/* Keep Darwin's public dladdr and dlopen mode declarations visible in C11. */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#endif

#include <jni.h>
#include <jvmti.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(MMMM_OBSERVER_ABI_PROFILE) && MMMM_OBSERVER_ABI_PROFILE == 1
#include <windows.h>
#elif defined(MMMM_OBSERVER_ABI_PROFILE) && (MMMM_OBSERVER_ABI_PROFILE == 2 || MMMM_OBSERVER_ABI_PROFILE == 3)
#include <dlfcn.h>
#endif

#if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#error MMMM_ABI_C11_REQUIRED
#endif

#ifndef MMMM_OBSERVER_ABI_PROFILE
#error MMMM_ABI_PROFILE_REQUIRED
#elif MMMM_OBSERVER_ABI_PROFILE == 1
#if !defined(_WIN32) || !defined(_WIN64) || !defined(_M_X64) || !defined(_MSC_VER) || defined(__clang__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_M_ARM64EC)
#error MMMM_ABI_WINDOWS_MSVC_X64_REQUIRED
#endif
#define MMMM_PROFILE_NAME "windows-x64-msvc"
_Static_assert(sizeof(long) == 4, "MMMM_ABI_WINDOWS_LLP64_REQUIRED");
#elif MMMM_OBSERVER_ABI_PROFILE == 2
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || !defined(__GLIBC__) || defined(__ILP32__) || defined(_WIN32) || defined(__APPLE__) || (!defined(__GNUC__) && !defined(__clang__))
#error MMMM_ABI_LINUX_GNU_X64_REQUIRED
#endif
#define MMMM_PROFILE_NAME "linux-x64-gnu"
_Static_assert(sizeof(long) == 8, "MMMM_ABI_LINUX_LP64_REQUIRED");
#elif MMMM_OBSERVER_ABI_PROFILE == 3
#if !defined(__APPLE__) || !defined(__MACH__) || !defined(__clang__) || !defined(__aarch64__) || !defined(__LP64__) || !defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) || defined(__arm64e__) || defined(__ILP32__) || defined(_WIN32)
#error MMMM_ABI_MACOS_DARWIN_ARM64_REQUIRED
#endif
#define MMMM_PROFILE_NAME "macos-arm64-darwin"
_Static_assert(sizeof(long) == 8, "MMMM_ABI_DARWIN_LP64_REQUIRED");
#else
#error MMMM_ABI_PROFILE_UNSUPPORTED
#endif

#if MMMM_OBSERVER_ABI_PROFILE == 2 || MMMM_OBSERVER_ABI_PROFILE == 3
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error MMMM_ABI_LITTLE_ENDIAN_REQUIRED
#endif
#endif

#define MMMM_SIZE_ALIGN(Type, Size, Align) \
    _Static_assert(sizeof(Type) == (Size), "MMMM_ABI_SIZE_" #Type); \
    _Static_assert(_Alignof(Type) == (Align), "MMMM_ABI_ALIGN_" #Type)
#define MMMM_SIGNATURE(Table, Member, Signature) \
    _Static_assert(_Generic(((Table *)0)->Member, Signature: 1, default: 0), \
                   "MMMM_ABI_SIGNATURE_" #Member)
#define MMMM_SLOT(Table, Member, Index) \
    _Static_assert(offsetof(Table, Member) == (size_t)(Index) * 8U, \
                   "MMMM_ABI_SLOT_" #Member); \
    _Static_assert(sizeof(((Table *)0)->Member) == 8, \
                   "MMMM_ABI_FUNCTION_POINTER_" #Member)
#define MMMM_JNI(Member, Index, Signature) \
    MMMM_SLOT(struct JNINativeInterface_, Member, Index); \
    MMMM_SIGNATURE(struct JNINativeInterface_, Member, Signature)
#define MMMM_TI(Member, Position, Signature) \
    MMMM_SLOT(struct jvmtiInterface_1_, Member, (Position) - 1); \
    MMMM_SIGNATURE(struct jvmtiInterface_1_, Member, Signature)
#define MMMM_CALLBACK(Member, Index, Signature) \
    MMMM_SLOT(jvmtiEventCallbacks, Member, Index); \
    MMMM_SIGNATURE(jvmtiEventCallbacks, Member, Signature)

_Static_assert(CHAR_BIT == 8, "MMMM_ABI_BYTE_WIDTH");
_Static_assert(UINTPTR_MAX == UINT64_MAX, "MMMM_ABI_UINTPTR_WIDTH");
MMMM_SIZE_ALIGN(void *, 8, 8);
MMMM_SIZE_ALIGN(jint, 4, 4);
MMMM_SIZE_ALIGN(jsize, 4, 4);
MMMM_SIZE_ALIGN(jlong, 8, 8);
MMMM_SIZE_ALIGN(jboolean, 1, 1);
MMMM_SIZE_ALIGN(jbyte, 1, 1);
MMMM_SIZE_ALIGN(jchar, 2, 2);
_Static_assert((jint)-1 < 0 && (jlong)-1 < 0 && (jbyte)-1 < 0,
               "MMMM_ABI_SIGNED_PRIMITIVES");
_Static_assert(_Generic((jboolean)0, unsigned char: 1, default: 0),
               "MMMM_ABI_UNSIGNED_JBOOLEAN");
_Static_assert(_Generic((jchar)0, unsigned short: 1, default: 0),
               "MMMM_ABI_UNSIGNED_JCHAR");
MMMM_SIZE_ALIGN(jobject, 8, 8);
MMMM_SIZE_ALIGN(jclass, 8, 8);
MMMM_SIZE_ALIGN(jthread, 8, 8);
MMMM_SIZE_ALIGN(jstring, 8, 8);
MMMM_SIZE_ALIGN(jbyteArray, 8, 8);
MMMM_SIZE_ALIGN(jmethodID, 8, 8);
MMMM_SIZE_ALIGN(jfieldID, 8, 8);
MMMM_SIZE_ALIGN(JNIEnv, 8, 8);
MMMM_SIZE_ALIGN(JavaVM, 8, 8);
MMMM_SIZE_ALIGN(jvmtiEnv, 8, 8);
MMMM_SIZE_ALIGN(jvalue, 8, 8);

/* Rust uses a four-byte integer at these ABI boundaries. Exact C signatures
 * retain the header enum types; C enum signedness is not a type-equality claim.
 * Width/alignment checks also reject options such as -fshort-enums. */
MMMM_SIZE_ALIGN(jvmtiError, 4, 4);
MMMM_SIZE_ALIGN(jvmtiPhase, 4, 4);
MMMM_SIZE_ALIGN(jvmtiEventMode, 4, 4);
MMMM_SIZE_ALIGN(jvmtiEvent, 4, 4);
_Static_assert(JVMTI_VERSION == 0x30190000, "MMMM_ABI_JVMTI_VERSION_25");
_Static_assert(JNI_VERSION_24 == 0x00180000, "MMMM_ABI_JNI_VERSION_24");
_Static_assert(JNI_OK == 0 && JNI_ERR == -1 && JVMTI_ERROR_NONE == 0,
               "MMMM_ABI_SUCCESS_CODES");
_Static_assert(JVMTI_DISABLE == 0 && JVMTI_ENABLE == 1, "MMMM_ABI_EVENT_MODE");
_Static_assert(JVMTI_PHASE_START == 6 && JVMTI_PHASE_LIVE == 4,
               "MMMM_ABI_USED_PHASES");
_Static_assert(JVMTI_CLASS_STATUS_PREPARED == 2, "MMMM_ABI_CLASS_PREPARED");
_Static_assert(JVMTI_EVENT_VM_INIT == 50 && JVMTI_EVENT_VM_DEATH == 51 &&
               JVMTI_EVENT_CLASS_FILE_LOAD_HOOK == 54 && JVMTI_EVENT_CLASS_LOAD == 55 &&
               JVMTI_EVENT_CLASS_PREPARE == 56 && JVMTI_EVENT_NATIVE_METHOD_BIND == 67,
               "MMMM_ABI_USED_EVENTS");

MMMM_SIZE_ALIGN(jvmtiCapabilities, 16, 4);
MMMM_SIZE_ALIGN(jvmtiEventCallbacks, 312, 8);
MMMM_SIZE_ALIGN(JNINativeMethod, 24, 8);
_Static_assert(offsetof(JNINativeMethod, name) == 0 &&
               offsetof(JNINativeMethod, signature) == 8 &&
               offsetof(JNINativeMethod, fnPtr) == 16, "MMMM_ABI_NATIVE_METHOD_OFFSETS");

/* Native image lifetime is a separate observation from these declarations.
 * This witness neither pins a module nor grants loaded-artifact identity.
 * Public contracts:
 * https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw
 * https://raw.githubusercontent.com/bminor/glibc/master/dlfcn/dlfcn.h
 * https://raw.githubusercontent.com/bminor/glibc/master/bits/dlfcn.h
 * https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/dlfcn.h
 */
#if MMMM_OBSERVER_ABI_PROFILE == 1
MMMM_SIZE_ALIGN(BOOL, 4, 4);
MMMM_SIZE_ALIGN(DWORD, 4, 4);
MMMM_SIZE_ALIGN(WCHAR, 2, 2);
MMMM_SIZE_ALIGN(HMODULE, 8, 8);
_Static_assert(_Generic((BOOL)0, int: 1, default: 0),
               "MMMM_ABI_MODULE_PIN_BOOL_TYPE");
_Static_assert(_Generic((DWORD)0, unsigned long: 1, default: 0),
               "MMMM_ABI_MODULE_PIN_DWORD_TYPE");
_Static_assert(_Generic((WCHAR)0, unsigned short: 1, default: 0),
               "MMMM_ABI_MODULE_PIN_WCHAR_TYPE");
typedef int (*MmmmGetModuleHandleExW)(unsigned long, const WCHAR *, HMODULE *);
_Static_assert(_Generic(&GetModuleHandleExW, MmmmGetModuleHandleExW: 1, default: 0),
               "MMMM_ABI_SIGNATURE_GetModuleHandleExW");
_Static_assert(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS == 0x00000004 &&
               GET_MODULE_HANDLE_EX_FLAG_PIN == 0x00000001 &&
               (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN) == 5,
               "MMMM_ABI_MODULE_PIN_WINDOWS_FLAGS");
#elif MMMM_OBSERVER_ABI_PROFILE == 2 || MMMM_OBSERVER_ABI_PROFILE == 3
MMMM_SIZE_ALIGN(Dl_info, 32, 8);
_Static_assert(offsetof(Dl_info, dli_fname) == 0 &&
               offsetof(Dl_info, dli_fbase) == 8 &&
               offsetof(Dl_info, dli_sname) == 16 &&
               offsetof(Dl_info, dli_saddr) == 24,
               "MMMM_ABI_DL_INFO_OFFSETS");
_Static_assert(_Generic(((Dl_info *)0)->dli_fname, const char *: 1, default: 0),
               "MMMM_ABI_DL_INFO_FILENAME_TYPE");
_Static_assert(_Generic(((Dl_info *)0)->dli_fbase, void *: 1, default: 0),
               "MMMM_ABI_DL_INFO_BASE_TYPE");
_Static_assert(_Generic(((Dl_info *)0)->dli_sname, const char *: 1, default: 0),
               "MMMM_ABI_DL_INFO_SYMBOL_NAME_TYPE");
_Static_assert(_Generic(((Dl_info *)0)->dli_saddr, void *: 1, default: 0),
               "MMMM_ABI_DL_INFO_SYMBOL_ADDRESS_TYPE");
typedef int (*MmmmDladdr)(const void *, Dl_info *);
typedef void *(*MmmmDlopen)(const char *, int);
typedef void *(*MmmmDlsym)(void *, const char *);
typedef char *(*MmmmDlerror)(void);
_Static_assert(_Generic(&dladdr, MmmmDladdr: 1, default: 0),
               "MMMM_ABI_SIGNATURE_dladdr");
_Static_assert(_Generic(&dlopen, MmmmDlopen: 1, default: 0),
               "MMMM_ABI_SIGNATURE_dlopen");
_Static_assert(_Generic(&dlsym, MmmmDlsym: 1, default: 0),
               "MMMM_ABI_SIGNATURE_dlsym");
_Static_assert(_Generic(&dlerror, MmmmDlerror: 1, default: 0),
               "MMMM_ABI_SIGNATURE_dlerror");
#if MMMM_OBSERVER_ABI_PROFILE == 2
_Static_assert(RTLD_NOW == 0x00002 && RTLD_LOCAL == 0 &&
               RTLD_NOLOAD == 0x00004 && RTLD_NODELETE == 0x01000,
               "MMMM_ABI_MODULE_PIN_GNU_MODES");
#else
_Static_assert(RTLD_NOW == 0x2 && RTLD_LOCAL == 0x4 && RTLD_NOLOAD == 0x10 &&
               RTLD_NODELETE == 0x80 && RTLD_FIRST == 0x100,
               "MMMM_ABI_MODULE_PIN_DARWIN_MODES");
#endif
#endif

typedef jclass (*MmmmFindClass)(JNIEnv *, const char *);
typedef jthrowable (*MmmmExceptionOccurred)(JNIEnv *);
typedef void (*MmmmExceptionClear)(JNIEnv *);
typedef jobject (*MmmmNewGlobalRef)(JNIEnv *, jobject);
typedef void (*MmmmDeleteRef)(JNIEnv *, jobject);
typedef jboolean (*MmmmIsSameObject)(JNIEnv *, jobject, jobject);
typedef jclass (*MmmmGetObjectClass)(JNIEnv *, jobject);
typedef jboolean (*MmmmIsInstanceOf)(JNIEnv *, jobject, jclass);
typedef jmethodID (*MmmmGetMethodID)(JNIEnv *, jclass, const char *, const char *);
typedef jobject (*MmmmCallObjectMethodA)(JNIEnv *, jobject, jmethodID, const jvalue *);
typedef jint (*MmmmCallIntMethodA)(JNIEnv *, jobject, jmethodID, const jvalue *);
typedef void (*MmmmCallVoidMethodA)(JNIEnv *, jobject, jmethodID, const jvalue *);
typedef jfieldID (*MmmmGetFieldID)(JNIEnv *, jclass, const char *, const char *);
typedef jobject (*MmmmGetObjectField)(JNIEnv *, jobject, jfieldID);
typedef jsize (*MmmmGetStringLength)(JNIEnv *, jstring);
typedef const char *(*MmmmGetStringUTFChars)(JNIEnv *, jstring, jboolean *);
typedef void (*MmmmReleaseStringUTFChars)(JNIEnv *, jstring, const char *);
typedef jsize (*MmmmGetArrayLength)(JNIEnv *, jarray);
typedef jobjectArray (*MmmmNewObjectArray)(JNIEnv *, jsize, jclass, jobject);
typedef jobject (*MmmmGetObjectArrayElement)(JNIEnv *, jobjectArray, jsize);
typedef void (*MmmmSetObjectArrayElement)(JNIEnv *, jobjectArray, jsize, jobject);
typedef jbyteArray (*MmmmNewByteArray)(JNIEnv *, jsize);
typedef void (*MmmmGetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, jbyte *);
typedef void (*MmmmSetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, const jbyte *);
typedef jint (*MmmmRegisterNatives)(JNIEnv *, jclass, const JNINativeMethod *, jint);
typedef void (*MmmmGetStringRegion)(JNIEnv *, jstring, jsize, jsize, jchar *);
typedef jboolean (*MmmmExceptionCheck)(JNIEnv *);
MMMM_JNI(FindClass, 6, MmmmFindClass);
MMMM_JNI(ExceptionOccurred, 15, MmmmExceptionOccurred);
MMMM_JNI(ExceptionClear, 17, MmmmExceptionClear);
MMMM_JNI(NewGlobalRef, 21, MmmmNewGlobalRef);
MMMM_JNI(DeleteGlobalRef, 22, MmmmDeleteRef);
MMMM_JNI(DeleteLocalRef, 23, MmmmDeleteRef);
MMMM_JNI(IsSameObject, 24, MmmmIsSameObject);
MMMM_JNI(GetObjectClass, 31, MmmmGetObjectClass);
MMMM_JNI(IsInstanceOf, 32, MmmmIsInstanceOf);
MMMM_JNI(GetMethodID, 33, MmmmGetMethodID);
MMMM_JNI(CallObjectMethodA, 36, MmmmCallObjectMethodA);
MMMM_JNI(CallIntMethodA, 51, MmmmCallIntMethodA);
MMMM_JNI(CallVoidMethodA, 63, MmmmCallVoidMethodA);
MMMM_JNI(GetFieldID, 94, MmmmGetFieldID);
MMMM_JNI(GetObjectField, 95, MmmmGetObjectField);
MMMM_JNI(GetStringLength, 164, MmmmGetStringLength);
MMMM_JNI(GetStringUTFChars, 169, MmmmGetStringUTFChars);
MMMM_JNI(ReleaseStringUTFChars, 170, MmmmReleaseStringUTFChars);
MMMM_JNI(GetArrayLength, 171, MmmmGetArrayLength);
MMMM_JNI(NewObjectArray, 172, MmmmNewObjectArray);
MMMM_JNI(GetObjectArrayElement, 173, MmmmGetObjectArrayElement);
MMMM_JNI(SetObjectArrayElement, 174, MmmmSetObjectArrayElement);
MMMM_JNI(NewByteArray, 176, MmmmNewByteArray);
MMMM_JNI(GetByteArrayRegion, 200, MmmmGetByteArrayRegion);
MMMM_JNI(SetByteArrayRegion, 208, MmmmSetByteArrayRegion);
MMMM_JNI(RegisterNatives, 215, MmmmRegisterNatives);
MMMM_JNI(GetStringRegion, 220, MmmmGetStringRegion);
MMMM_JNI(ExceptionCheck, 228, MmmmExceptionCheck);

typedef jint (*MmmmGetEnv)(JavaVM *, void **, jint);
MMMM_SLOT(struct JNIInvokeInterface_, GetEnv, 6);
MMMM_SIGNATURE(struct JNIInvokeInterface_, GetEnv, MmmmGetEnv);

/* Four fixed arguments followed by ellipsis are intentional. */
typedef jvmtiError (*MmmmSetEventNotificationMode)(jvmtiEnv *, jvmtiEventMode,
                                                 jvmtiEvent, jthread, ...);
typedef jvmtiError (*MmmmGetCurrentThread)(jvmtiEnv *, jthread *);
typedef jvmtiError (*MmmmDeallocate)(jvmtiEnv *, unsigned char *);
typedef jvmtiError (*MmmmGetClassSignature)(jvmtiEnv *, jclass, char **, char **);
typedef jvmtiError (*MmmmGetClassStatus)(jvmtiEnv *, jclass, jint *);
typedef jvmtiError (*MmmmGetClassMethods)(jvmtiEnv *, jclass, jint *, jmethodID **);
typedef jvmtiError (*MmmmGetClassLoader)(jvmtiEnv *, jclass, jobject *);
typedef jvmtiError (*MmmmGetMethodName)(jvmtiEnv *, jmethodID, char **, char **, char **);
typedef jvmtiError (*MmmmGetMethodDeclaringClass)(jvmtiEnv *, jmethodID, jclass *);
typedef jvmtiError (*MmmmGetMethodModifiers)(jvmtiEnv *, jmethodID, jint *);
typedef jvmtiError (*MmmmGetBytecodes)(jvmtiEnv *, jmethodID, jint *, unsigned char **);
typedef jvmtiError (*MmmmGetVersionNumber)(jvmtiEnv *, jint *);
typedef jvmtiError (*MmmmGetCapabilities)(jvmtiEnv *, jvmtiCapabilities *);
typedef jvmtiError (*MmmmSetEventCallbacks)(jvmtiEnv *, const jvmtiEventCallbacks *, jint);
typedef jvmtiError (*MmmmGetPhase)(jvmtiEnv *, jvmtiPhase *);
typedef jvmtiError (*MmmmAddCapabilities)(jvmtiEnv *, const jvmtiCapabilities *);
typedef jvmtiError (*MmmmGetConstantPool)(jvmtiEnv *, jclass, jint *, jint *, unsigned char **);
MMMM_TI(SetEventNotificationMode, 2, MmmmSetEventNotificationMode);
MMMM_TI(GetCurrentThread, 18, MmmmGetCurrentThread);
MMMM_TI(Deallocate, 47, MmmmDeallocate);
MMMM_TI(GetClassSignature, 48, MmmmGetClassSignature);
MMMM_TI(GetClassStatus, 49, MmmmGetClassStatus);
MMMM_TI(GetClassMethods, 52, MmmmGetClassMethods);
MMMM_TI(GetClassLoader, 57, MmmmGetClassLoader);
MMMM_TI(GetMethodName, 64, MmmmGetMethodName);
MMMM_TI(GetMethodDeclaringClass, 65, MmmmGetMethodDeclaringClass);
MMMM_TI(GetMethodModifiers, 66, MmmmGetMethodModifiers);
MMMM_TI(GetBytecodes, 75, MmmmGetBytecodes);
MMMM_TI(GetVersionNumber, 88, MmmmGetVersionNumber);
MMMM_TI(GetCapabilities, 89, MmmmGetCapabilities);
MMMM_TI(SetEventCallbacks, 122, MmmmSetEventCallbacks);
MMMM_TI(GetPhase, 133, MmmmGetPhase);
MMMM_TI(GetPotentialCapabilities, 140, MmmmGetCapabilities);
MMMM_TI(AddCapabilities, 142, MmmmAddCapabilities);
MMMM_TI(GetConstantPool, 146, MmmmGetConstantPool);

typedef void (*MmmmVmInit)(jvmtiEnv *, JNIEnv *, jthread);
typedef void (*MmmmVmDeath)(jvmtiEnv *, JNIEnv *);
typedef void (*MmmmClassFileLoadHook)(jvmtiEnv *, JNIEnv *, jclass, jobject,
                                     const char *, jobject, jint, const unsigned char *,
                                     jint *, unsigned char **);
typedef void (*MmmmClassEvent)(jvmtiEnv *, JNIEnv *, jthread, jclass);
typedef void (*MmmmNativeMethodBind)(jvmtiEnv *, JNIEnv *, jthread, jmethodID, void *, void **);
MMMM_CALLBACK(VMInit, 0, MmmmVmInit);
MMMM_CALLBACK(VMDeath, 1, MmmmVmDeath);
MMMM_CALLBACK(ClassFileLoadHook, 4, MmmmClassFileLoadHook);
MMMM_CALLBACK(ClassLoad, 5, MmmmClassEvent);
MMMM_CALLBACK(ClassPrepare, 6, MmmmClassEvent);
MMMM_CALLBACK(NativeMethodBind, 17, MmmmNativeMethodBind);

typedef jint (*MmmmAgentLoad)(JavaVM *, char *, void *);
typedef void (*MmmmAgentUnload)(JavaVM *);
typedef jint (*MmmmJniLoad)(JavaVM *, void *);
_Static_assert(_Generic(&Agent_OnLoad, MmmmAgentLoad: 1, default: 0),
               "MMMM_ABI_SIGNATURE_Agent_OnLoad");
_Static_assert(_Generic(&Agent_OnAttach, MmmmAgentLoad: 1, default: 0),
               "MMMM_ABI_SIGNATURE_Agent_OnAttach");
_Static_assert(_Generic(&Agent_OnUnload, MmmmAgentUnload: 1, default: 0),
               "MMMM_ABI_SIGNATURE_Agent_OnUnload");
_Static_assert(_Generic(&JNI_OnLoad, MmmmJniLoad: 1, default: 0),
               "MMMM_ABI_SIGNATURE_JNI_OnLoad");

static int mmmm_fail(const char *code, int exit_code)
{
    (void)fputs(code, stderr);
    (void)fflush(stderr);
    return exit_code;
}

/* Check each named field separately so swapping required fields cannot pass
 * merely because their combined mask is unchanged. No bit-field offsetof. */
static int mmmm_capability_layout_matches(void)
{
    static const unsigned int ordinals[6] = {3U, 26U, 30U, 35U, 37U, 42U};
    static const uint32_t required[4] = {UINT32_C(0x44000008), UINT32_C(0x00000428), 0U, 0U};
    jvmtiCapabilities selected;
    uint32_t words[4];
    size_t field;
    size_t word;

    for (field = 0; field < 6; ++field) {
        memset(&selected, 0, sizeof(selected));
        switch (field) {
        case 0: selected.can_get_bytecodes = 1; break;
        case 1: selected.can_generate_all_class_hook_events = 1; break;
        case 2: selected.can_generate_native_method_bind_events = 1; break;
        case 3: selected.can_get_constant_pool = 1; break;
        case 4: selected.can_retransform_classes = 1; break;
        case 5: selected.can_generate_early_class_hook_events = 1; break;
        default: return 0;
        }
        memcpy(words, &selected, sizeof(words));
        for (word = 0; word < 4; ++word) {
            const uint32_t expected = word == ordinals[field] / 32U
                ? UINT32_C(1) << (ordinals[field] % 32U) : UINT32_C(0);
            if (words[word] != expected) {
                return 0;
            }
        }
    }
    memset(&selected, 0, sizeof(selected));
    selected.can_get_bytecodes = 1;
    selected.can_generate_all_class_hook_events = 1;
    selected.can_generate_native_method_bind_events = 1;
    selected.can_get_constant_pool = 1;
    selected.can_retransform_classes = 1;
    selected.can_generate_early_class_hook_events = 1;
    memcpy(words, &selected, sizeof(words));
    for (word = 0; word < 4; ++word) {
        if (words[word] != required[word]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    const uint32_t endian_probe = UINT32_C(1);
    static const char report[] =
        "{\"schema\":\"mmmm-observer-c-abi-witness/1\","
        "\"profile\":\"" MMMM_PROFILE_NAME "\",\"status\":\"passed\","
        "\"pointer_bytes\":8,\"pointer_alignment\":8,\"endianness\":\"little\","
        "\"primitive_bytes\":{\"jint\":4,\"jsize\":4,\"jlong\":8,\"jboolean\":1,\"jbyte\":1,\"jchar\":2},"
        "\"jvmti_enum_bytes\":4,\"jvmti_enum_alignment\":4,"
        "\"capabilities_bytes\":16,\"capabilities_alignment\":4,"
        "\"capability_ordinals\":[3,26,30,35,37,42],"
        "\"capability_words_hex\":[\"44000008\",\"00000428\",\"00000000\",\"00000000\"],"
        "\"individual_capability_checks\":6,\"combined_capability_checks\":1,"
        "\"callbacks_bytes\":312,\"callbacks_alignment\":8,\"callback_slots\":[0,1,4,5,6,17],"
        "\"native_method_bytes\":24,\"native_method_alignment\":8,\"native_method_offsets\":[0,8,16],"
        "\"jni_slots\":[6,15,17,21,22,23,24,31,32,33,36,51,63,94,95,164,169,170,171,172,173,174,176,200,208,215,220,228],"
        "\"jvmti_positions\":[2,18,47,48,49,52,57,64,65,66,75,88,89,122,133,140,142,146],"
        "\"java_vm_get_env_slot\":6,\"table_signature_checks\":47,\"callback_signature_checks\":6,"
        "\"entry_signature_checks\":4,\"set_event_variadic\":true,"
        "\"vm_invoked\":false,\"table_entries_called\":false,\"target_policy_granted\":false}\n";
    _Static_assert(sizeof(report) <= 4096, "MMMM_ABI_REPORT_BOUND");

    (void)argv;
    if (argc != 1) {
        return mmmm_fail("MMMM_ABI_ARGUMENTS_REJECTED\n", 64);
    }
    if (*(const unsigned char *)&endian_probe != 1U) {
        return mmmm_fail("MMMM_ABI_ENDIAN_MISMATCH\n", 65);
    }
    if (!mmmm_capability_layout_matches()) {
        return mmmm_fail("MMMM_ABI_CAPABILITY_LAYOUT_MISMATCH\n", 66);
    }
    if (fwrite(report, 1, sizeof(report) - 1, stdout) != sizeof(report) - 1 || fflush(stdout) != 0) {
        return mmmm_fail("MMMM_ABI_REPORT_WRITE_FAILED\n", 74);
    }
    return 0;
}
