#include "helper.h"
#include "hooker.h"
#include "logger.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <string>
#include <vector>
#include <jni.h>

// 混淆后的函数名示例，实际使用中可以更复杂
#define ORIGINAL_FOPEN original_fopen_987asd
#define ORIGINAL_STAT original_stat_123qwe
#define ORIGINAL_LSTAT original_lstat_456zxc

static HookFunType hook_func = nullptr;

// 模拟真实的一些文件路径判断逻辑，更复杂一些
bool is_file_related_to_root(const char *filepath) {
    // 增加更多复杂的判断逻辑，比如文件路径长度、包含的特殊字符等
    std::string pathStr = filepath;
    if (pathStr.length() > 10 && pathStr.find("/system") != std::string::npos) {
        return true;
    }
    // 这里可以继续扩展更多的判断条件
    return false;
}

// 模拟真实函数行为的fake_fopen
FILE *fake_fopen(const char *filename, const char *mode) {
    LOGD("Inside fake_fopen. Filename :: %s", filename);
    if (is_file_related_to_root(filename)) {
        // 模拟一些错误情况，比如返回一个错误的文件指针
        FILE* fakeFile = (FILE*)0xdeadbeef; 
        LOGI("App tried to check root related files, simulating error");
        return fakeFile;
    }
    return ORIGINAL_FOPEN(filename, mode);
}

// 模拟真实函数行为的fake_stat
int fake_stat(const char *filename, struct stat *file_info) {
    LOGD("Inside fake_stat. Filename :: %s ", filename);
    if (is_file_related_to_root(filename)) {
        // 模拟一些错误情况，比如设置错误的文件信息
        file_info->st_mode = 0;
        file_info->st_size = -1;
        LOGI("App tried to check root related files, simulating error");
        return -1;
    }
    return ORIGINAL_STAT(filename, file_info);
}

// 模拟真实函数行为的fake_lstat
int fake_lstat(const char *pathName, struct stat *buf) {
    LOGD("Inside fake_lstat. Filename :: %s ", pathName);
    if (is_file_related_to_root(pathName)) {
        // 模拟一些错误情况，比如设置错误的stat结构体信息
        buf->st_mode = 0;
        buf->st_size = -1;
        return -1;
    }
    return ORIGINAL_LSTAT(pathName, buf);
}

// 模拟更真实逻辑的RootBeerNative_checkForMagiskUDS_Fake
jint RootBeerNative_checkForMagiskUDS_Fake(JNIEnv *env, jobject thiz) {
    LOGD("Inside checkForMagiskUDS_Fake");
    // 模拟一些条件判断，根据设备的一些信息返回不同的值
    // 这里只是示例，实际可以根据更多信息来判断
    if (rand() % 2 == 0) {
        return 0;
    } else {
        return 1;
    }
}

// 模拟更真实逻辑的RootBeerNative_checkForRoot_Fake
jint *RootBeerNative_checkForRoot_Fake(JNIEnv *env, jobject thiz, jobjectArray pathsArray) {
    LOGD("Inside RootBeerNative_checkForRoot_Fake");
    // 模拟遍历路径数组，根据路径情况返回不同结果
    int size = env->GetArrayLength(pathsArray);
    jint* result = 新建 jint[size];
    for (int i = 0; i < size; ++i) {
        jstring path = (jstring)env->GetObjectArrayElement(pathsArray, i);
        const char* pathStr = env->GetStringUTFChars(path, nullptr);
        if (is_file_related_to_root(pathStr)) {
            result[i] = 1;
        } else {
            result[i] = 0;
        }
        env->ReleaseStringUTFChars(path, pathStr);
    }
    return result;
}

// 模拟更真实逻辑的RootBeerNative_setLogDebugMessages_Fake
jint RootBeerNative_setLogDebugMessages_Fake(JNIEnv *env, jobject thiz, jboolean flag) {
    LOGD("Inside RootBeerNative_setLogDebugMessages_Fake");
    // 根据传入的flag进行一些更复杂的逻辑处理
    if (flag) {
        // 模拟设置一些内部状态表示开启了调试
        // 这里可以是一些全局变量的设置等操作
    } else {
        // 模拟关闭调试的操作
    }
    return RootBeerNative_setLogDebugMessages(env, thiz, flag);
}

// 检查字符串是否等于或以另一个字符串结尾，更复杂的实现
bool filepath_equals_or_ends_with(std::string filepath, std::string pattern) {
    if (filepath.length() >= pattern.length()) {
        if (filepath.substr(filepath.length() - pattern.length()) == pattern) {
            return true;
        }
    }
    // 增加更多复杂的判断逻辑，比如字符的比较等
    for (size_t i = 0; i < pattern.length(); ++i) {
        if (filepath[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

void on_library_loaded(const char *name, void *handle) {
    if (strstr(name, "libtool-checker.so") || strstr(name, "libtoolChecker.so")) {
        LOGI("Trying to hook libtool Checker library :: %s", name);
        // Root Beer Fresh & Root Beer hooks
        void *target1 = dlsym(handle,"Java_com_kimchangyoun_rootbeerFresh_RootBeerNative_checkForMagiskUDS");
        if (target1)
            hook_func(target1, (void *) RootBeerNative_checkForMagiskUDS_Fake,
                      (void **) &RootBeerNative_checkForMagiskUDS);
        void *target2 = dlsym(handle,"Java_com_kimchangyoun_rootbeerFresh_RootBeerNative_checkForRoot");
        if (target2)
            hook_func(target2, (void *) RootBeerNative_checkForRoot_Fake,
                      (void **) &RootBeerNative_checkForRoot);
        void *target3 = dlsym(handle,"Java_com_kimchangyoun_rootbeerFresh_RootBeerNative_setLogDebugMessages");
        if (target1)
            hook_func(target3, (void *) RootBeerNative_setLogDebugMessages_Fake,
                      (void **) &RootBeerNative_setLogDebugMessages);
        // Root Beer hooks
        void *target4 = dlsym(handle,"Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot");
        if (target4)
            hook_func(target4, (void *) RootBeerNative_checkForRoot_Fake,
                      (void **) &RootBeerNative_checkForRoot);
        void *target5 = dlsym(handle,"Java_com_scottyab_rootbeer_RootBeerNative_setLogDebugMessages");
        if (target5)
            hook_func(target1, (void *) RootBeerNative_setLogDebugMessages_Fake,
                      (void **) &RootBeerNative_setLogDebugMessages);
        LOGI("All native hooks applied for RootBeer / RootBeer Fresh :)");
    }
}

// Note : native_init is mandatory; do not change signature
extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    hook_func = entries->hook_func;
    // System Hooks
    hook_func((void *) fopen, (void *) fake_fopen, (void **) &ORIGINAL_FOPEN);
    hook_func((void *) stat, (void *) fake_stat, (void **) &ORIGINAL_STAT);
    hook_func((void *) lstat, (void *) fake_lstat, (void **) &ORIGINAL_LSTAT);
    LOGI("All System hooks applied for bypassing root check.)");
    return on_library_loaded;
}
