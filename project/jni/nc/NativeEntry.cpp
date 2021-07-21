//
// Created by greyw on 2021/7/20.
//
#include <jni.h>
#include <android/log.h>
#include "Dex2C.h"

typedef struct
{
    const char *clazzName;
    const JNINativeMethod *methods;
    const int methodCount;
} ClassEntry;

//####REPLACE####

//入口
void JNI_PROTECT entryPoint(JNIEnv *env, jobject instance, jint v)
{
    v = v ^ 20;
    LOGD("Protect stub index=%d", v);
    ClassEntry classEntry = entryArray[v];
    jclass clazz = env->FindClass(classEntry.clazzName);
    int rc = env->RegisterNatives(clazz, classEntry.methods, classEntry.methodCount);
    env->DeleteLocalRef(clazz);
    LOGD("method register successful %d index=%d", rc, v);
}

 extern "C" {void _init(void){}}