LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := stub
LOCAL_LDLIBS    := -llog

SOURCES := $(wildcard $(LOCAL_PATH)/nc/*.cpp)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/nc

LOCAL_SRC_FILES := $(SOURCES:$(LOCAL_PATH)/%=%)

LOCAL_CFLAGS += -pie -fPIE -fPIC
LOCAL_LDFLAGS += -pie -fPIE -fPIC

LOCAL_CPPFLAGS += -ffunction-sections -fdata-sections -fvisibility=hidden
LOCAL_CFLAGS += -ffunction-sections -fdata-sections -fvisibility=hidden
ifneq ($(TARGET_ARCH), arm64)
LOCAL_LDFLAGS += -Wl,--gc-sections,--exclude-libs,ALL,--icf=safe
else
LOCAL_LDFLAGS += -Wl,--gc-sections,--exclude-libs,ALL
endif

LOCAL_CFLAGS +=  -mllvm -sobf -mllvm -sub_loop=3 -mllvm -split_num=4 -mllvm -bcf_loop=2 -mllvm -bcf_prob=100


include $(BUILD_SHARED_LIBRARY)
