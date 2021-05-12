LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := keys
LOCAL_SRC_FILES := keys.c
LOCAL_LDLIBS    := -lm -llog

include $(BUILD_SHARED_LIBRARY)
