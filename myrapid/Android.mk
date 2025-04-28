LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := myrapid
LOCAL_SRC_FILES := host/client_robot.c
LOCAL_CFLAGS += -Wall -g
LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE_PATH := $(TARGET_OUT)/bin
include $(BUILD_EXECUTABLE)

