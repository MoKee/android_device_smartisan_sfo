#
# Copyright (C) 2015 The CyanogenMod Project
# Copyright (C) 2019 The MoKee Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

ifeq ($(TARGET_DEVICE),sfo)

include $(call all-makefiles-under,$(LOCAL_PATH))

include $(CLEAR_VARS)

WIFI_MAC_BINS := wifi_mac_nv.bin wifi_random_mac.bin
WIFI_MAC_SYMLINKS := $(addprefix $(TARGET_OUT_ETC)/firmware/wlan/prima/,$(notdir $(WIFI_MAC_BINS)))
$(WIFI_MAC_SYMLINKS): $(LOCAL_INSTALLED_MODULE)
	@echo "WIFI MAC firmware link: $@"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf /persist/.$(notdir $@) $@

ALL_DEFAULT_INSTALLED_MODULES += $(WIFI_MAC_SYMLINKS)

endif
