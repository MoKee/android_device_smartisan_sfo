/*
 * Copyright 2016, The Android Open Source Project
 * Copyright 2018, The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG  "WifiMacGenerator"

#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <cutils/log.h>
#include <cutils/properties.h>
#include <sys/stat.h>

#include <android-base/logging.h>

/* wifi get mac */
static const char WIFI_MAC_NV_BIN[]        = "/persist/.wifi_mac_nv.bin";
static const char WLAN_MAC_BIN[]           = "/persist/wlan_mac.bin";
static const char STA_MAC_ADDR_NAME[]      = "Intf0MacAddress=";
static const char P2P_MAC_ADDR_NAME[]      = "Intf1MacAddress=";
static const char MAC_ADDR_NAME_NOT_USE1[] = "Intf3MacAddress=000AF58989FD\n";
static const char MAC_ADDR_NAME_NOT_USE2[] = "Intf4MacAddress=000AF58989FC\n";
static const char MAC_ADDR_NAME_END[]      = "END\n";
static const char MAC_ADDR_NAME_REN[]      = "\n";

static void array2str(uint8_t *array,char *str) {
    int i;
    char c;
    for (i = 0; i < 6; i++) {
        c = (array[i] >> 4) & 0x0f; //high 4 bit
        if(c >= 0 && c <= 9) {
            c += 0x30;
        }
        else if (c >= 0x0a && c <= 0x0f) {
            c = (c - 0x0a) + 'a'-32;
        }

        *str ++ = c;
        c = array[i] & 0x0f; //low 4 bit
        if(c >= 0 && c <= 9) {
            c += 0x30;
        }
        else if (c >= 0x0a && c <= 0x0f) {
            c = (c - 0x0a) + 'a'-32;
        }
        *str ++ = c;
    }
    *str = 0;
}

static int is_valid_mac_address(const char *pMacAddr) {
    int xdigit = 0;

    /* Mac full with zero */
    if (strcmp(pMacAddr, "000000000000") == 0) {
        return 0;
    }

    while (*pMacAddr) {
        if ((xdigit == 1) && ((*pMacAddr % 2) != 0))
            break;

        if (isxdigit(*pMacAddr)) {
            xdigit++;
        }
        ++pMacAddr;
    }
    return (xdigit == 12? 1 : 0);
}

static void update_wlan_mac_bin(uint8_t *mac) {
    FILE *fb = NULL;
    struct stat st;
    char buf [150];
    int i = 0;
    uint8_t staMac[6];
    uint8_t p2pMac[6];
    char wifi_addr[20];
    char p2p_addr[20];

    memset(buf, 0, 150);
    memset(wifi_addr, 0, 20);
    memset(p2p_addr, 0, 20);

    /* mac valid check */
    if (mac != NULL) {
        for (i = 0; i < 6; i++) {
            staMac[i] = mac[i];
        }
        array2str(staMac, wifi_addr);
        if (!is_valid_mac_address(wifi_addr)) {//invalid mac
            ALOGE("%s: Invalid mac", __func__);
            return;
        }

        for (i = 0; i < 6; i++) {
            p2pMac[i] = mac[i + 6];
        }
        array2str(p2pMac, p2p_addr);
        if (!is_valid_mac_address(p2p_addr)) {//invalid mac
            ALOGE("%s: Invalid mac", __func__);
            return;
        }
    }

    snprintf(buf, sizeof(buf), "%s%s%s%s%s%s%s%s%s",
             STA_MAC_ADDR_NAME, wifi_addr, MAC_ADDR_NAME_REN,
             P2P_MAC_ADDR_NAME, p2p_addr, MAC_ADDR_NAME_REN,
             MAC_ADDR_NAME_NOT_USE1,
             MAC_ADDR_NAME_NOT_USE2,
             MAC_ADDR_NAME_END);

    ALOGV("%s: Buffer: %s", __func__, buf);

    fb = fopen(WLAN_MAC_BIN, "wb");
    if (fb != NULL) {
        ALOGD("%s: Writing wiif mac to file %s", __func__, WLAN_MAC_BIN);
        fwrite(buf, strlen(buf), 1, fb);
        fclose(fb);
    }
}

void get_mac_from_nv() {
    struct stat st;
    FILE * fd;
    uint8_t buf[12] = {0};
    int len = 0;

    if ((stat(WIFI_MAC_NV_BIN, &st) != 0 || st.st_size != 12)) {
        ALOGE("%s: Invalid NV mac file %s", __func__, WIFI_MAC_NV_BIN);
        return;
    }

    // read nv files in binary mode
    if ((fd = fopen(WIFI_MAC_NV_BIN, "rb")) == NULL) {
        ALOGE("%s: Could not open NV mac file %s", __func__, WIFI_MAC_NV_BIN);
        return;
    }

    fseek(fd, 0, SEEK_SET);
    len = fread(buf, sizeof(char), st.st_size, fd);
    fclose(fd);

    update_wlan_mac_bin(buf);
}

int main()
{
    get_mac_from_nv();
    return 0;
}
