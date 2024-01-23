#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <iomanip>

struct ieee80211_radiotap_header {
	u_int8_t        it_version = 0;     /* set to 0 */
	u_int8_t        it_pad = 0;
	u_int16_t       it_len = 8;         /* entire length */
    u_int32_t       it_present = 0;
} __attribute__((__packed__));

struct ieee80211_header {
	uint16_t frame_control;
	uint16_t duration_id = 0;
	uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control = 0;
};

struct beacon_frame_fixed {
    uint16_t ReasonCode;
};

struct last {
    struct ieee80211_radiotap_header rheader;
    struct ieee80211_header deauth;
    struct beacon_frame_fixed fixed;
};

void usage() {
	printf("syntax: ./ad <interface>\n");
	printf("sample: ./ad wlan0\n");
}