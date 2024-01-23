#include "packet.h"

int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], 0, 0, 0, errbuf);
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
