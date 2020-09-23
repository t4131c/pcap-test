#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <stdlib.h>

#define MAC 0
#define IP 1
#define PORT 2


#pragma pack(push, 1)
typedef struct packet_info{
    struct libnet_ethernet_hdr ethernet;
    struct libnet_ipv4_hdr ipv4;
    struct libnet_tcp_hdr tcp;
}packet_info;
#pragma pack(pop)

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
void myprint(const char* str, const uint8_t* packet, int chk){
    if(chk == MAC){
        printf(str);
        for(int i=0; i<6; i++){
            if(i == 5){
                printf("%x\n", packet[i]);
                break;
            }
            printf("%x.", packet[i]);
        }
    }
    else if(chk == IP){
        printf(str);
        for(int i=0; i<4; i++){
            if(i == 3){
                printf("%d\n", packet[i]);
                break;
            }
            printf("%d.", packet[i]); 
        }     
    }
    else if(chk == PORT){
        printf(str);
        int port = packet[0] * 256 + packet[1];
        printf("%d\n", port);
    }
    else{
        printf("[*]error!");
        return;
    }
    
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        printf("------------------------------------------\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct packet_info *p_info = (struct packet_info*) packet;
        if(ntohs(p_info->ethernet.ether_type) != ETHERTYPE_IP){
            printf("not ip\n");
            continue;
        }
        if(p_info->ipv4.ip_p != IPPROTO_TCP){
            printf("not tcp\n");
            continue;
        }

        myprint("src mac : ",p_info->ethernet.ether_shost, MAC);
        myprint("dst mac : ",p_info->ethernet.ether_dhost, MAC);


        struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr*) (packet+sizeof(struct libnet_ethernet_hdr));

        myprint("src ip : ",(uint8_t *) &(p_info->ipv4.ip_src), IP);
        myprint("dst ip : ",(uint8_t *) &(p_info->ipv4.ip_dst), IP);

        myprint("src port : ",(uint8_t *)&(p_info->tcp.th_sport), PORT);
        myprint("dst port : ",(uint8_t *)&(p_info->tcp.th_dport), PORT);
        

        int start_data = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + (p_info->tcp.th_off * sizeof(uint32_t));
        int end_data = header->caplen;
        printf("data\n");
        for(int i = start_data; i < end_data && i < start_data + 16; i++){
            printf("%02x ", packet[i]);
        }
        printf("\n");
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(handle);
}
