#include <stdio.h>
#include <pcap.h>
#include <libnet.h>

#define IPHDR_PROTOCOL_TCP 0x06

#define forward_msg   "blocked"
#define backward_msg  "HTTP/1.1 302 Found\r\n" \
                      "Location: https://en.wikipedia.org/wiki/HTTP_302\r\n"
#define forward_msg_len   sizeof(forward_msg)   - 1
#define backward_msg_len  sizeof(backward_msg)  - 1

struct pseudo_h 
{
	unsigned int ip_src;
	unsigned int ip_dst;
	unsigned char  zero;
	unsigned char  ip_p;
	unsigned short ip_len;
};

int packet_capture(const unsigned char *receive_p)
{
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr     *ip;
	struct libnet_tcp_hdr      *tcp;

	// ethernet header
	eth = (struct libnet_ethernet_hdr *)receive_p;

	// ip header
	if (ntohs(eth->ether_type) != ETHERTYPE_IP)
	{
		return 0;
	}
	
	ip = (struct libnet_ipv4_hdr *)((char *)eth + LIBNET_ETH_H);

	// tcp header
	if (ntohs(ip->ip_len) <= 40 || ip->ip_p != IPHDR_PROTOCOL_TCP)
	{
		return 0;
	}
	tcp = (struct libnet_tcp_hdr *)((char *)ip + ip->ip_hl * 4);

	// tcp data
	const char *cp = (char *)tcp + tcp->th_off * 4;

	if(memcmp(cp, "GET", 3))
	{
		return 0;	
	}
	
	return 1;
}

void checksum_ip(struct libnet_ipv4_hdr *ip)
{
	/*
        1. ip header를 2바이트씩 자른다.
        2. 체크섬 바이트를 0으로 초기화 한다.
        3. 체크섬 바이트에 짤린 바이트를 그대로 계속 더해나간다. (sum += 각 2바이트)
        4. 더해지는 sum은 4바이트여야 한다. (올림이 생기기 때문에)
        5. 다 더한다음 sum(4바이트) 중 윗 부분의 2바이트를 아랫부분의 2바이트에 다시 더한다.
        6. 다시 sum(4바이트) 중 윗 부분의 2바이트를 아랫부분의 2바이트에 다시 더한다.
        7. 이제 2바이트가 된 sum을 1의 보수로 바꾸면 된다.
        */
        unsigned short *p = (unsigned short *)ip;
        unsigned int sum = 0; 
        unsigned short nLen = 20;
        
        nLen >>= 1;
        ip->ip_sum = 0;
        
        for(int i= 0; i < nLen; i ++ )
        {       
                sum += *p++;
        }
        
        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;
        
        ip->ip_sum = ~sum & 0xffff;
}

void checksum_tcp(const struct libnet_ipv4_hdr* ip, struct libnet_tcp_hdr * tcp, const unsigned int len)
{
	/*
	IP 헤더의 체크섬 계산법과 마찬가지로 20바이트에 해당하는 tcp 헤더의 값을 모두 더한다.
	데이터가 존재할경우 데이터 부분까지 더해 줍니다. 데이터가 홀수로 끝나는 부분은 주의해서 더해야 한다.
	다음으로 IP Header의 srcip, dstip를 2바이트로 잘라 더해준 후
	부가적으로 IP Header의 protocol 필드, tcp 헤더의 길이를 더해준다.
	여기서 tcp 헤더의 길이는 데이터 부분이 존재할경우 데이터 부분까지길이를 말합니다.
	이후 IP의 체크섬과 마찬가지로 위 과정에서 발생한 케리값을 더해주는 과정을 거쳐 체크섬 계산이 완성
	*/
	struct pseudo_h pse;
        unsigned short *p;
        unsigned int ct;
        unsigned int sum = 0;

        tcp->th_sum = 0;

        pse.ip_src = ip->ip_src.s_addr;
        pse.ip_dst = ip->ip_dst.s_addr;
        pse.zero   = 0;
        pse.ip_p   = IPHDR_PROTOCOL_TCP;
        pse.ip_len = htons(ntohs(ip->ip_len) - LIBNET_IPV4_H);

        //tcp data 더하기
        ct = len >> 1;
        p = (unsigned short *)tcp;
        
	for(;ct>0;ct--)
	{
                sum += *p++;
	}
        if(len % 2)//홀수일 때
                sum += *p;

        //psedo data 더하기
        p = (unsigned short *)&pse;
	for(int i=0; i<5; i++)
	{
        	sum += *p++;
      	}
        sum += *p;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;

        tcp->th_sum = ~sum & 0xffff;
}

void send_forward(unsigned char *send_p, const unsigned char *receive_p, const unsigned char *msg, const unsigned short msg_len)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr  *tcp;

	memcpy(send_p, receive_p, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);
	ip = (struct libnet_ipv4_hdr *)(send_p + LIBNET_ETH_H);
	tcp = (struct libnet_tcp_hdr *)((char *)ip + LIBNET_IPV4_H);
	memcpy((char *)tcp + LIBNET_TCP_H, msg, msg_len);

	ip->ip_id    += 1;
	tcp->th_seq   = htonl(ntohl(tcp->th_seq) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H);
	ip->ip_len    = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win   = 0;

	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
}

void send_backward(unsigned char *send_p, const unsigned char *receive_p, const unsigned char *msg, const unsigned short msg_len)
{
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	int ethlen=14;
	int iplen=20;
	int tcplen=20;
	unsigned short tmp;
	unsigned int tmp2;
	unsigned short tmp3[6];

	memcpy(send_p, receive_p, ethlen+iplen+tcplen);
	eth = (struct libnet_ethernet_hdr *)send_p;
	ip = (struct libnet_ipv4_hdr *)(send_p + ethlen);
	tcp = (struct libnet_tcp_hdr *)((char *)ip + iplen);
	memcpy((char *)tcp + tcplen, msg, msg_len);

	memcpy(tmp3, eth->ether_shost, 6);
        memcpy(eth->ether_shost, eth->ether_dhost, 6);
        memcpy(eth->ether_dhost, tmp3, 6);

        tmp2 = ip->ip_dst.s_addr;
        ip->ip_dst.s_addr = ip->ip_src.s_addr;
        ip->ip_src.s_addr = tmp2;

        tmp = tcp->th_dport;
        tcp->th_dport = tcp->th_sport;
        tcp->th_sport = tmp;

        tmp2 = tcp->th_ack;
        tcp->th_ack = tcp->th_seq;
        tcp->th_seq = tmp2;
	
	ip->ip_ttl    = 128;
	tcp->th_ack   = htonl(ntohl(tcp->th_ack) + ntohs(ip->ip_len) - LIBNET_IPV4_H - LIBNET_TCP_H);
	ip->ip_len    = htons(LIBNET_IPV4_H + LIBNET_TCP_H + msg_len);
	tcp->th_flags = TH_FIN | TH_ACK;
	tcp->th_win   = 0;

	checksum_ip(ip);
	checksum_tcp(ip, tcp, LIBNET_TCP_H + msg_len);
}


int main()
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *pkthdr;
	unsigned char msg_forward[forward_msg_len+1] = forward_msg;
	unsigned char msg_backward[backward_msg_len+1] = backward_msg;
	pcap_t *pd;
	const unsigned char *receive_p;
	unsigned char send_p[1024] = { 0 };

	if((dev = pcap_lookupdev(errbuf))==NULL)//네트워크 디바이스 가져오고
	{
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}
	if((pd = pcap_open_live(dev, 65536, 0, 0, errbuf))==NULL)//nonpromiscouous 모드로 열어주고
	{
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	while(1)
	{
		if(pcap_next_ex(pd, &pkthdr, &receive_p) == 1)//마지막으로 캡처한 패킷 데이터를 실제 가져오는 함수이다.
		{	
			if (packet_capture(receive_p))
			{
				// forward fin 보내는 부분
				send_forward(send_p, receive_p, forward_msg, forward_msg_len);
				pcap_sendpacket(pd, send_p, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + forward_msg_len);
	
				// backward fin 보내는 부분 
				send_backward(send_p, receive_p, backward_msg, backward_msg_len);
				pcap_sendpacket(pd, send_p, LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + backward_msg_len);
			}
		}
	}

	pcap_close(pd);
	return 0;
}

