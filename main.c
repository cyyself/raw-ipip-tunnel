#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "cksum.c"

char* bind_interface = "docker0";//use -l to change
struct in_addr my_ip,peer_ip,my_ipip,peer_ipip;//use -ip to change

unsigned char peer_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};//use -mac to change
unsigned short my_port = 2333, peer_port = 2333;//use -b -p to change

unsigned char my_mac[6];
unsigned short mtu_ip = 1500;//you can even try 28
unsigned short mtu_ipip = 1480;//you can even try 28

pthread_t receiver_thread;

const unsigned short more_frag_mask= 0x2000;
const unsigned short frag_offset_mask = 0x1fff;

const unsigned char proto_ipip = 4;
const unsigned char proto_udp = 17;
#define buf_sz 65536
#define max_frag_size 65536//actually supoort to 9000 Bytes jumbo frame is enough

int sock_fd;

void sigint_handler(sig_t s){
	pthread_kill(receiver_thread,SIGSTOP);
	close(sock_fd);
	exit(1); 
}

void print_mac_addr(unsigned char *mac) {
	for (int i=0;i<6;i++) printf("%02x%c",(unsigned char)mac[i],i==5?'\n':':');
}

void read_mac_addr(char *input,unsigned char *mac) {
	int dst[6];
	sscanf(input,"%x:%x:%hx:%x:%x:%x",&dst[0],&dst[1],&dst[2],&dst[3],&dst[4],&dst[5]);
	for (int i=0;i<6;i++) mac[i] = dst[i];
}

char get_header_hash(struct iphdr l3_header) {
	const char hash_base = 2333;
	char src_ip_hash = 
		((l3_header.saddr >>  0) & 0xff) ^
		((l3_header.saddr >>  8) & 0xff) ^ 
		((l3_header.saddr >> 16) & 0xff) ^ 
		((l3_header.saddr >> 24) & 0xff);
	char dst_ip_hash = 
		((l3_header.daddr >>  0) & 0xff) ^
		((l3_header.daddr >>  8) & 0xff) ^ 
		((l3_header.daddr >> 16) & 0xff) ^ 
		((l3_header.daddr >> 24) & 0xff);
	char id_hash = (l3_header.id >> 8) ^ (l3_header.id & 0xff);
	return hash_base ^ src_ip_hash ^ dst_ip_hash ^ id_hash;
}

void print_hex(unsigned char *payload,unsigned short len) {
	printf("%d:{",len);
	for (int i=0;i<len;i++) printf("%02x,",payload[i]);
	printf("}\n");
}
int verify_cksum(struct iphdr l3_header) {
	unsigned short cksum = l3_header.check;
	l3_header.check = 0;
	if (in_cksum(&l3_header,sizeof(l3_header)) == cksum) return 0;
	else return 1;
}
void recv_udp(unsigned char *payload,unsigned short len) {
	struct udphdr l4_header;
	memcpy(&l4_header,payload,sizeof(l4_header));
	if (l4_header.source != htons(my_port) || l4_header.dest != htons(peer_port)) return;
	if (ntohs(l4_header.len) == len) {
		//printf("recv_udp src=%d dst=%d\n",ntohs(l4_header.source),ntohs(l4_header.dest));
		printf("<");
		for (int i=8;i<len;i++) printf("%c",payload[i]);
		printf("\n");
	}
	else {
		//printf("bad udp size\n");
	}
}
void recv_ipv4(unsigned char *packet,unsigned short len, int ipip) {
	struct iphdr l3_header;
	memcpy(&l3_header,packet,sizeof(l3_header));
	struct in_addr saddr, daddr;
	memcpy(&saddr,&l3_header.saddr,sizeof(saddr));
	memcpy(&daddr,&l3_header.daddr,sizeof(saddr));
	char *src_ip_s = inet_ntoa(saddr);
	//printf("src ip=%s, ",src_ip_s);
	char *dst_ip_s = inet_ntoa(daddr);
	//printf("dst ip=%s,",dst_ip_s);
	if (len != ntohs(l3_header.tot_len)) {
		//printf("Packet size error\n");
		return;
	} 
	if (verify_cksum(l3_header)) {
		//printf("header cksum error\n");
		return;
	}
	if (
		(!ipip && (daddr.s_addr != my_ip.s_addr || saddr.s_addr != peer_ip.s_addr)) ||
		(ipip && (daddr.s_addr != my_ipip.s_addr || saddr.s_addr != peer_ipip.s_addr))
	) {
		return;//ignore ip not equals my_ip
	}
	unsigned short more_frag = ntohs(l3_header.frag_off) & more_frag_mask;
	unsigned short frag_offset = (ntohs(l3_header.frag_off) & frag_offset_mask) << 3;
	unsigned char *payload = packet + (l3_header.ihl << 2);
	unsigned short payloadlen = ntohs(l3_header.tot_len) - (l3_header.ihl << 2);
	//printf("payloadlen=%d,frag_offset=%d,more_frag=%s\n",payloadlen,frag_offset,more_frag?"YES":"NO");
	if (more_frag || frag_offset) {
		static char frag_mem[1<<8][max_frag_size];//hash id to 8 bit
		static unsigned short frag_len[1<<8];
		static unsigned short frag_totlen[1<<8];
		unsigned char header_hash = get_header_hash(l3_header);
		if (payloadlen + frag_offset >= max_frag_size) {//check if this packet will result in buffer overflow
			//printf("bad packet\n");
			return;
		}
		frag_len[header_hash] += payloadlen;
		memcpy(&frag_mem[header_hash][frag_offset],payload,payloadlen);
		if (frag_totlen[header_hash] && frag_offset > frag_totlen[header_hash]) {
			frag_totlen[header_hash] = 0;
			//printf("drop frag\n");
		}
		if (!more_frag) frag_totlen[header_hash] = frag_offset + payloadlen;
		if (frag_len && frag_len[header_hash] == frag_totlen[header_hash]) {
			//printf("reassemble packet success\n");
			if (l3_header.protocol == proto_udp) {
				recv_udp(frag_mem[header_hash],frag_totlen[header_hash]);
			}
			frag_totlen[header_hash] = 0;
			frag_len[header_hash] = 0;
		}
	}
	else {
		if (l3_header.protocol == proto_udp) {
			recv_udp(payload,payloadlen);
		}
		else if (l3_header.protocol == proto_ipip) {
			recv_ipv4(payload,payloadlen,1);
		}
	}
}


void recv_eth(unsigned char *frame,unsigned short len) {
	struct ethhdr l2_header;
	memcpy(&l2_header,frame,sizeof(l2_header));
	/*
	printf("mac dst: ");
	print_mac_addr(l2_header.h_dest);
	printf("mac src: ");
	print_mac_addr(l2_header.h_source);
	*/
	switch (ntohs(l2_header.h_proto)) {
		case ETH_P_IP:
			//printf("IPv4\n");
			recv_ipv4(frame+sizeof(l2_header),len-sizeof(l2_header),0);
			break;
		default:
			//printf("unknow protocol %04x\n",ntohs(l2_header.h_proto));
			break;
	}
}
int lowbit_clear(int x,int len) {
	return x >> len << len;
}
void send_eth(unsigned char *dst,unsigned short proto,unsigned char *payload,unsigned int payloadlen) {
	char buf[buf_sz];
	struct ethhdr l2_header;
	memcpy(&l2_header.h_dest,dst,6);
	memcpy(&l2_header.h_source,my_mac,6);
	l2_header.h_proto = proto;
	memcpy(buf,&l2_header,sizeof(l2_header));
	memcpy(buf+14,payload,payloadlen);
	send(sock_fd,buf,payloadlen+14,0);
}
void send_ip(struct in_addr dst_ip,unsigned char protocol,unsigned char *payload,unsigned short len) {
	char buf[buf_sz];
	struct iphdr l3_header;
	l3_header.version = 4;
	l3_header.ihl = 5;
	l3_header.tos = 0;
	l3_header.tot_len = htons(len + (l3_header.ihl << 2));
	l3_header.id = rand() & 0xffff;
	l3_header.frag_off = 0;
	l3_header.ttl = 64;
	l3_header.protocol = protocol;
	l3_header.check = 0;
	l3_header.saddr = my_ip.s_addr;
	l3_header.daddr = dst_ip.s_addr;
	if (len > mtu_ip - (l3_header.ihl << 2)) {
		//do_fragment
		int each_sz = lowbit_clear(mtu_ip - (l3_header.ihl << 2),3);
		//try to send in reverse order to check frag is ok
		for (int i=len-(len%each_sz==0?each_sz:len%each_sz);i>=0;i-=each_sz) {
		//for (int i=0;i<len;i+=each_sz) {
			unsigned char more_frag = i + each_sz < len;
			l3_header.tot_len = htons(20 + (more_frag ? each_sz : len - i));
			l3_header.frag_off = htons((i >> 3) | (more_frag?more_frag_mask:0));
			l3_header.check = 0;
			l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
			memcpy(buf,&l3_header,sizeof(l3_header));
			memcpy(buf+20,payload+i,(more_frag ? each_sz : len - i));
			send_eth(peer_mac,htons(ETH_P_IP),buf,ntohs(l3_header.tot_len));
		}
	}
	else {
		l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
		memcpy(buf,&l3_header,sizeof(l3_header));
		memcpy(buf+20,payload,len);
		send_eth(peer_mac,htons(ETH_P_IP),buf,len+20);
	}
}
void send_ipip(struct in_addr dst_ip,struct in_addr dst_ipip,unsigned char protocol,unsigned char *payload,unsigned short len) {
	char buf[buf_sz];
	struct iphdr l3_header;
	l3_header.version = 4;
	l3_header.ihl = 5;
	l3_header.tos = 0;
	l3_header.tot_len = htons(len + (l3_header.ihl << 2));
	l3_header.id = rand() & 0xffff;
	l3_header.frag_off = 0;
	l3_header.ttl = 64;
	l3_header.protocol = protocol;
	l3_header.check = 0;
	l3_header.saddr = my_ipip.s_addr;
	l3_header.daddr = dst_ipip.s_addr;
	if (len > mtu_ipip - (l3_header.ihl << 2)) {
		//do_fragment
		int each_sz = lowbit_clear(mtu_ipip - (l3_header.ihl << 2),3);
		//try to send in reverse order to check frag is ok
		for (int i=len-(len%each_sz==0?each_sz:len%each_sz);i>=0;i-=each_sz) {
		//for (int i=0;i<len;i+=each_sz) {
			unsigned char more_frag = i + each_sz < len;
			l3_header.tot_len = htons(20 + (more_frag ? each_sz : len - i));
			l3_header.frag_off = htons((i >> 3) | (more_frag?more_frag_mask:0));
			l3_header.check = 0;
			l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
			memcpy(buf,&l3_header,sizeof(l3_header));
			memcpy(buf+20,payload+i,(more_frag ? each_sz : len - i));
			send_ip(dst_ip,proto_ipip,buf,ntohs(l3_header.tot_len));
		}
	}
	else {
		l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
		memcpy(buf,&l3_header,sizeof(l3_header));
		memcpy(buf+20,payload,len);
		send_ip(dst_ip,proto_ipip,buf,len+20);
	}
}
void send_udp(struct in_addr dst_ip,unsigned short src_port,unsigned short dst_port,char *payload,unsigned short len) {
	char buf[buf_sz];
	struct udphdr l4_header;
	l4_header.source = htons(src_port);
	l4_header.dest = htons(dst_port);
	l4_header.check = 0;
	l4_header.len = htons(len + 8);
	memcpy(buf,&l4_header,sizeof(l4_header));
	memcpy(buf+8,payload,len);
	send_ip(dst_ip,proto_udp,buf,len+8);
}
void send_udp_ipip(struct in_addr dst_ip,struct in_addr dst_ipip,unsigned short src_port,unsigned short dst_port,char *payload,unsigned short len) {
	char buf[buf_sz];
	struct udphdr l4_header;
	l4_header.source = htons(src_port);
	l4_header.dest = htons(dst_port);
	l4_header.check = 0;
	l4_header.len = htons(len + 8);
	memcpy(buf,&l4_header,sizeof(l4_header));
	memcpy(buf+8,payload,len);
	send_ipip(dst_ip,dst_ipip,proto_udp,buf,len+8);
}
char test_udp_payload[3000];
void init_test_udp_payload() {
	memset(test_udp_payload,' ',sizeof(test_udp_payload));
	char *begin = "----- Test BEGIN -----\nHi, I'm a udp payload of size 3000.\n";
	memcpy(test_udp_payload,begin,strlen(begin));
	char *end = "\n----- Test END -----\n";
	memcpy(test_udp_payload+3000-strlen(end),end,strlen(end));
}

void receiver() {
	unsigned char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(sock_fd,buf,buf_sz,0)) > 0) {
		recv_eth(buf,sz);
	}
}
void sender() {
	static char buf[buf_sz];
	char *buf_ptr = buf;
	size_t buf_sz_t = buf_sz;
	int sz;
	while (sz = getline(&buf_ptr,&buf_sz_t,stdin)) {
		buf[sz-1] = 0;
		sz --;
		if (strcmp(buf,"testfrag") == 0) send_udp_ipip(peer_ip,peer_ipip,my_port,peer_port,test_udp_payload,3000);
		else send_udp_ipip(peer_ip,peer_ipip,my_port,peer_port,buf,sz);
	}
}
int main(int argc,char *argv[]) {
	srand(time(NULL));
	init_test_udp_payload();
	inet_aton("172.17.255.255",&peer_ip);//default ip address
	inet_aton("192.168.0.1",&my_ipip);
	inet_aton("192.168.0.2",&peer_ipip);
	//use -l to bind for specific interface
	for (int i=0;i<argc;i++) if (i + 1 < argc) {
		if (strcmp(argv[i],"-l") == 0) {
			bind_interface = argv[i+1];
		}
		else if (!strcmp(argv[i],"-ip")) {
			inet_aton(argv[i+1],&peer_ip);
		}
		else if (!strcmp(argv[i],"-myipip")) {
			inet_aton(argv[i+1],&my_ipip);
		}
		else if (!strcmp(argv[i],"-peeripip")) {
			inet_aton(argv[i+1],&peer_ipip);
		}
		else if (!strcmp(argv[i],"-mac")) {
			read_mac_addr(argv[i+1],&peer_mac);
		}
		else if (!strcmp(argv[i],"-b")) {
			sscanf(argv[i+1],"%hu",&my_port);
		}
		else if (!strcmp(argv[i],"-p")) {
			sscanf(argv[i+1],"%hu",&peer_port);
		}
	}
	printf("bind_interface = %s\n",bind_interface);
	printf("peer_ip = %s\n",inet_ntoa(peer_ip));
	printf("my_ipip = %s\n",inet_ntoa(my_ipip));
	printf("peer_ipip = %s\n",inet_ntoa(peer_ipip));
	printf("peer_mac = ");
	print_mac_addr(peer_mac);
	printf("peer_udp_port = %hu\n",peer_port);
	printf("local_udp_port = %hu\n",my_port);
	//init random seed (for random packet id)
	srand(time(NULL));
	//init sighandler to avoid unuseable fd after close
	signal(SIGINT,(__sighandler_t)sigint_handler);
	//init socket
	sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll sll;
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name,bind_interface);
	//get ip addr for this interface
	ifstruct.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock_fd,SIOCGIFADDR,&ifstruct) == 0) {
		memcpy(&my_ip,&(((struct sockaddr_in *)&ifstruct.ifr_addr)->sin_addr),sizeof(my_ip));
		printf("local_ip = %s\n",inet_ntoa(my_ip));
	}
	else {
		perror("can't get ip address");
		exit(1);
	}
	//get mac addr for this interface
	if (ioctl(sock_fd,SIOCGIFHWADDR,&ifstruct) == 0) {
		memcpy(my_mac,&ifstruct.ifr_addr.sa_data,sizeof(my_mac));
		printf("local_mac = ");
		print_mac_addr(my_mac);
		/*
			use different mac_addr is ok, 
			but some virtual machines will
			filter mac address by default,
			so the frame will be drop.
			For Hyper-V, you should open 
			"MAC Address Spoofing".
		*/
	}
	//get interface index
	if (ioctl(sock_fd,SIOCGIFINDEX,&ifstruct) == 0) {
		sll.sll_ifindex = ifstruct.ifr_ifindex;
		sll.sll_protocol = htons(ETH_P_ALL);
	}
	else {
		perror("can't get interface index");
		exit(1);
	}
	//bind raw socket
	if (bind(sock_fd,(struct sockaddr *)&sll,sizeof(sll)) == -1) {
		perror("bind error! Are you root?\n");
		exit(1);
	}
	pthread_create(&receiver_thread,NULL,receiver,NULL);
	pthread_detach(receiver_thread);
	sender();
	close(sock_fd);
	return 0;
}