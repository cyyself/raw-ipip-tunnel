#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <map>
#include "cksum.c"

using std::map;

struct mac_addr {
    unsigned char addr[6];
    void print() {
        for (int i=0;i<6;i++) printf("%02x%c",(unsigned char)addr[i],i==5?'\n':':');
    }
    mac_addr() {
        memset(addr,0xff,sizeof(addr));
    }
    mac_addr(unsigned char* mac) {
        memcpy(addr,mac,sizeof(addr));
    }
    friend bool operator == (const mac_addr &a, const mac_addr &b) {
        for (int i=0;i<6;i++) if (a.addr[i] != b.addr[i]) return false;
        return true;
    }
};

char* bind_interface = "enp7s0";// use -l to change

struct in_addr my_ip;

struct in_addr peer_ip,left_net,right_net;// use -peer,-left,-right to change

struct in_addr left_net_mask,right_net_mask;// use -leftmask, -rightmask to change

unsigned char peer_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

unsigned char my_mac[6];
unsigned short mtu_ip = 1500;//you can even try 28

const unsigned short more_frag_mask= 0x2000;
const unsigned short frag_offset_mask = 0x1fff;

const unsigned char proto_ipip = 4;

#define buf_sz 65536
#define max_frag_size 65536//actually supoort to 9000 Bytes jumbo frame is enough

int sock_fd;

void sigint_handler(sig_t s){
	close(sock_fd);
	exit(1); 
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
	if (in_cksum((unsigned short *)&l3_header,sizeof(l3_header)) == cksum) return 0;
	else return 1;
}

std::map <in_addr_t,mac_addr> mac_addr_table;

void send_ipip(unsigned char *payload,unsigned short len);
void send_eth(mac_addr dst,unsigned short proto,unsigned char *payload,unsigned int payloadlen);

void debug() {

}

void recv_ipv4(unsigned char *packet,unsigned short len,struct ethhdr *l2_header) {
	struct iphdr l3_header;
	memcpy(&l3_header,packet,sizeof(l3_header));
	struct in_addr saddr, daddr;
	memcpy(&saddr,&l3_header.saddr,sizeof(saddr));
	memcpy(&daddr,&l3_header.daddr,sizeof(saddr));
	if (len == 46 && ntohs(l3_header.tot_len) < 46) len = ntohs(l3_header.tot_len);
	if (len != ntohs(l3_header.tot_len)) {
		// printf("Packet size error\n");
		return;
	} 
	if (verify_cksum(l3_header)) {
		// printf("header cksum error\n");
		return;
	}
	/*
	char *src_ip_s = inet_ntoa(saddr);
	printf("src ip=%s, ",src_ip_s);
	char *dst_ip_s = inet_ntoa(daddr);
	printf("dst ip=%s\n",dst_ip_s);
	struct in_addr test;
	inet_aton("192.168.0.2",&test);
	if (test.s_addr == saddr.s_addr) {
		debug();
	}
	*/
    if (l2_header && (mac_addr(l2_header->h_dest) == mac_addr(my_mac) || daddr.s_addr == my_ip.s_addr) ) { // 学习源IP的MAC地址，这样就免去了ARP的实现
        if ( (saddr.s_addr & left_net_mask.s_addr) == left_net.s_addr) {
            // 发现是left net，学习地址
            mac_addr_table[saddr.s_addr] = mac_addr(l2_header->h_source);
			// printf("%s is at ",inet_ntoa(saddr));
			// mac_addr_table[saddr.s_addr].print();
        }
        else if (saddr.s_addr == peer_ip.s_addr) {
            // 发现是ipip路由器对端，学习地址
            mac_addr_table[saddr.s_addr] = mac_addr(l2_header->h_source);
			// printf("%s is at ",inet_ntoa(saddr));
			// mac_addr_table[saddr.s_addr].print();
        }
    }
	unsigned short more_frag = ntohs(l3_header.frag_off) & more_frag_mask;
	unsigned short frag_offset = (ntohs(l3_header.frag_off) & frag_offset_mask) << 3;
	unsigned char *payload = packet + (l3_header.ihl << 2);
	unsigned short payloadlen = ntohs(l3_header.tot_len) - (l3_header.ihl << 2);
	if ((more_frag || frag_offset) && l3_header.protocol == proto_ipip && l3_header.daddr == my_ip.s_addr) {
		static unsigned char frag_mem[1<<8][max_frag_size];//hash id to 8 bit
		static unsigned short frag_len[1<<8];
		static unsigned short frag_totlen[1<<8];
		unsigned char header_hash = get_header_hash(l3_header);
		if (payloadlen + frag_offset >= max_frag_size) {//check if this packet will result in buffer overflow
			// printf("bad packet\n");
			return;
		}
		frag_len[header_hash] += payloadlen;
		memcpy(&frag_mem[header_hash][frag_offset],payload,payloadlen);
		if (frag_totlen[header_hash] && frag_offset > frag_totlen[header_hash]) {
			frag_totlen[header_hash] = 0;
			// printf("drop frag\n");
		}
		if (!more_frag) frag_totlen[header_hash] = frag_offset + payloadlen;
		if (frag_len && frag_len[header_hash] == frag_totlen[header_hash]) {
			// printf("reassemble packet success\n");
            if (l3_header.protocol == proto_ipip) {
                recv_ipv4(frag_mem[header_hash],frag_totlen[header_hash],NULL);
            }
			frag_totlen[header_hash] = 0;
			frag_len[header_hash] = 0;
		}
	}
	else {
        if (l3_header.protocol == proto_ipip) {
            recv_ipv4(payload,payloadlen,NULL);
        }
        else if ( ( (saddr.s_addr & left_net_mask.s_addr) == left_net.s_addr) && ( (daddr.s_addr & right_net_mask.s_addr) == right_net.s_addr) && mac_addr(l2_header->h_dest) == mac_addr(my_mac)) {
            // 表示来自left net，需要转发到right net
            send_ipip(packet,len);
			// printf("tx\n");
        }
        else if ( ( (saddr.s_addr & right_net_mask.s_addr) == right_net.s_addr) && ( (daddr.s_addr & left_net_mask.s_addr) == left_net.s_addr)) {
            // 表示来自right net，需要转发到left net
			l3_header.ttl --;
			l3_header.check = 0;
			l3_header.check = in_cksum((unsigned short *)&l3_header,sizeof(l3_header));
			memcpy(packet,&l3_header,sizeof(l3_header));
            send_eth(mac_addr_table[daddr.s_addr],htons(ETH_P_IP),packet,len);
			// printf("rx\n");
        }
	}
    return;
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
			recv_ipv4(frame+sizeof(l2_header),len-sizeof(l2_header),&l2_header);
			break;
		default:
			//printf("unknow protocol %04x\n",ntohs(l2_header.h_proto));
			break;
	}
}
int lowbit_clear(int x,int len) {
	return x >> len << len;
}
void send_eth(mac_addr dst,unsigned short proto,unsigned char *payload,unsigned int payloadlen) {
	char buf[buf_sz];
	struct ethhdr l2_header;
	memcpy(&l2_header.h_dest,dst.addr,6);
	memcpy(&l2_header.h_source,my_mac,6);
	l2_header.h_proto = proto;
	memcpy(buf,&l2_header,sizeof(l2_header));
	memcpy(buf+14,payload,payloadlen);
	send(sock_fd,buf,payloadlen+14,0);
}
void send_ip(struct in_addr dst_ip,unsigned char protocol,unsigned char *payload,unsigned short len) {
	unsigned char buf[buf_sz];
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
			l3_header.check = in_cksum((unsigned short *)&l3_header,sizeof(l3_header));
			memcpy(buf,&l3_header,sizeof(l3_header));
			memcpy(buf+20,payload+i,(more_frag ? each_sz : len - i));
			send_eth(mac_addr_table[dst_ip.s_addr],htons(ETH_P_IP),buf,ntohs(l3_header.tot_len));
		}
	}
	else {
		l3_header.check = 0;
		l3_header.check = in_cksum((unsigned short *)&l3_header,sizeof(l3_header));
		memcpy(buf,&l3_header,sizeof(l3_header));
		memcpy(buf+20,payload,len);
		send_eth(mac_addr_table[dst_ip.s_addr],htons(ETH_P_IP),buf,len+20);
	}
}
void send_ipip(unsigned char *payload,unsigned short len) {
	unsigned char buf[buf_sz];
	struct iphdr l3_header;
    memcpy(&l3_header,payload,len);
    l3_header.ttl --;
	l3_header.check = 0;
    l3_header.check = in_cksum((unsigned short *)&l3_header,sizeof(l3_header));
    memcpy(buf,&l3_header,sizeof(l3_header));
    memcpy(buf+20,payload+20,len-20);
    send_ip(peer_ip,proto_ipip,buf,len);
}
void receiver() {
	unsigned char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(sock_fd,buf,buf_sz,0)) > 0) {
		recv_eth(buf,sz);
	}
}
int main(int argc,char *argv[]) {
	inet_aton("172.17.0.2",&peer_ip);//default ip address
	inet_aton("192.168.0.0",&left_net);
	inet_aton("192.168.1.0",&right_net);
	inet_aton("255.255.255.0",&left_net_mask);
	inet_aton("255.255.255.0",&right_net_mask);
	//use -l to bind for specific interface
	for (int i=0;i<argc;i++) if (i + 1 < argc) {
		if (strcmp(argv[i],"-l") == 0) {
			bind_interface = argv[i+1];
		}
		else if (!strcmp(argv[i],"-peer")) {
			inet_aton(argv[i+1],&peer_ip);
		}
		else if (!strcmp(argv[i],"-left")) {
			inet_aton(argv[i+1],&left_net);
		}
		else if (!strcmp(argv[i],"-right")) {
			inet_aton(argv[i+1],&right_net);
		}
		else if (!strcmp(argv[i],"-leftmask")) {
			inet_aton(argv[i+1],&left_net_mask);
		}
		else if (!strcmp(argv[i],"-rightmask")) {
			inet_aton(argv[i+1],&right_net_mask);
		}
	}
	left_net.s_addr &= left_net_mask.s_addr;
	right_net.s_addr &= right_net_mask.s_addr;
	printf("bind_interface = %s\n",bind_interface);
	printf("peer_ip = %s\n",inet_ntoa(peer_ip));
    printf("left_net = %s/",inet_ntoa(left_net));
    printf("%s\n",inet_ntoa(left_net_mask));
    printf("right_net = %s/",inet_ntoa(right_net));
    printf("%s\n",inet_ntoa(right_net_mask));
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
        mac_addr(my_mac).print();
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
	receiver();
	close(sock_fd);
	return 0;
}