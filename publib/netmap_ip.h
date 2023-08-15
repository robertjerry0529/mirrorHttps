#ifndef IP_HEAD___
#define IP_HEAD___





#define ICMP_PROT  1
#define TCP_PROT  6
#define UDP_PROT  17


#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_MIN_IPHDR_LEN  20
#define ETH_ARP_LEN   28
#define ETH_UDP_LEN  8
#define MINIPSIZE 20






struct iphdr_bm {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	unsigned char	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	unsigned char	version:4,
  		ihl:4;
#else
#error	"Please define endian bitfield"
#endif
	unsigned char 	tos;
	unsigned short	tot_len;
	unsigned short	id;
	unsigned short	frag_off;
	unsigned char	ttl;
	unsigned char	protocol;
	unsigned short	check;
	unsigned int	saddr;
	unsigned int	daddr;
	/*The options start here. */
};
#ifdef WIN32
#pragma pack(push,1)
#endif

struct ethhdr_bm {
	unsigned char	h_dest[ETH_ALEN];	
	unsigned char	h_source[ETH_ALEN];	
	unsigned short	h_proto;		
}

#ifdef WIN32

#pragma pack(pop)
#elif defined(GNU)
__attribute__((packed));
#endif


#ifdef WIN32
#pragma pack(push,1)
#endif


#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG)

struct tcptype {
	in_port_t	sport;
	in_port_t	dport;
	unsigned int		seq;
	unsigned int		ack; 
	unsigned char		len;		/* high 4 bits is len */
	unsigned char		flags;
	unsigned short		window;
	unsigned short		checksum; 
	unsigned short		urgentpointer;
};

struct udptype {
	in_port_t	sport;		
	in_port_t	dport;		
	unsigned short		length;		
	unsigned short		checksum;	
	unsigned int		udpdata[0];	
};


typedef struct Protoh Protoh;
struct Protoh {
	in_addr_t saddr;
	in_addr_t daddr;
	unsigned char zero;
	unsigned char proto;
	unsigned short len;
};

struct arphdr
{
	unsigned short		ar_hrd;		
	unsigned short		ar_pro;		
	unsigned char		ar_hln;		
	unsigned char		ar_pln;		
	unsigned short		ar_op;		

	unsigned char		ar_sha[ETH_ALEN];	
	unsigned char		ar_sip[4];		
	unsigned char		ar_tha[ETH_ALEN];	
	unsigned char		ar_tip[4];		

}
#ifdef WIN32
#pragma pack(pop)
#elif defined(GNU)
__attribute__((packed));
#endif


      
#endif

