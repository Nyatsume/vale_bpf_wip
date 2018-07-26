#include <net/vale_bpf_native_api.h>
#define ETH_P_IP 0x0008
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define DIRECTION_IN 0
#define DIRECTION_OUT 1

#define VIP 0x0100000a // 10.0.0.3 network byteorder
#define SERVER_IP2 0x0200000a// 10.0.0.2 network byteorder
#define SERVER_IP3 0x0300000a

struct eth {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
};

struct ip {
  uint8_t verihl;
  uint8_t tos;
  uint16_t tot_length;
  uint16_t id;
  uint16_t flagofs;
  uint8_t ttl;
  uint8_t proto;
  uint16_t csum;
  uint32_t saddr;
  uint32_t daddr;
};

struct tcp {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t res1:4;
  uint16_t doff:4;
  uint16_t fin:1;
  uint16_t syn:1;
  uint16_t rst:1;
  uint16_t psh:1;
  uint16_t ack:1;
  uint16_t urg:1;
  uint16_t res2:2;
  uint16_t window;
  uint16_t csum;
  uint16_t urg_ptr;
};

struct udp {
  uint16_t sport;
  uint16_t dport;
  uint16_t length;
  uint16_t csum;
};

#define FNV_32_PRIME ((uint32_t) 0x01000193UL)
static inline __attribute__((always_inline)) uint32_t
fnv_32_hash(const void *buf, size_t len, uint32_t hval)
{
  const u_int8_t *s = (const u_int8_t *)buf;

  while (len-- != 0) {
    hval *= FNV_32_PRIME;
    hval ^= *s++;
  }

  return hval;
}

static inline __attribute__((always_inline)) uint16_t
csum16_add(uint16_t csum, uint16_t addend)
{
	  uint16_t ret = csum + addend;
	    return ret + (ret < addend);
}

static inline __attribute__((always_inline)) uint16_t
csum16_sub(uint16_t csum, uint16_t addend)
{
	  return csum16_add(csum, ~addend);
}

static inline __attribute__((always_inline)) void
rewrite_addr_ipv4(struct ip *ip, uint32_t rewrite_addr,uint32_t *addr)
{
	// IPヘッダの中のアドレス書き換え & チェックサム再計算

  
  ip->csum = csum16_sub(ip->csum, ~(*addr & 0xffff));
  ip->csum = csum16_sub(ip->csum, ~(*addr >> 16));
  ip->csum = csum16_add(ip->csum, ~(rewrite_addr & 0xffff));
  ip->csum = csum16_add(ip->csum, ~(rewrite_addr >> 16));
   *addr = rewrite_addr;
 }


static inline __attribute__((always_inline)) void
rewrite_addr_udp(struct udp *udp, struct ip *ip, uint32_t rewrite_addr, uint32_t *addr)
{
	
	// UDPのチェックサム再計算
  udp->csum = csum16_sub(udp->csum, ~(*addr & 0xffff));
  udp->csum = csum16_sub(udp->csum, ~(*addr >> 16));
  
	rewrite_addr_ipv4(ip, rewrite_addr, addr);
  udp->csum = csum16_add(udp->csum, ~(rewrite_addr & 0xffff));
  udp->csum = csum16_add(udp->csum, ~(rewrite_addr >> 16));
	
}

static inline __attribute__((always_inline)) void
rewrite_addr_tcp(struct tcp *tcp, struct ip *ip, uint32_t rewrite_addr, uint32_t *addr)
{

	// TCPのチェックサム再計算
  tcp->csum = csum16_sub(tcp->csum, ~(*addr & 0xffff));
  tcp->csum = csum16_sub(tcp->csum, ~(*addr >> 16));
	rewrite_addr_ipv4(ip, rewrite_addr, addr);
  tcp->csum = csum16_add(tcp->csum, ~(rewrite_addr & 0xffff));
  tcp->csum = csum16_add(tcp->csum, ~(rewrite_addr >> 16));
}

uint32_t
lookup(struct vale_bpf_native_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  uint32_t ingress_port = ctx->ingress_port;

  if (data + sizeof(struct eth) > data_end) {
    bpf_trace_printk("pkt dropped");	 
    return VALE_BPF_DROP;
  }

  struct eth *eth = data;
  if (eth->type != ETH_P_IP) {
    bpf_trace_printk("pkt dropped");
    return VALE_BPF_DROP;
  }

  struct ip *ip = (struct ip *)(eth + 1);
  if (ip + 1 > data_end) {
    bpf_trace_printk("pkt dropped");	 
    return VALE_BPF_DROP;
  }

  // ごにょごにょ IPアドレスとUDPのポートをそれぞれ出力
  struct udp *udp;
  struct tcp *tcp;
  uint16_t port;

  if (ip->proto == IPPROTO_UDP) {
    udp = (struct udp *)(ip + 1);
    if (udp + 1 > data_end) {
	    bpf_trace_printk("pkt dropped");
      return VALE_BPF_DROP;
    }
    port = udp->sport;
  } else if (ip->proto == IPPROTO_TCP) {
    tcp = (struct tcp *)(ip + 1);
    if (tcp + 1 > data_end) {
	    bpf_trace_printk("pkt dropped");
      return VALE_BPF_DROP;
    }
    port = tcp->sport;
  } else {
　bpf_trace_printk("pkt dropped");
    return VALE_BPF_DROP;
  }

  // サーバー側から来たパケット
  if (ingress_port != 0) {
    if (ip->proto == IPPROTO_UDP) {
      rewrite_addr_udp(udp, ip, VIP, &ip->saddr);
    } else if (ip->proto == IPPROTO_TCP) {
      rewrite_addr_tcp(tcp, ip, VIP,&ip->saddr);
    }

    return 0;
  }
   
  // これいこうの処理はクライアント側からきたやつ

  // IPアドレスとUDPのポート番号を元にハッシュ値を計算
  uint32_t hash = 0;
  hash = fnv_32_hash(&ip->saddr, sizeof(uint32_t), hash);
  hash = fnv_32_hash(&port, sizeof(uint16_t), hash);
  hash = fnv_32_hash(&ip->proto, sizeof(uint8_t), hash);

  // % 2 で丸める
  uint32_t mod = hash % 2;
  if (mod == 0) {
    eth->dst[0] = 0xa0;
    eth->dst[1] = 0x36;
    eth->dst[2] = 0x9f;
    eth->dst[3] = 0x1a;
    eth->dst[4] = 0x2d;
    eth->dst[5] = 0xfc;
    if (ip->proto == IPPROTO_UDP) {
      rewrite_addr_udp(udp, ip, SERVER_IP2,&ip->daddr );
    } else if (ip->proto == IPPROTO_TCP) {
      rewrite_addr_tcp(tcp, ip, SERVER_IP2, &ip->daddr);
    }
    


	  return 1; // なんとか
  } else if (mod == 1) {
     eth->dst[0] = 0xa0;
     eth->dst[1] = 0x36;
     eth->dst[2] = 0x9f;
     eth->dst[3] = 0x1a;
     eth->dst[4] = 0x2d;
     eth->dst[5] = 0xfe;

      if (ip->proto == IPPROTO_UDP) {
        rewrite_addr_udp(udp, ip, SERVER_IP3, &ip->daddr);
      } else if (ip->proto == IPPROTO_TCP) {
        rewrite_addr_tcp(tcp, ip, SERVER_IP3, &ip->daddr);
      }
	  // IP書き換え、チェックサム計算
	  return 2; // なんとか
  }

  /*
  bpf_trace_printk("%d,%d\n",bpf_ntohs(udp->sport),bpf_ntohs(udp->dport));
  ip->csum = csum16_sub(ip->csum, ~(ip->saddr & 0xffff));
  ip->csum = csum16_sub(ip->csum, ~(ip->saddr >> 16));
  udp->csum = csum16_sub(udp->csum, ~(ip->saddr & 0xffff));
  udp->csum = csum16_sub(udp->csum, ~(ip->saddr >> 16));
  ip->saddr=123456;  
  ip->csum = csum16_add(ip->csum, ~(ip->saddr & 0xffff));
  ip->csum = csum16_add(ip->csum, ~(ip->saddr >>16));
  udp->csum = csum16_add(udp->csum, ~(ip->saddr & 0xffff));
  udp->csum = csum16_add(udp->csum, ~(ip->saddr >> 16));
  */
  bpf_trace_printk("pkt dropped");
  return VALE_BPF_DROP;
}
