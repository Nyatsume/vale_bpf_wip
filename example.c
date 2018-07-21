#include <net/vale_bpf_native_api.h>

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

struct udp {
  uint16_t sport;
  uint16_t dport;
  uint16_t length;
  uint16_t csum;
};

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

uint32_t
lookup(struct vale_bpf_native_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  if (data + sizeof(struct eth) > data_end) {
    return VALE_BPF_DROP;
  }

  struct eth *eth = data;

  /*
  bpf_trace_printk("dst1: %x:%x:%x\n",
    eth->dst[0], eth->dst[1], eth->dst[2]);

  bpf_trace_printk("dst2: %x:%x:%x\n",
    eth->dst[3], eth->dst[4], eth->dst[5]);
  */

  struct ip *ip = (struct ip *)(eth + 1);
  if (ip + 1 > data_end) {
    return VALE_BPF_DROP;
  }


 csum16_sub(ip->csum, ~(ip->saddr & 0xffff));
 csum16_sub(ip->csum, ~(ip->saddr >> 16));
 ip->saddr=123456;
 csum16_add(ip->csum, ~(ip->saddr & 0xffff));
 csum16_add(ip->csum, ~(ip->saddr >>16));
 
  bpf_trace_printk("%x\n", bpf_ntohl(ip->saddr));
  // ごにょごにょ IPアドレスとUDPのポートをそれぞれ出力
  struct udp *udp = (struct udp *)(ip + 1);
  if (udp + 1 > data_end) {
    return VALE_BPF_DROP;
  }


  bpf_trace_printk("%d,%d\n",bpf_ntohs(udp->sport),bpf_ntohs(udp->dport));

  return 1;
}
