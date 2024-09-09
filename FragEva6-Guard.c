#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>


#define IPPROTO_HOPOPTS   0
#define IPPROTO_TCP       6
#define IPPROTO_UDP       17
#define IPPROTO_ROUTING   43
#define IPPROTO_FRAGMENT  44
#define IPPROTO_ICMPV6    58
#define IPPROTO_DSTOPTS   60

#define MAX_EXT_HDRS      32  

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

struct fragment_hdr {
    __u8    nexthdr;
    __u8    reserved;
    __be16  frag_off;
    __be32  identification;
};

//static __u64 alert_count = 0;

/* Packet parsing helpers */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    if ((void *)(ip6h + 1) > data_end)
        return -1;

    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

#define IPV6_TLV_PAD1 0
#define IPV6_TLV_PADN 1
#define IPV6_TLV_ROUTERALERT 5
#define IPV6_TLV_JUMBO 194

static __always_inline int parse_opt_hdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct ipv6_opt_hdr **opt_hdr)
{
    struct ipv6_opt_hdr *hdr = nh->pos;

    if ((void *)(hdr + 1) > data_end)
        return -1;

    if (hdr->hdrlen > 60) {
        return -1;
    }

    *opt_hdr = hdr;

    __u8 *first_opt = (__u8 *)(hdr + 1);
    if ((void *)first_opt < data_end) { 
        __u8 opt_type = *first_opt;
        switch (opt_type) {
            case IPV6_TLV_PAD1:
            case IPV6_TLV_PADN:
            case IPV6_TLV_ROUTERALERT:
            case IPV6_TLV_JUMBO:
                break;
            default:
                //bpf_printk("IPv6 Unknown Option type!!\n");
                bpf_printk("Possible CVE-2024-38063 vulnerability detected!\n");
                return XDP_DROP;
        }
    }

    nh->pos = (void *)hdr + (hdr->hdrlen + 1) * 8;

    if (nh->pos > data_end)
        return -1;

    return hdr->nexthdr;
}

static __always_inline int parse_routing_hdr(struct hdr_cursor *nh,
                                             void *data_end,
                                             struct ipv6_rt_hdr **rt_hdr)
{
    struct ipv6_rt_hdr *hdr = nh->pos;

    if ((void *)(hdr + 1) > data_end)
        return -1;

    *rt_hdr = hdr;
    nh->pos = (void *)hdr + (hdr->hdrlen + 1) * 8;

    if (nh->pos > data_end)
        return -1;

    return hdr->nexthdr;
}

static __always_inline int parse_frag_hdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct fragment_hdr **frag_hdr)
{
    struct fragment_hdr *hdr = nh->pos;

    if ((void *)(hdr + 1) > data_end)
        return -1;

    *frag_hdr = hdr;
    nh->pos = hdr + 1;

    return hdr->nexthdr;
}

SEC("xdp")
int xdp_ipv6_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6hdr;
    struct ipv6_rt_hdr *rt_hdr;
    struct fragment_hdr *frag_hdr;
    struct ipv6_opt_hdr *hopopt_hdr;
    struct ipv6_opt_hdr *dstopts_hdr;

    struct hdr_cursor nh;
    int nh_type = 0;
    int first_frag=0;

    nh.pos = data;

    if ((void *)(nh.pos + sizeof(*eth)) > data_end)
        return XDP_PASS;

    nh_type = eth->h_proto;
    nh.pos = nh.pos + sizeof(*eth);

    if (nh_type != __constant_htons(ETH_P_IPV6) && nh_type != __constant_htons(ETH_P_IP)) {
        return XDP_DROP;
    }

    if (nh_type == __constant_htons(ETH_P_IPV6)) {
        nh_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);

        int ext_hdr_count = 0;
        int last_hdr_was_frag = 0;  
        
        while (ext_hdr_count < MAX_EXT_HDRS && nh.pos <= data_end) {
        //6Guard:Detecting the incompleted headerChain! 
            if (nh.pos == data_end && first_frag){ 
             	//bpf_printk("IPv6 HeaderChain Incompleted!!\n");
            	//return XDP_DROP;
            	if(nh_type == 6 || nh_type == 17 || nh_type == 58){
            	    bpf_printk("IPv6 HeaderChain Incompleted! Known Upper-layer!\n");
                    //alert_count++;
                    //bpf_printk("Alert count: %llu\n", alert_count);
                    /*if (alert_count == 1) {
                        bpf_printk("Alert count: %llu\n", alert_count);
                    }
                    else if (alert_count % 500 == 0) {
                        bpf_printk("Alert count: %llu\n", alert_count);
                    }*/
            	    return XDP_DROP;
            }
            	else if(nh_type != 6 && nh_type != 17 && nh_type != 58 && nh_type != 59){
            	    bpf_printk("IPv6 HeaderChain Incompleted! Unknown Upper-layer!\n");
            	    //alert_count++;
            	    //bpf_printk("Alert count: %llu\n", alert_count);
                    /*if (alert_count == 1) {
                        bpf_printk("Alert count: %llu\n", alert_count);
                    }
                    else if (alert_count % 500 == 0) {
                        bpf_printk("Alert count: %llu\n", alert_count);
                    }*/
            	    return XDP_DROP;
            	}	           	
            }
			if (nh_type == IPPROTO_HOPOPTS) {
		        nh_type = parse_opt_hdr(&nh, data_end, &hopopt_hdr);
		        if (nh_type == -1) {
		            return XDP_DROP;
		        }
		       /* if ((void *)(hopopt_hdr + 1) <= data_end) {
		            bpf_printk("IPv6 HOPOPTS Header detected!\n");
		            bpf_printk("nexthdr: %d\n", hopopt_hdr->nexthdr);
		            bpf_printk("hdrlen: %d\n", hopopt_hdr->hdrlen);
		        }*/
		    } else if (nh_type == IPPROTO_DSTOPTS) {
		        nh_type = parse_opt_hdr(&nh, data_end, &dstopts_hdr);
		        if (nh_type == -1) {
		            return XDP_DROP;
		        }
		      /*   if ((void *)(dstopts_hdr + 1) <= data_end) {
		            bpf_printk("IPv6 DSTOPTS Header detected!\n");
		            bpf_printk("nexthdr: %d\n", dstopts_hdr->nexthdr);
		            bpf_printk("hdrlen: %d\n", dstopts_hdr->hdrlen);
		        }*/
		    } else if (nh_type == IPPROTO_ROUTING) {
		        nh_type = parse_routing_hdr(&nh, data_end, &rt_hdr);
		        if (nh_type == -1) {
		            return XDP_DROP;
		        }
		       /* if ((void *)(rt_hdr + 1) <= data_end) {
		            bpf_printk("IPv6 Routing Header detected!\n");
		            bpf_printk("nexthdr: %d\n", rt_hdr->nexthdr);
		            bpf_printk("hdrlen: %d\n", rt_hdr->hdrlen);
		            bpf_printk("type: %d\n", rt_hdr->type);
		            bpf_printk("segments_left: %d\n", rt_hdr->segments_left);
		        } */
		    } else if (nh_type == IPPROTO_FRAGMENT) {
		        if (last_hdr_was_frag) {
		            bpf_printk("Possible cve-2021-24086 vulnerability detected!\n");
		            return XDP_DROP;
		        }
		        		    
		        nh_type = parse_frag_hdr(&nh, data_end, &frag_hdr);
		        if (nh_type == -1) {
		            return XDP_DROP;
		        }
		        if ((void *)(frag_hdr + 1) <= data_end) {
		           /* bpf_printk("IPv6 Fragment Header detected!\n");
		            bpf_printk("nexthdr: %d\n", frag_hdr->nexthdr);
		            bpf_printk("reserved: %d\n", frag_hdr->reserved);
		            bpf_printk("frag_off: %d\n", frag_hdr->frag_off);
		            bpf_printk("identification: %d\n", frag_hdr->identification);*/
		            if ((frag_hdr->frag_off & __constant_htons(0xfff8)) == 0) {
                        first_frag = 1;
                    }
		        } 
		        last_hdr_was_frag = 1;  
		    } else {
		    	last_hdr_was_frag = 0;  
		        break;
		    }            
            if (nh_type == -1) {
                return XDP_DROP;
            }
            ext_hdr_count++;
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
