#pragma once

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include "decoder_http.h"
#include "decoder_ssh.h"
#include "decoder_tls.h"

const uint32_t IP_OPTMAX      = 40;
const uint32_t TCP_OPTLENMAX  = 40;

const uint32_t TCP_FLAG_FIN = 0x01;
const uint32_t TCP_FLAG_SYN = 0x02;
const uint32_t TCP_FLAG_RST = 0x04;
const uint32_t TCP_FLAG_PSH = 0x08;
const uint32_t TCP_FLAG_ACK = 0x10;
const uint32_t TCP_FLAG_URG = 0x20;
const uint32_t TCP_FLAG_ECE = 0x40;  /* ECN echo, RFC 3168 */
const uint32_t TCP_FLAG_CWR = 0x80;  /* Congestion Window Reduced, RFC 3168 */
const uint32_t JUMBO_MTU    = 9000;

const uint32_t PROTO_FLAG_NONE = 0x0000;
const uint32_t PROTO_FLAG_IP   = 0x0001;
const uint32_t PROTO_FLAG_TCP  = 0x0004;
const uint32_t PROTO_FLAG_UDP  = 0x0008;
const uint32_t PROTO_FLAG_ALL  = 0xffff;

const uint32_t HDR_ETHER_LEN   = 14;
const uint32_t HDR_VLAN_LEN    = 4;
const uint32_t HDR_IP_LEN      = 20;
const uint32_t HDR_TCP_LEN     = 20;

const uint32_t ETHER_MTU        = 1500;
const uint32_t ETHER_MTU_ENCAP  = 1518;
const uint32_t ETHER_TYPE_IP    = 0x0800;
const uint32_t ETHER_TYPE_IPV6  = 0x86dd;
const uint32_t ETHER_TYPE_VLAN  = 0x8100;

const uint32_t IP6_MAX_EXT      = 8;
const uint32_t ETH_DSAP         = 0xaa;
const uint32_t ETH_SSAP         = 0xaa;

struct raw_tcp_hdr_t
{
    uint16_t src_port;    
    uint16_t dst_port;     
    uint32_t seq;           
    uint32_t ack;           
    uint8_t  offset;    /* Offset and reserved */
    uint8_t  flags;
    uint16_t win;           
    uint16_t csum;          
    uint16_t urg;           
};

struct raw_ip_hdr_t
{
    uint8_t  verhl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id; 
    uint16_t off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    struct in_addr src;
    struct in_addr dst;
};

struct raw_ip6_hdr_t {
    union
    {
        struct _ip6_ctl_t
        {
            uint32_t ip6_flow;   /* 4 bits version, 8 bits TC, 20 bits for ID */
            uint16_t ip6_plen;   
            uint8_t  ip6_next;  
            uint8_t  ip6_hlim;   /* Hop limit */
        };

        uint8_t ip6_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctl_t;

    struct in6_addr src;      /* source address */
    struct in6_addr dst;      /* destination address */
};

struct vlan_tag_hdr_t
{
    uint16_t pri_cfi_vlan;
    uint16_t proto;  /* protocol field... */
};

struct vlan_eth_llc_t
{
    uint8_t dsap;
    uint8_t ssap;
};

struct vlan_eth_llc_other_t
{
    uint8_t ctrl;
    uint8_t org_code[3];
    uint16_t proto_id;
};

#define VLAN_LEN_ALL (sizeof(vlan_tag_hdr_t) + sizeof(vlan_eth_llc_t) + sizeof(vlan_eth_llc_other_t))

struct options_t
{
    uint8_t code;
    uint8_t len; /* length of the data section */
    const uint8_t *data;
};

struct ether_hdr_t
{
    uint8_t ether_dst[6];
    uint8_t ether_src[6];
    uint16_t ether_type;
};

struct tmod_ip6h_t 
{
    raw_ip6_hdr_t *rawiph;
};

struct tmod_iph_t 
{
    raw_ip_hdr_t *rawiph;

    uint16_t 
        actual_ip_len,
        ip_opt_len,
        ip_opt_count,
        frag_offset,
        ip_frag_len,
        proto_bits,
        payload_size;
    uint8_t
        reserved_flag,
        dont_frag,
        more_frag,
        frag_flag,
        family,
        *ip_frag_start,
        *payload;
    uint8_t *ip_options_data;
    options_t ip_options[IP_OPTMAX];
};

struct tmod_tcph_t 
{
    raw_tcp_hdr_t *rawtcp;
    uint8_t *ip_options_data;
    uint8_t *tcp_options_data;
    uint16_t tcp_options_len;
    uint16_t tcp_option_count;
    options_t tcp_options[TCP_OPTLENMAX];
};

struct tmod_vlan_t
{
    vlan_tag_hdr_t *raw;
    vlan_eth_llc_t *ehllc;
    vlan_eth_llc_other_t *ehllcother;
};

class tmod_pkt_t 
{
    const tmod_pkt_t &operator=(const tmod_pkt_t &pkt);
public:
    tmod_pkt_t();
    
    /* Effectively a copy constructor. Chose this route since the packet buffer
       is managed outside of the class. */
    void copy(const tmod_pkt_t &pkt, uint8_t *buffer);

    const uint8_t *raw_pkt;
    uint32_t raw_size;
    timeval timestamp;
    const uint8_t *payload;
    uint32_t payload_size;
    void *user;

    tmod_iph_t iph;
    tmod_ip6h_t ip6h;
    tmod_tcph_t tcph;
    tmod_vlan_t vlan;
};

struct tmod_proto_stats_t 
{
    uint32_t 
        packets,
        ip4,
        ip6,
        tcp,
        ip_embedded,
        ip_bad_len,
        ip_bad_ver,
        ip_bad_hdr_len,
        ip_packet_trunc,
        ip_trunc,
        ip_opts,
        ip_frags,
        ip_other_proto,
        tcp_opt_too_large,
        overlaps
        ;
};

extern tmod_proto_stats_t stats;

void hex_dump(const uint8_t *, int);

bool decode(tmod_pkt_t &packet,
            const struct pcap_pkthdr *pkthdr, 
            const uint8_t *pkt);


bool decode_http(tmod_pkt_t &pkt);
bool decode_ssh(tmod_pkt_t &pkt);
bool decode_tls(tmod_pkt_t &pkt);

void tmod_decoder_init();
