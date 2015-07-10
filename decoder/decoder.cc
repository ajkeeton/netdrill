
#include <pcap.h>
#include <arpa/inet.h>
#include "decoder.h"

extern tmod_proto_stats_t stats;

void tmod_decode_ip4(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);
void tmod_decode_ip6(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);
void tmod_decode_ip4_embedded(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);
void tmod_decode_ip4_options(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);
void tmod_decode_ip6_options(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);
void tmod_decode_tcp_options(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len);

static inline uint32_t iph_verhl_to_ver(uint32_t verhl) 
{
    return (verhl & 0xf0) >> 4;
}

static inline uint32_t iph_verhl_to_hlen(uint32_t verhl)
{
    return verhl & 0x0f;
}

static inline uint32_t tcph_get_offset(uint32_t val)
{
    return (val & 0xf0) >> 4;
}

void tmod_decode_tcp(tmod_pkt_t *stream, const uint8_t *pkt, uint32_t len)
{
    if(len < HDR_TCP_LEN)
        return;

    stats.tcp++;

    raw_tcp_hdr_t *rawtcp = (raw_tcp_hdr_t*)pkt;

    uint32_t hlen = tcph_get_offset(rawtcp->offset) << 2;

    if(hlen < HDR_TCP_LEN)
        return;

    if(hlen > len)
        return;

    tmod_tcph_t *tcph = &stream->tcph;
    tcph->rawtcp = rawtcp;

    /* Decode any tcp options */
    tcph->tcp_options_len = (uint16_t)(hlen - HDR_TCP_LEN);

    if(tcph->tcp_options_len > 0) {
        tcph->tcp_options_data = (uint8_t*)(pkt + HDR_TCP_LEN);
        tmod_decode_tcp_options(
            stream, pkt + HDR_TCP_LEN, tcph->tcp_options_len);
    }
    else {
        tcph->tcp_option_count = 0;
    }

    stream->payload = pkt + hlen;

    if(hlen < len)
        stream->payload_size = len - hlen;
}

int tmod_tcp_opt_length_validate(
    uint8_t *option_ptr,
    uint8_t *end,
    uint8_t *len_ptr,
    int expected_len,
    options_t *tcpopt,
    uint8_t *byte_skip)
{
    return 0;
    // TODO
}

void tmod_decode_tcp_options(
    tmod_pkt_t *stream, const uint8_t *pkt, uint32_t options_len)
{
    if(options_len > TCP_OPTLENMAX) {
        stats.tcp_opt_too_large++;
        return;
    }
    
    // TODO
}

void tmod_decode_ip4_options(tmod_pkt_t *stream, const uint8_t *pkt)
{
    // TODO
}

void tmod_decode_ip4_embedded(
    tmod_pkt_t *stream, uint8_t *pkt, uint32_t len)
{
    /* Not supported. */
    stats.ip_embedded++;
}

void tmod_decode_ip4(tmod_pkt_t *stream, uint8_t *pkt, uint32_t len)
{
    stats.ip4++;

    if(len < HDR_IP_LEN) {
        stats.ip_bad_len++;
        // XXX log something?
        return;
    }

    raw_ip_hdr_t *rawiph = (raw_ip_hdr_t*)pkt;

    if(iph_verhl_to_ver(rawiph->verhl) != 4) {
        /* This should not have happened. Previous layer said we were IP4! 
           :( */
        stats.ip_bad_ver++;
        return;
    }

    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */ 
    uint32_t hlen;   /* ip header length */
   
    /* The IP datagram length */
    ip_len = ntohs(rawiph->len);

    /* The IP header length */
    hlen = iph_verhl_to_hlen(rawiph->verhl) << 2;

    /* header length sanity check */
    if(hlen < HDR_IP_LEN) {
        // IP header is too small. 
        stats.ip_bad_hdr_len++;
        return;
    }

    if(ip_len > len) {
        stats.ip_packet_trunc++;
        return;
    }

    /* Verify that the reported IP datagram length is long enough to fit the 
       IP header itself */
    if(ip_len < hlen) {
        // IP header datagram length is too short to fit the IP header.
        stats.ip_trunc++;
        return;
    }

    tmod_iph_t *riph = &stream->iph;
    riph->rawiph = rawiph;

    /* test for IP options */
    riph->ip_opt_len = (uint16_t)(hlen - HDR_IP_LEN);

    if(riph->ip_opt_len) {
        stats.ip_opts++;
        riph->ip_options_data = pkt + HDR_IP_LEN;
        tmod_decode_ip4_options(stream, pkt + HDR_IP_LEN);
    }
    else {
        riph->ip_opt_count = 0;
    }

    riph->actual_ip_len = (uint16_t)ip_len;

    ip_len -= hlen;

    riph->frag_offset = ntohs(rawiph->off);
    riph->reserved_flag = (uint8_t)((riph->frag_offset & 0x8000) >> 15);
    riph->dont_frag = (uint8_t)((riph->frag_offset & 0x4000) >> 14);
    riph->more_frag = (uint8_t)((riph->frag_offset & 0x2000) >> 13);
    riph->frag_offset &= 0x1FFF;

    if(riph->frag_offset || riph->more_frag) {
        stats.ip_frags++;
        riph->frag_flag = true;
        riph->ip_frag_start = pkt + hlen;
        riph->ip_frag_len = (uint16_t)ip_len;
    } 
    else {
        riph->frag_flag = false;
    }

    /* Convenience pointers */
    riph->payload = pkt + hlen;
    riph->payload_size = (u_short)ip_len;
    riph->proto_bits |= PROTO_FLAG_IP;

    if(!riph->frag_flag || 
        (riph->frag_flag && 
          (riph->frag_offset == 0) && (rawiph->proto == IPPROTO_UDP) ))
    {
        switch(rawiph->proto)
        {
            case IPPROTO_TCP:
                tmod_decode_tcp(stream, pkt + hlen, ip_len);
                return;

            case IPPROTO_IPIP:
                tmod_decode_ip4_embedded(stream, pkt + hlen, ip_len);
                return;

            case IPPROTO_GRE:
                //tmod_decode_gre(stream, pkt + hlen, ip_len);
                break;

            default:
                stats.ip_other_proto++;
                stream->payload = pkt + hlen;
                stream->payload_size = ip_len;
                return;
        }
    }
    else
    {
        stream->payload = pkt + hlen;
        stream->payload_size = ip_len;
    }
}

void tmod_decode_ip6(tmod_pkt_t *stream, uint8_t *pkt, uint32_t len)
{
    stats.ip6++;
    #warning ipv6 decoder not yet implemented
}

void tmod_decode_vlan(tmod_pkt_t *stream, uint8_t *pkt, uint32_t len)
{
    if(len < HDR_VLAN_LEN) {
        // Err/stat?
        return;
    }  

    stream->vlan.raw = (vlan_tag_hdr_t *)pkt;

    // Check to see if there's an encapsulated LLC layer
    // If it's LLC, the type field becomes the lenght which should be less than 1518.
    if(ntohs(stream->vlan.raw->proto) <= ETHER_MTU_ENCAP) {
        if(len < sizeof(vlan_tag_hdr_t) + sizeof(vlan_eth_llc_t)) {
            // XXX tick stat
            return;
        }

        stream->vlan.ehllc = (vlan_eth_llc_t *) (pkt + sizeof(vlan_tag_hdr_t));

        if(stream->vlan.ehllc->dsap == ETH_DSAP && 
           stream->vlan.ehllc->ssap == ETH_SSAP) {
            if(len < VLAN_LEN_ALL) {
                // XXX tick stat
                return;
            }

            stream->vlan.ehllcother = (vlan_eth_llc_other_t *)
                (pkt + sizeof(vlan_tag_hdr_t) + sizeof(vlan_eth_llc_t));

            switch(ntohs(stream->vlan.ehllcother->proto_id)) {
                case ETHER_TYPE_IP:
                    tmod_decode_ip4(stream, 
                             pkt + VLAN_LEN_ALL,
                             len - VLAN_LEN_ALL);
                    return;

                case ETHER_TYPE_IPV6:
                    tmod_decode_ip6(stream,
                             (uint8_t*)pkt + VLAN_LEN_ALL,
                             len - VLAN_LEN_ALL);
                    return;

                case ETHER_TYPE_VLAN:
                    tmod_decode_vlan(
                                stream,
                                (uint8_t*)pkt + VLAN_LEN_ALL,
                                len - VLAN_LEN_ALL);
                    return;

                default:
                    return;
            }
        }
    }
    else {
        switch(ntohs(stream->vlan.raw->proto)) {
            case ETHER_TYPE_IP:
                tmod_decode_ip4(stream, 
                        pkt + sizeof(vlan_tag_hdr_t),
                        len - sizeof(vlan_tag_hdr_t));
                return;

            case ETHER_TYPE_IPV6:
                tmod_decode_ip6(stream,
                        pkt + sizeof(vlan_tag_hdr_t),
                        len - sizeof(vlan_tag_hdr_t));
                return;

            case ETHER_TYPE_VLAN:
                tmod_decode_vlan(stream,
                        pkt + sizeof(vlan_tag_hdr_t),
                        len - sizeof(vlan_tag_hdr_t));
                return;

            default:
                return;
        }
    }
}

bool decode(
    tmod_pkt_t &packet,
    const struct pcap_pkthdr *pkthdr, 
    const uint8_t *pkt)
{
    stats.packets++;

    if(pkthdr->caplen < HDR_ETHER_LEN) {
        return false;
    }

    packet.raw_pkt = pkt; 
    packet.raw_size = pkthdr->caplen;
    packet.payload = NULL;
    packet.payload_size = 0;
    packet.timestamp = pkthdr->ts;

    ether_hdr_t *eh = (ether_hdr_t*)pkt;

    switch(ntohs(eh->ether_type))
    {
        case ETHER_TYPE_IP:
            tmod_decode_ip4(
                &packet,
                (uint8_t*)packet.raw_pkt + HDR_ETHER_LEN, 
                pkthdr->caplen - HDR_ETHER_LEN);

            break;

        case ETHER_TYPE_IPV6:
            tmod_decode_ip6(
                &packet,
                (uint8_t*)packet.raw_pkt + HDR_ETHER_LEN, 
                pkthdr->caplen - HDR_ETHER_LEN);

            break;

        case ETHER_TYPE_VLAN:
            tmod_decode_vlan(
                &packet,
                (uint8_t*)packet.raw_pkt + HDR_ETHER_LEN, 
                pkthdr->caplen - HDR_ETHER_LEN);

        break;
    }

    return true;
}

tmod_pkt_t::tmod_pkt_t()
{ 
    raw_pkt = NULL;
    user = NULL;
    payload = NULL;
    raw_size = 0;
    memset(&iph, 0, sizeof(iph));
    memset(&ip6h, 0, sizeof(ip6h));
    memset(&tcph, 0, sizeof(tcph));
    memset(&vlan, 0, sizeof(vlan));
}

static uint8_t *generate_offset(
    const void *raw_pkt, const void *top, const void *bottom)
{
    return (uint8_t*)raw_pkt + ((uint8_t*)top - (uint8_t*)bottom);
}

void tmod_pkt_t::copy(const tmod_pkt_t &pkt, uint8_t *buffer) 
{
    raw_pkt = buffer;
    raw_size = pkt.raw_size; 
    timestamp = pkt.timestamp;
    payload = raw_pkt + (pkt.payload - pkt.raw_pkt);
    payload_size = pkt.payload_size;
    user = pkt.user;

    iph = pkt.iph;

    if(pkt.iph.rawiph) {
        iph.rawiph = (raw_ip_hdr_t*)generate_offset(raw_pkt, pkt.iph.rawiph, pkt.raw_pkt);

        if(pkt.iph.ip_frag_start)
            iph.ip_frag_start = generate_offset(raw_pkt, pkt.iph.ip_frag_start, pkt.raw_pkt);
        else
            iph.ip_frag_start = NULL;

        if(pkt.iph.payload)
            iph.payload = generate_offset(raw_pkt, pkt.iph.payload, pkt.raw_pkt);
        else
            iph.payload = NULL;
    
        if(pkt.iph.ip_options_data) {
            iph.ip_options_data = 
                generate_offset(raw_pkt, pkt.iph.ip_options_data, pkt.raw_pkt);
            memcpy(iph.ip_options, pkt.iph.ip_options, sizeof(iph.ip_options));
        }
        else
            iph.ip_options_data = NULL;
    }
    else {
        iph.rawiph = NULL;
        iph.ip_frag_start = NULL;
        iph.payload = NULL;
        iph.ip_options_data = NULL;
    }

    ip6h = pkt.ip6h;

    if(pkt.ip6h.rawiph)
        ip6h.rawiph = (raw_ip6_hdr_t*)generate_offset(raw_pkt, pkt.ip6h.rawiph, pkt.raw_pkt);
    else
        ip6h.rawiph = NULL;

    tcph = pkt.tcph;

    if(pkt.tcph.rawtcp) {
        tcph.rawtcp = 
            (raw_tcp_hdr_t*)generate_offset(raw_pkt, pkt.tcph.rawtcp, pkt.raw_pkt);

        if(pkt.tcph.ip_options_data)
            tcph.ip_options_data = 
                generate_offset(raw_pkt, pkt.tcph.ip_options_data, pkt.raw_pkt);
        else
            tcph.ip_options_data = NULL;

        if(tcph.tcp_options_data)
            tcph.tcp_options_data = 
                generate_offset(raw_pkt, pkt.tcph.tcp_options_data, pkt.raw_pkt);
        else
            tcph.tcp_options_data = NULL;
    }
    else {
        tcph.rawtcp = NULL;
        tcph.ip_options_data = NULL;
        tcph.tcp_options_data = NULL;
    }

    vlan = pkt.vlan;

    if(pkt.vlan.raw) {
        vlan.raw = (vlan_tag_hdr_t*)
            generate_offset(raw_pkt, pkt.vlan.raw, pkt.raw_pkt);
        vlan.ehllc = (vlan_eth_llc_t*)
            generate_offset(raw_pkt, pkt.vlan.ehllc, pkt.raw_pkt);
        vlan.ehllcother = (vlan_eth_llc_other_t*)
            generate_offset(raw_pkt, pkt.vlan.ehllcother, pkt.raw_pkt);
    }
    else {
        vlan.raw = NULL;
        vlan.ehllc = NULL;
        vlan.ehllcother = NULL;
    }
}
