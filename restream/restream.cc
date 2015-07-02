/* 
    Copyright (C) 2010 Adam Keeton <ajkeeton at gmail>
*/

#include <pcap.h>
#include <arpa/inet.h>
#include "restream.h"

tmod_stats_t stats;
ssn_stats_t ssn_stats;

void restream_dump_packet(const tmod_pkt_t &pkt) 
{
    char srcip[128], dstip[128];
    uint32_t tmpip = ntohl(pkt.iph.rawiph->src.s_addr);
    inet_ntop(AF_INET, &tmpip, srcip, sizeof(srcip));
    tmpip = ntohl(pkt.iph.rawiph->dst.s_addr);
    inet_ntop(AF_INET, &tmpip, dstip, sizeof(dstip));
    printf("*** %s:%d -> %s:%d\n", 
        srcip, ntohs(pkt.tcph.rawtcp->src_port), 
        dstip, ntohs(pkt.tcph.rawtcp->dst_port));
}

void restream_print_stats()
{
    printf("Total packets:  %ld\n", stats.packets);
    printf("IP:             %ld\n", stats.ip4);
    printf("IP6:            %ld\n", stats.ip6);
    printf("TCP:            %ld\n", stats.tcp);
    printf("Sessions:       %ld\n", ssn_stats.inserts);
}

restream_ctx_t::restream_ctx_t(void *user, restream_cb_t cb)
{
    user_data = user;
    callback = cb;
}

void restream_packet_process(
    restream_ctx_t *ctx,
    tmod_pkt_t &packet)
{
    ctx->update(packet);
}

void restream_ctx_t::update(const tmod_pkt_t &packet)
{
    if(!packet.iph.rawiph || !packet.tcph.rawtcp)
        return;

    restream_ssn_t *ssn = tracker.find(packet);

    if(!ssn) {
        try {
            ssn = tracker.save(packet);
        }
        catch (...) {
            // XXX Handle more interestingly
            abort();
        }
    }

    stats.packets++;

    ssn_state_t state = ssn->update(packet);

    segment_t *segment;

    while((segment = ssn->next())) {
        callback(user_data, this, segment->buffer, segment->length);

        ssn->pop();
    }

    if(state == SSN_STATE_CLOSED)
        tracker.clear(packet);
}
