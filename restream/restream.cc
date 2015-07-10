/* 
    Copyright (C) 2010 Adam Keeton <ajkeeton at gmail>
*/

#include <pcap.h>
#include <arpa/inet.h>
#include "restream.h"

tmod_proto_stats_t stats;
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

//    printf("HTTP:           %ld\n", stats.http);
//    printf("SSL/TLS:        %ld\n", stats.tls);
//    printf("Other:          %ld\n\n", stats.other);
   
    printf("Sessions:          %ld\n", ssn_stats.inserts);
    printf("Drops:             %ld\n", ssn_stats.drops);
    printf("Broken handshakes: %ld\n", ssn_stats.broken_handshakes);
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

    ssn_state_t state = ssn->update(packet);

    segment_t *segment;

    while((segment = ssn->next())) {
        callback(user_data, this, &segment->packet);

        ssn->pop();
    }

    if(state == SSN_STATE_CLOSED) {
        puts("Closing session"); 
        tracker.clear(packet);
    }
}
