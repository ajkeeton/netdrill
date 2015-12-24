/* 
    Copyright (C) 2010 Adam Keeton <ajkeeton at gmail>
*/

#include <pcap.h>
#include <arpa/inet.h>
#include "restream.h"

tmod_proto_stats_t stats;
restream_ssn_stats_t r_ssn_stats;

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
   
    printf("Sessions:          %ld\n", r_ssn_stats.inserts);
    printf("Drops:             %ld\n", r_ssn_stats.drops);
    printf("Broken handshakes: %ld\n", r_ssn_stats.broken_handshakes);
}

bool restream_is_client_side(restream_ssn_t *stream)
{
    if(stream)
        return stream->is_client_side();

    abort();
    /* XXX Raise exception instead? */
    return false;
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

void restream_ssn_cleanup(void *r)
{
    if(r)
        delete (restream_ssn_t*)r;
}

void restream_ctx_t::update(const tmod_pkt_t &packet)
{
    if(!packet.iph.rawiph || !packet.tcph.rawtcp)
        return;

    restream_ssn_t *ssn = (restream_ssn_t*)tracker.find(packet);

    if(!ssn) {
        try {
            ssn = (restream_ssn_t*)tracker.save(
                packet, new restream_ssn_t(), NULL);
            r_ssn_stats.inserts++;
        }
        catch (...) {
            // XXX Handle more interestingly
            abort();
        }
    }

    ssn_state_t state = ssn->update(packet);

    segment_t *segment;

    while((segment = ssn->next())) {
        segment->packet.stream = ssn;
        callback(user_data, &segment->packet);
        ssn->pop();
    }

    if(state == SSN_STATE_CLOSED) {
        tracker.clear(packet);
    }
}
