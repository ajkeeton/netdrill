#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "decoder.h"
#include "restream_ssn.h"

// typedef void (*restream_cb_t)(tmod_pkt_t &packet);
typedef void (*restream_cb_t)(uint8_t *data, uint32_t length);

class restream_ctx_t
{
public:
    void update(const tmod_pkt_t &packet);
    restream_tracker_t tracker;
    restream_cb_t callback; // XXX this is inside the ssn tracking code too - remove from there?
};

restream_ctx_t *restream_new(restream_cb_t cb);
void restresam_free(restream_ctx_t *ctx);
void restream_packet_process(restream_ctx_t *ctx, tmod_pkt_t &pkt);
void restream_print_stats();
