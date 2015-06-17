#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "decoder.h"
#include "ssn_tracking.h"

class restream_ctx_t
{
public:
    void update(const restream_pkt_t &packet);
    restream_tracker_t tracker;
};

restream_ctx_t *restream_new(restream_cb_t cb);
void restresam_free(restream_ctx_t *ctx);
void restream_packet_process(restream_ctx_t *ctx, restream_pkt_t &pkt);
void restream_print_stats();
