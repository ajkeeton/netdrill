#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "decoder.h"
#include "restream_ssn.h"

class restream_ctx_t;

typedef void (*restream_cb_t)(void *user_ctx, tmod_pkt_t *packet);

class restream_ctx_t
{
    restream_cb_t callback; 
    void *user_data;
    restream_ctx_t();
public:
    void update(const tmod_pkt_t &packet);
    restream_ctx_t(void *user, restream_cb_t callback);
    ssn_tracker_t tracker;
};

void restresam_free(restream_ctx_t *ctx);
void restream_packet_process(restream_ctx_t *ctx, tmod_pkt_t &pkt);
void restream_print_stats();
bool restream_is_client_side(restream_ssn_t *stream);
