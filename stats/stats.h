#pragma once

#include "decoder.h"

class tmod_stats_t
{
    void dump();
public:
    tmod_stats_t();
    ~tmod_stats_t();
    void update(const tmod_pkt_t &pkt);

    uint64_t 
        http,
        tls,
        ssh,
        other;
};

