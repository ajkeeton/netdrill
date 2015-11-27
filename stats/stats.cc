#include "stats.h"

tmod_stats_t::tmod_stats_t() {}

tmod_stats_t::~tmod_stats_t()
{
    dump();
}

void tmod_stats_t::dump()
{

}

void tmod_stats_t::update(const tmod_pkt_t &tmp)
{
    // XXX figure out what to do about this in the future;
    tmod_pkt_t *pkt = (tmod_pkt_t*)&tmp;

    if(decode_http(*pkt)) {
        http++;
        return;
    }

    if(decode_tls(*pkt)) {
        tls++;
        return;
    }
    
    if(decode_ssh(*pkt)) {
        ssh++;
        return;
    }

    other++;
}

