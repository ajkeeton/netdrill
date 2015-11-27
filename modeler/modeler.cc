#include "decoder.h"
#include "modeler.h"

void tmod_modeler_t::update(const tmod_pkt_t &tmp)
{
    // XXX figure out what to do about this in the future;
    tmod_pkt_t *pkt = (tmod_pkt_t*)&tmp;

    if(decode_http(*pkt)) {
        return;
    }

    #if 0
    if(decode_ssl(*pkt)) {
        return;
    }
    
    if(decode_ssh(*pkt)) {
        return;
    }
    #endif
}

