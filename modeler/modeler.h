#pragma once

#include "logger.h"
#include "decoder.h"
#include "ssn.h"

class tmod_modeler_t
{
    bool log_only;
    ssn_tracker_t tracker;
    void http_handler(tmod_pkt_t &pkt);
public:
    tmod_modeler_t() {
        log_only = true;
    }

    void update(const tmod_pkt_t &pkt);
};

