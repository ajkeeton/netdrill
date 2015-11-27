#pragma once

#include "decoder.h"
#include "ssn.h"

class tmod_modeler_t
{
    ssn_tracker_t tracker;
public:
    void update(const tmod_pkt_t &pkt);
};

