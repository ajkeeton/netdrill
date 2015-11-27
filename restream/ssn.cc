#include "ssn.h"
#include "logger.h"

extern ssn_stats_t ssn_stats;

void *ssn_tracker_t::find(const tmod_pkt_t &packet)
{
    ssn_tbl_key_t key(packet);

    ssn_tbl_t::iterator it = table.find(key);
    
    if(it == table.end()) {
        ssn_stats.misses++;
        return NULL;
    }

    it->second.last_access = time(NULL);

    return it->second.data;
}

void *ssn_tracker_t::save(const tmod_pkt_t &packet, void *data)
{
    ssn_stats.inserts++;
    ssn_tbl_key_t key(packet);

    time_t timeout = time(NULL);
    timeouts.insert(std::pair<time_t, ssn_tbl_key_t>(timeout, key));
    table.insert(
        std::pair<ssn_tbl_key_t, ssn_node_t>(key, ssn_node_t(data, timeout)));

    return data;
}

void ssn_tracker_t::clear(const tmod_pkt_t &packet)
{
    ssn_tbl_t::iterator it = table.find(ssn_tbl_key_t(packet));

    if(it == table.end())
        return;

    timeouts.erase(it->second.timestamp);
    table.erase(it);
}

void ssn_tracker_t::update_timeouts()
{
    /* Build up a range of list nodes to timeout */
    ssn_tbl_timeout_t::iterator end;

    time_t cur_time = time(NULL);

    /* Find the range of nodes in the list that need to be removed */
    for(end = timeouts.begin(); 
            end != timeouts.end() && (cur_time - end->first) > timeout; 
            end++) {

        ssn_tbl_t::iterator tbl = table.find(end->second);

        /* XXX This is horrible. Refactor the timeout code */
        if(cur_time - tbl->second.last_access > timeout) {
            TMOD_DEBUG("Cleaning node from session table: %u > %u\n",
                cur_time - end->first, timeout);
            table.erase(end->second);
        }
    }

    /* Remove the blacklist node this element points to */
    if(end != timeouts.begin()) {
        timeouts.erase(timeouts.begin(), end);
    }
}

