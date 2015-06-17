
#include "restream.h"

#define MAX_QUEUED_SEGMENTS 128
extern restream_stats_t stats;
extern ssn_stats_t ssn_stats;

inline bool restream_ssn_t::is_client_side()
{
    return packet_flags & PKT_FROM_CLIENT;
}

restream_ssn_t *restream_tracker_t::find(const restream_pkt_t &packet)
{
    ssn_tbl_key_t key(packet);

    ssn_tbl_t::iterator it = table.find(key);
    
    if(it == table.end()) {
        ssn_stats.misses++;
        return NULL;
    }

    it->second.last_access = time(NULL);

    return (restream_ssn_t*)it->second.data;
}

restream_ssn_t *restream_tracker_t::save(const restream_pkt_t &packet)
{
    ssn_stats.inserts++;
    ssn_tbl_key_t key(packet);

    restream_ssn_t *ssn = new restream_ssn_t(callback);

    time_t timeout = time(NULL);
    timeouts.insert(std::pair<time_t, ssn_tbl_key_t>(timeout, key));
    table.insert(
        std::pair<ssn_tbl_key_t, ssn_node_t>(key, ssn_node_t(ssn, timeout)));

    return ssn;
}

void restream_tracker_t::clear(const restream_pkt_t &packet)
{
    ssn_tbl_t::iterator it = table.find(ssn_tbl_key_t(packet));

    if(it == table.end())
        return;

    timeouts.erase(it->second.timestamp);
    table.erase(it);
}

void restream_tracker_t::update_timeouts()
{
    /* Build up a range of list nodes to timeout */
    ssn_tbl_timeout_t::iterator end;

    time_t cur_time = time(NULL);

    /* Find the range of nodes in the list that need to be removed */
    for(end = timeouts.begin(); 
            end != timeouts.end() && (cur_time - end->first) > timeout; 
            end++) {

        ssn_tbl_t::iterator tbl = table.find(end->second);

        /* This is horrible. Refactor the timeout code */
        if(cur_time - tbl->second.last_access > timeout) {
            printf("Cleaning node from session table: %u > %u\n",
                cur_time - end->first, timeout);
            table.erase(end->second);
        }
    }

    /* Remove the blacklist node this element points to */
    if(end != timeouts.begin()) {
        timeouts.erase(timeouts.begin(), end);
    }
}

tcp_endpoint_t::tcp_endpoint_t() 
{
    next_seq = 0;
    port = 0;
    ip[0] = ip[1] = ip[2] = ip[3] = 0;
    state = ENDPOINT_NONE;
}

#if 0
void tcp_endpoint_t::flush_packet(const segment_t &seg)
{
    //callback(seg.buffer, seg.length);
}

void tcp_endpoint_t::flush()
{
    list<segment_t>::iterator it = segments.begin();

    do {
        if(next_seq != it->seq) {
            printf("%u != %u\n", next_seq, it->seq);
            break;
        }

        next_seq = htonl(ntohl(next_seq) + it->length);

        /*
        if(buffer_only) {
            callback(buffer);
        }
        else 
        */
        {
            flush_packet(*it);
        }

        it++;
    } while(1);

    if(it != segments.begin())
        segments.erase(segments.begin(), it);
}
#endif

void restream_ssn_t::flush()
{
// TODO
    //client.flush();
    //server.flush();
}

ssn_state_t restream_ssn_t::close_session(const restream_pkt_t &packet,
                                          tcp_endpoint_t &endpoint)
{
// XXX Untested and incomplete
// What about out of order teardowns?

    int flags = packet.tcph.rawtcp->flags;
    tcp_endpoint_t *sender, *receiver;

    if(packet_flags == PKT_FROM_SERVER) {
        receiver = &client;
        sender = &server;
    }
    else {
        receiver = &server;
        sender = &client;
    }

    if(flags & TCP_FLAG_RST) {
        sender->state = ENDPOINT_CLOSED;
    }

    if(sender->state = ENDPOINT_ESTABLISHED) {
        sender->state = ENDPOINT_FIN_WAIT1;
        receiver->state = ENDPOINT_CLOSE_WAIT;
    }
    else if(sender->state == ENDPOINT_FIN_WAIT1) {
        if(flags & TCP_FLAG_ACK) {
            sender->state = ENDPOINT_FIN_WAIT2;
            receiver->state = ENDPOINT_CLOSE_WAIT;
        }
        if(flags & TCP_FLAG_FIN) {
            sender->state = ENDPOINT_TIME_WAIT;
            receiver->state = ENDPOINT_LAST_ACK;
        }
    }
    else if(sender->state == ENDPOINT_FIN_WAIT2) {
        if(flags & TCP_FLAG_ACK) {
            sender->state = ENDPOINT_CLOSED;
            receiver->state = ENDPOINT_CLOSED;
            return SSN_STATE_CLOSED;
        }
    }
    
    if(sender->state == ENDPOINT_CLOSED && receiver->state == ENDPOINT_CLOSED)
        return SSN_STATE_CLOSED;

    return SSN_STATE_OK;
}

ssn_state_t restream_ssn_t::queue(
    tcp_endpoint_t &ep, const restream_pkt_t &packet)
{
    ssn_state_t complete = SSN_STATE_OK;
    uint32_t sequence = ntohl(packet.tcph.rawtcp->seq);
    
    if(ep.next_seq == sequence)
        complete = SSN_STATE_CAN_FLUSH;

    if(ep.segments.size() >= MAX_QUEUED_SEGMENTS) {
        ep.segments.clear();
        ssn_stats.drops++;
        return SSN_STATE_OK;
    }

    if(!ep.segments.size()) {
        ep.segments.push_front(packet);
        ep.next_seq = sequence + packet.payload_size;
        return SSN_STATE_CAN_FLUSH;
    }

    list<segment_t>::iterator it = ep.segments.begin();

    /* Queue up new segment. */
    for(; it != ep.segments.end(); it++) {
        if(it->sequence == sequence) {
            if(it->length != packet.payload_size) {
                /* Possible evasion! */
                // TODO
                break;
            }
            
            /* Two packets with the same sequence... overwrite first one. */
            *it = segment_t(packet);
            /* In case the lengths were different, update next seq: */
            ep.next_seq = sequence + packet.payload_size;
            break;
        }
        if(it->sequence > sequence)
            break;
    } 
    
    ep.segments.insert(it, packet);

    return complete;
}

segment_t *restream_ssn_t::next_server()
{
    if(!server.segments.size())
        return NULL;

    segment_t *seg = &server.segments.front();

    if(seg && seg->sequence <= server.next_seq) {
        server.next_seq = seg->sequence + seg->length;
        return seg;
    }

    return NULL;
}

segment_t *restream_ssn_t::next_client()
{
    if(!client.segments.size())
        return NULL;

    segment_t *seg = &client.segments.front();

    if(seg && seg->sequence <= client.next_seq) {
        client.next_seq = seg->sequence + seg->length;
        return seg;
    }

    return NULL;
}

segment_t *restream_ssn_t::next(bool is_client)
{
    if(is_client)
        return next_client();

    return next_server();
}

void restream_ssn_t::pop_server() 
{
    server.segments.pop_front();
}

void restream_ssn_t::pop_client() 
{
    client.segments.pop_front();
}

void restream_ssn_t::pop(bool is_client)
{
    if(is_client)
        pop_client();

    pop_server();
}
#if 0
ssn_state_t tcp_endpoint_t::queue(const restream_pkt_t &packet)
{
    // TODO Need to add PAWS check

    if(!packet.payload_size) {
        return SSN_STATE_OK;
    }

    uint32_t sequence = ntohl(packet.tcph.rawtcp->seq);

    /* Packet is out of order! */
   
    // XXX improve - can better determine if we should start at the head or tail of
    // the list. Just walk from the head for now.

    list<segment_t>::iterator segment,
                              prev_segment;
    segment = prev_segment = segments.begin();

    if(segments.size() == 0) {
        segments.insert(segment, segment_t(packet));

        /* Are we in order? */
        if(sequence == next_seq) {
            /* Splendid. */
            next_seq = htonl(ntohl(next_seq) + packet.payload_size);
            flush();
        }

        return SSN_STATE_OK;
    }

    /* Are we in order? */
    if(sequence == next_seq) {
        /* Splendid. */
        next_seq = htonl(ntohl(next_seq) + packet.payload_size);
        segments.insert(segment, segment_t(packet));
        flush();

        return SSN_STATE_OK;
    }
 
    do {
        #if 0
        /* Overlap? */
        if() {
            if(policy == LINUX) {
            }
            else if(policy == WINDOWS) {
            }
        }
        #endif
        if(segment == segments.end()) {
            segments.insert(segment, segment_t(packet));
            break;
        }

        if(sequence < segment->seq) {
            printf("Q'ing %u\n", ntohl(sequence));
            hex_dump(packet.raw_pkt, packet.raw_size);
            segments.insert(segment, segment_t(packet));
            break;
        }
        if(sequence <= prev_segment->seq + prev_segment->length) {
            stats.overlaps++;
            /* TODO Overlap */
            abort();
        }

        if(sequence > segment->seq) {
            prev_segment = segment;
            segment++;
            continue;
        }
        else {
            segments.insert(segment, segment_t(packet));
            break;
        }

        // XXX update window size?
    } while(1);

    if(packet.tcph.rawtcp->flags & TCP_FLAG_ACK) 
        flush();

    return SSN_STATE_OK;
}
#endif

ssn_state_t restream_ssn_t::update_session(
    const restream_pkt_t &packet, tcp_endpoint_t &endpoint)
{
    /* Check if this packet is shutting down a TCP session */
    if(packet.tcph.rawtcp->flags & TCP_FLAG_FIN || 
       packet.tcph.rawtcp->flags & TCP_FLAG_RST || 
       session_flags & SSN_CLOSING) {
        session_flags |= SSN_CLOSING;

        return close_session(packet, endpoint);
    }

    return queue(endpoint, packet);
}

ssn_state_t restream_ssn_t::add_session(const restream_pkt_t &packet)
{
    raw_tcp_hdr_t *tcph = packet.tcph.rawtcp;

    /* Check if first packet in 3WHS */
    if(session_flags == SSN_UNKNOWN) {
        time_start.tv_sec = packet.timestamp.tv_sec;
        time_start.tv_usec = packet.timestamp.tv_usec;

        if(!(tcph->flags & TCP_FLAG_SYN && !(tcph->flags & TCP_FLAG_ACK))) {
            /* We've never seen this session but this isn't a SYN. We're 
               somewhere midstream */
            // XXX handle
            puts("midstream?"); return SSN_STATE_IGNORE; //abort();
        }
        
        session_flags = SSN_SEEN_SYN | SSN_HANDSHAKE;
        packet_flags = PKT_FROM_CLIENT;

        client.port = tcph->src_port;
        server.port = tcph->dst_port;

        if(packet.iph.rawiph) {
            client.ip[0] = packet.iph.rawiph->src.s_addr;
            server.ip[0] = packet.iph.rawiph->dst.s_addr;
        }
        else {
            memcpy4(client.ip, packet.ip6h.rawiph->src.s6_addr32);
            memcpy4(server.ip, packet.ip6h.rawiph->dst.s6_addr32);
        }

        client.next_seq = ntohl(tcph->seq) + 1;
        server.state = ENDPOINT_LISTEN;
    }
    else if(session_flags & SSN_SEEN_SYN &&
            tcph->flags & TCP_FLAG_SYN && tcph->flags & TCP_FLAG_ACK) {

        // XXX Need to handle the case that this is a retransmitted SYN from the client
        //if(client.ip == pkt.ip && client.port == pkt.port)
        //    bail

        session_flags = SSN_ESTABLISHED;
        packet_flags = PKT_FROM_SERVER;

        server.state = ENDPOINT_ESTABLISHED;
        client.state = ENDPOINT_ESTABLISHED;

        server.next_seq = ntohl(tcph->seq) + 1;
    }
    else {
        // Something is broken
        printf("Broken at %d\n", __LINE__);
        return SSN_STATE_IGNORE; //abort();
    }

    printf("SEQs: %u and %u\n", client.next_seq, server.next_seq);

    return SSN_STATE_OK;
}

ssn_state_t restream_ssn_t::update(const restream_pkt_t &packet)
{
    if(!packet.tcph.rawtcp) 
        return SSN_STATE_OK; 

    time_last_pkt = packet.timestamp;

    if(!(session_flags & SSN_ESTABLISHED)) {
        if(SSN_STATE_OK == add_session(packet)) {
            // call callback with it
        }
        else {
            // ...
            return SSN_STATE_IGNORE;
        }
    }
    
    packet_flags = 0;

    if(packet.iph.rawiph) {
        if(packet.iph.rawiph->src.s_addr == server.ip[0]) {
            packet_flags = PKT_FROM_SERVER;
            return update_session(packet, server);
        }
        else {
            packet_flags = PKT_FROM_CLIENT;
            return update_session(packet, client);
        }
    }
    else {
        if(mem4eq(packet.ip6h.rawiph->src.s6_addr32, server.ip)) {
            packet_flags = PKT_FROM_SERVER;
            return update_session(packet, server);
        }
        else {
            packet_flags = PKT_FROM_CLIENT;
            return update_session(packet, client);
        }
    }
}

