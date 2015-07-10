#include "restream.h"
#include "logger.h"

#define MAX_QUEUED_SEGMENTS 16

extern tmod_proto_stats_t stats;
extern ssn_stats_t ssn_stats;

inline bool restream_ssn_t::is_client_side()
{
    return packet_flags & PKT_FROM_CLIENT;
}

restream_ssn_t *restream_tracker_t::find(const tmod_pkt_t &packet)
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

restream_ssn_t *restream_tracker_t::save(const tmod_pkt_t &packet)
{
    ssn_stats.inserts++;
    ssn_tbl_key_t key(packet);

    restream_ssn_t *ssn = new restream_ssn_t();

    time_t timeout = time(NULL);
    timeouts.insert(std::pair<time_t, ssn_tbl_key_t>(timeout, key));
    table.insert(
        std::pair<ssn_tbl_key_t, ssn_node_t>(key, ssn_node_t(ssn, timeout)));

    return ssn;
}

void restream_tracker_t::clear(const tmod_pkt_t &packet)
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

tcp_endpoint_t::tcp_endpoint_t() 
{
    next_seq = 0;
    port = 0;
    ip[0] = ip[1] = ip[2] = ip[3] = 0;
    state = ENDPOINT_NONE;
}

void restream_ssn_t::flush()
{
// TODO
    //client.flush();
    //server.flush();
}

ssn_state_t restream_ssn_t::close_session(const tmod_pkt_t &packet,
                                          tcp_endpoint_t &endpoint)
{
    int flags = packet.tcph.rawtcp->flags;
    tcp_endpoint_t *sender, *receiver, *peer;

    if(packet_flags == PKT_FROM_SERVER) {
        receiver = &client;
        sender = &server;
    }
    else {
        receiver = &server;
        sender = &client;
    }

    if(session_state == SSN_STATE_CLIENT_CLOSING) {
        peer = &client;
    }
    else if(session_state == SSN_STATE_SERVER_CLOSING) {
        peer = &server;
    }
    else if(sender == &client) {
        session_state = SSN_STATE_CLIENT_CLOSING;
        peer = &client;
    }   
    else {
        session_state = SSN_STATE_SERVER_CLOSING;
        peer = &server;
    }

    /* XXX revisit */
    if(flags & TCP_FLAG_RST) {
        sender->state = ENDPOINT_CLOSED;
    }

    switch(peer->state) {
        case ENDPOINT_ESTABLISHED:
            sender->state = ENDPOINT_FIN_WAIT1;
            receiver->state = ENDPOINT_CLOSE_WAIT;
            break;
        case ENDPOINT_FIN_WAIT1:
            if(flags & TCP_FLAG_ACK) {
                if(peer == receiver) {
                    peer->state = ENDPOINT_FIN_WAIT2;
                    sender->state = ENDPOINT_CLOSE_WAIT;
                }
                else {
                    peer->state = ENDPOINT_CLOSED;
                }
            }
            else if(flags & TCP_FLAG_FIN && peer == receiver) {
                peer->state = ENDPOINT_CLOSED;
                receiver->state = ENDPOINT_LAST_ACK;
            }
                
            break;
        case ENDPOINT_FIN_WAIT2:
            if(peer == receiver && flags & TCP_FLAG_FIN) {
                peer->state = ENDPOINT_TIME_WAIT;
            }
            else if(peer == sender) {
                if(flags & TCP_FLAG_ACK) {
                    peer->state = ENDPOINT_TIME_WAIT;
                    receiver->state = ENDPOINT_CLOSED;
                    session_state = SSN_STATE_CLOSED;
                    return SSN_STATE_CLOSED;
                }
                else if(flags & TCP_FLAG_FIN) {
                    peer->state = ENDPOINT_CLOSED;
                    receiver->state = ENDPOINT_CLOSED;
                    session_state = SSN_STATE_CLOSED;
                    return SSN_STATE_CLOSED;
                }
            }
            break;
        case ENDPOINT_TIME_WAIT:
            if(peer == sender && flags & TCP_FLAG_ACK) {
                peer->state = ENDPOINT_CLOSED;
                receiver->state = ENDPOINT_CLOSED;
                return SSN_STATE_CLOSED;
            }
            break;
        default:
            break;
    };

    if(sender->state == ENDPOINT_CLOSED && receiver->state == ENDPOINT_CLOSED)
        return SSN_STATE_CLOSED;

    return SSN_STATE_OK;
}

ssn_state_t restream_ssn_t::queue(
    const tmod_pkt_t &packet, tcp_endpoint_t &ep)
{
    ssn_state_t complete = SSN_STATE_OK;
    uint32_t sequence = ntohl(packet.tcph.rawtcp->seq);
    
    // TMOD_DEBUG("Next: %u vs %u\n", ep.next_seq, sequence);

    if(ep.next_seq == sequence)
        complete = SSN_STATE_CAN_FLUSH;

    if(ep.segments.size() >= MAX_QUEUED_SEGMENTS) {
        TMOD_DEBUG("Dropping @ %d\n", __LINE__);
        // XXX Trashing all segments. Revisit what to do when we have a gap.
        ep.segments.clear();
        ssn_stats.drops++;
        return complete;
    }

    if(!ep.segments.size()) {
        TMOD_DEBUG("New segment @ %d. Packet %d\n", __LINE__, stats.packets);
        ep.segments.push_front(packet);
        ep.next_seq = sequence + packet.payload_size;

        return complete;
    }

    list<segment_t>::iterator it = ep.segments.begin();

    /* Queue up new segment. */
    for(; it != ep.segments.end(); it++) {
        if(it->sequence == sequence) {
            TMOD_DEBUG("Queuing @ %d\n", __LINE__);
            // XXX Revisit
            /* Two packets with the same sequence... overwrite first one.
               This definitely opens up an evasion case */
            *it = segment_t(packet);

            /* In case the lengths were different, update next seq: */
            ep.next_seq = sequence + packet.payload_size;
            
            return complete;
        }
        if(it->sequence > sequence) {
            TMOD_DEBUG("Cur seq > new seq @ %d\n", __LINE__);
            break;
        }
    } 
    
    TMOD_DEBUG("Inserting @ %d\n", __LINE__);
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
        // TMOD_DEBUG("Client flushing %u. %u queued.\n", seg->sequence, client.segments.size());
        client.next_seq = seg->sequence + seg->length;
        return seg;
    }

    return NULL;
}

segment_t *restream_ssn_t::next()
{
    if(packet_flags == PKT_FROM_CLIENT)
        return next_client();
    else
        return next_server();
}

void restream_ssn_t::pop_server() 
{
    if(server.segments.size())
        server.segments.pop_front();
}

void restream_ssn_t::pop_client() 
{
    if(client.segments.size())
        client.segments.pop_front();
}

void restream_ssn_t::pop()
{
    if(packet_flags == PKT_FROM_CLIENT)
        pop_client();
    else
        pop_server();
}

ssn_state_t restream_ssn_t::update_session(
    const tmod_pkt_t &packet, tcp_endpoint_t &endpoint)
{
    /* Check if this packet is shutting down a TCP session */
    if(packet.tcph.rawtcp->flags & TCP_FLAG_FIN || 
       packet.tcph.rawtcp->flags & TCP_FLAG_RST || 
       session_state == SSN_STATE_CLIENT_CLOSING ||
       session_state == SSN_STATE_SERVER_CLOSING) {

        ssn_state_t retval = close_session(packet, endpoint);

        if(retval == SSN_STATE_CLOSED)
            ssn_stats.drops += client.segments.size() + server.segments.size();

        return retval;
    }

    return queue(packet, endpoint);
}

ssn_state_t restream_ssn_t::add_session(const tmod_pkt_t &packet)
{
    raw_tcp_hdr_t *tcph = packet.tcph.rawtcp;

    TMOD_DEBUG("Handshake. Packet %d\n", stats.packets);

    /* Check if first packet in 3WHS */
    if(session_state == SSN_STATE_UNKNOWN) {
        time_start.tv_sec = packet.timestamp.tv_sec;
        time_start.tv_usec = packet.timestamp.tv_usec;

        if(!(tcph->flags & TCP_FLAG_SYN && !(tcph->flags & TCP_FLAG_ACK))) {
            /* We've never seen this session but this isn't a SYN. We're 
               somewhere midstream */
            // XXX handle
            puts("midstream?"); return SSN_STATE_IGNORE; //abort();
        }
        
        session_state = SSN_STATE_SEEN_SYN;
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
    else if(session_state == SSN_STATE_SEEN_SYN &&
            tcph->flags & TCP_FLAG_SYN && tcph->flags & TCP_FLAG_ACK) {

        // XXX Need to handle the case that this is a retransmitted SYN from the client
        //if(client.ip == pkt.ip && client.port == pkt.port)
        //    bail

        packet_flags = PKT_FROM_SERVER;

        server.state = ENDPOINT_ESTABLISHED;
        client.state = ENDPOINT_ESTABLISHED;

        server.next_seq = ntohl(tcph->seq) + 1;
    }
    else if(server.state == ENDPOINT_ESTABLISHED &&
            tcph->src_port == client.port &&
            tcph->flags & TCP_FLAG_ACK) {
        session_state = SSN_STATE_ESTABLISHED;
        queue(packet, client);
    }
    else {
        printf("Could not follow handshake. Missing packets? Packet %d\n", 
            stats.packets);

        // XXX Later, need to make this recoverable
        session_state = SSN_STATE_IGNORE;
        ssn_stats.broken_handshakes++;
        return SSN_STATE_IGNORE; 
    }

    // TMOD_DEBUG("SEQs: %u and %u\n", client.next_seq, server.next_seq);

    return SSN_STATE_OK;
}

static bool handle_handshake(ssn_state_t val)
{
    return (val == SSN_STATE_UNKNOWN) ||
           (val == SSN_STATE_SEEN_SYN) ||
           (val == SSN_STATE_HANDSHAKING);
}

ssn_state_t restream_ssn_t::update(const tmod_pkt_t &packet)
{
    if(!packet.tcph.rawtcp) 
        return SSN_STATE_OK; 

    /* XXX This will ignore a lot of traffic. Need to revise later. Maybe store
           a flag for 'broken'  but still process traffic. */
    if(session_state == SSN_STATE_IGNORE)
        return SSN_STATE_IGNORE;

    time_last_pkt = packet.timestamp;

    if((session_state == SSN_STATE_ESTABLISHED) && 
        handle_handshake(session_state)) {
        if(SSN_STATE_OK == add_session(packet)) {
            return SSN_STATE_OK;
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
    else if(packet.ip6h.rawiph) {
        if(mem4eq(packet.ip6h.rawiph->src.s6_addr32, server.ip)) {
            packet_flags = PKT_FROM_SERVER;
            return update_session(packet, server);
        }
        else {
            packet_flags = PKT_FROM_CLIENT;
            return update_session(packet, client);
        }
    }
    else {
        // XXX No IP header. Handling?
    }

    return SSN_STATE_OK;
}

