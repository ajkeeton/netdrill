#pragma once

#include "decoder.h"
#include "ssn.h"

struct restream_ssn_stats_t 
{
    uint64_t 
        inserts,
        clears,
        misses,
        drops,
        broken_handshakes;
};

extern restream_ssn_stats_t r_ssn_stats;

enum endpoint_state_t {
    ENDPOINT_NONE,
    ENDPOINT_LISTEN,
    ENDPOINT_ESTABLISHED,    
    ENDPOINT_SYN_SENT,
    ENDPOINT_SYN_RCVD,
    ENDPOINT_FIN_WAIT1,
    ENDPOINT_CLOSE_WAIT,
    ENDPOINT_CLOSING,
    ENDPOINT_FIN_WAIT2,
    ENDPOINT_LAST_ACK,
    ENDPOINT_TIME_WAIT,
    ENDPOINT_CLOSED
};

enum ssn_state_t {
    SSN_STATE_UNKNOWN,
    SSN_STATE_OK,
    SSN_STATE_ERR,
    SSN_STATE_IGNORE,
//    SSN_STATE_OUT_OF_ORDER,
//    SSN_STATE_CLOSING,
    SSN_STATE_CAN_FLUSH,
    SSN_STATE_SEEN_SYN,
    SSN_STATE_HANDSHAKING,
    SSN_STATE_ESTABLISHED,
    SSN_STATE_CLIENT_CLOSING,
    SSN_STATE_SERVER_CLOSING,
    SSN_STATE_CLOSED,
};

#define PKT_FROM_CLIENT     1
#define PKT_FROM_SERVER     1<<1

class segment_t
{
public:
    tmod_pkt_t packet;
    uint8_t buffer[JUMBO_MTU];
    uint32_t length;
    uint32_t sequence;

    segment_t(const tmod_pkt_t &pkt) {
        if(pkt.raw_size > JUMBO_MTU) abort();

        length = pkt.raw_size;
        sequence = ntohl(pkt.tcph.rawtcp->seq);
        memcpy(buffer, pkt.raw_pkt, pkt.raw_size);
        packet.copy(pkt, buffer);
    }

    segment_t(const segment_t &s)
    {
        length = s.length;
        sequence = s.sequence;
        memcpy(buffer, s.buffer, length);
        packet.copy(s.packet, buffer);
    }

    const segment_t &operator=(const segment_t &s)
    {
        length = s.length;
        sequence = s.sequence;
        memcpy(buffer, s.buffer, length);
        packet.copy(s.packet, buffer);

        return *this;
    }
};

class tcp_endpoint_t 
{
public:
    uint32_t next_seq;
    endpoint_state_t state;
    uint32_t ip[4];
    uint16_t port;
    list<segment_t> segments;

    tcp_endpoint_t();
};

class restream_ssn_t 
{
    ssn_state_t session_state;
    uint64_t packet_flags;
    timeval time_start,
            time_last_pkt;
    
    tcp_endpoint_t client,
                   server;

    ssn_state_t close_session(const tmod_pkt_t &packet,
                             tcp_endpoint_t &endpoint);
    ssn_state_t add_session(const tmod_pkt_t &packet);
    ssn_state_t update_session(const tmod_pkt_t &packet, 
                               tcp_endpoint_t &talker,
                               tcp_endpoint_t &listener);
    ssn_state_t update_session(const tmod_pkt_t &packet);

    ssn_state_t queue(
        const tmod_pkt_t &pkt, tcp_endpoint_t &talker, tcp_endpoint_t &listener);
    void flush(tcp_endpoint_t &ep);

    restream_ssn_t &operator=(const restream_ssn_t *ssn);
public:

    restream_ssn_t() {
        packet_flags = 0;
        session_state = SSN_STATE_UNKNOWN;
        gettimeofday(&time_start, NULL);
    }
    ~restream_ssn_t() {
        flush();
    }
    ssn_state_t update(const tmod_pkt_t &packet);
    void flush() { /* XXX TODO */ }
    segment_t *next_server();
    segment_t *next_client();
    segment_t *next();
    void pop_server();
    void pop_client();
    void pop();
    bool is_client_side();
};

