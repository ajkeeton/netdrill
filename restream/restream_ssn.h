#pragma once

#include <time.h>
#include <map>
#include <list>
#include "decoder.h"

using namespace std;

const time_t TIMEOUT_DEFAULT = 30;

static inline int CMP8(const uint64_t x, const uint64_t y)
{
    if(x < y) return -1;
    if(x > y) return 1;
    return 0;
}

static inline int CMP16(const uint64_t x[2], const uint64_t y[2])
{
    if(x[0] != y[0]) return CMP8(x[0], y[0]);
    return CMP8(x[1], y[1]);
}

static inline int CMP16(const uint32_t x[4], const uint32_t y[4])
{
    return CMP16((uint64_t*)x, (uint64_t*)y);
}

/* Should be optimal over a true memcpy */
static inline void memcpy4(uint32_t *dst, const uint32_t *src)
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

/* Should be optimal over a true memcmp */
static inline bool mem4eq(uint32_t *a, const uint32_t *b)
{
    return 
        a[0] == b[0] &&
        a[1] == b[1] &&
        a[2] == b[2] &&
        a[3] == b[3];
}

struct ssn_stats_t 
{
    uint64_t 
        inserts,
        clears,
        misses,
        drops;
};

extern ssn_stats_t ssn_stats;

class ssn_tbl_key_t {
public:
    uint32_t client_ip[4],
             server_ip[4];
    uint16_t client_port,
             server_port,
             vlan_tag;
    uint8_t family;

    ssn_tbl_key_t() 
    { 
        client_ip[0] = client_ip[1] = client_ip[2] = client_ip[3] =
        server_ip[0] = server_ip[1] = server_ip[2] = server_ip[3] = 0;
        client_port = server_port = vlan_tag = 0;
        family = AF_INET;
    }

    ssn_tbl_key_t(const ssn_tbl_key_t &t)
    {
        memcpy4(client_ip, t.client_ip);
        memcpy4(server_ip, t.server_ip);
        client_port = t.client_port;
        server_port = t.server_port;
        vlan_tag = t.vlan_tag;
        family = t.family;
    }

    void init(in_addr ip_src, in_addr ip_dst, 
              uint16_t src_port, uint16_t dst_port, uint16_t vlan) 
    {
        family = AF_INET;
        vlan_tag = vlan;

        if(ntohs(src_port) > ntohs(dst_port)) {
            client_ip[0] = ip_src.s_addr;
            server_ip[0] = ip_dst.s_addr;
            client_port = src_port;
            server_port = dst_port;
        }
        else {
            client_ip[0] = ip_dst.s_addr;
            server_ip[0] = ip_src.s_addr;
            client_port = dst_port;
            server_port = src_port;
        }

        client_ip[1] = client_ip[2] = client_ip[3] =
        server_ip[1] = server_ip[2] = server_ip[3] = 0;
    }

    void init(in6_addr ip_src, in6_addr ip_dst, 
              uint16_t src_port, uint16_t dst_port, uint16_t vlan) 
    {
        family = AF_INET6;
        vlan_tag = vlan;

        if(ntohs(src_port) > ntohs(dst_port)) {
            memcpy4(client_ip, ip_src.s6_addr32);
            memcpy4(server_ip, ip_dst.s6_addr32);
            client_port = src_port;
            server_port = dst_port;
        }
        else {
            memcpy4(client_ip, ip_dst.s6_addr32);
            memcpy4(server_ip, ip_src.s6_addr32);
            server_port = src_port;
            client_port = dst_port;
        }
    }

    ssn_tbl_key_t(const tmod_pkt_t &pkt)
    {
        if(pkt.iph.rawiph) {
            init(pkt.iph.rawiph->src,
                 pkt.iph.rawiph->dst,
                 pkt.tcph.rawtcp->src_port,
                 pkt.tcph.rawtcp->dst_port,
                 pkt.vlan.raw ? *(uint16_t*)pkt.vlan.raw & 0x0FFF : 0);
        }
        else if(pkt.ip6h.rawiph) {
            init(pkt.ip6h.rawiph->src,
                 pkt.ip6h.rawiph->dst,
                 pkt.tcph.rawtcp->src_port,
                 pkt.tcph.rawtcp->dst_port,
                 pkt.vlan.raw ? *(uint16_t*)pkt.vlan.raw & 0x0FFF : 0);
        }
    }

    bool operator<(const ssn_tbl_key_t &k) const 
    {
        /* Order of comparisons chosen intentionally */
        if(client_port != k.client_port)
            return client_port < k.client_port;

        int c = CMP16(client_ip, k.client_ip);

        if(c)
            return c < 0;

        c = CMP16(server_ip, k.server_ip);

        if(c)
            return c < 0;

        if(server_port != k.server_port)
            return server_port < k.server_port;

        if(vlan_tag != k.vlan_tag)
            return vlan_tag < k.vlan_tag;

        return 0;
    }

    bool operator==(const ssn_tbl_key_t &rh) const
    {
        if(this == &rh) return true;
        return 
                // Order is intentional
                client_port == rh.client_port && 

                client_ip[3] == rh.client_ip[3] &&
                client_ip[2] == rh.client_ip[2] && 
                client_ip[1] == rh.client_ip[1] && 
                client_ip[0] == rh.client_ip[0] && 

                server_ip[3] == rh.server_ip[3] &&
                server_ip[2] == rh.server_ip[2] &&
                server_ip[1] == rh.server_ip[1] &&
                server_ip[0] == rh.server_ip[0] &&
                server_port == rh.server_port &&

                vlan_tag == rh.vlan_tag &&
                family == rh.family;
    }

    bool operator!=(const ssn_tbl_key_t &rh) const
    {
        return !(*this == rh);
    }

    ssn_tbl_key_t &operator=(const ssn_tbl_key_t &rh)
    {
        memcpy4(client_ip, rh.client_ip);
        memcpy4(server_ip, rh.server_ip);

        client_port = rh.client_port;
        server_port = rh.server_port;
        vlan_tag = rh.vlan_tag;
        family = rh.family;

        return *this;
    }
};

class ssn_node_t {
public:
    ssn_node_t() : 
        data(NULL), len(0), ssn_node_cleanup(NULL) {
        timestamp = last_access = time(NULL);
    }

    ssn_node_t(void *d, time_t t) : 
        data(d), len(0), timestamp(t), 
        last_access(t), ssn_node_cleanup(NULL) {}

    ~ssn_node_t() { 
        if(data && ssn_node_cleanup) {
            ssn_node_cleanup(data); 
            ssn_stats.clears++;
        }
    }

    ssn_node_t &operator=(const ssn_node_t &s) {
        timestamp = s.timestamp;
        last_access = s.last_access;
        data = s.data;
        len = s.len;
        ssn_node_cleanup = s.ssn_node_cleanup;
        const_cast<ssn_node_t &>(s).data = NULL;
        const_cast<ssn_node_t &>(s).len = 0;
        return *this;
    }

    ssn_node_t(const ssn_node_t &s) {
        *this = s;
    }

    void *data;
    uint32_t len;
    time_t timestamp;
    time_t last_access;
    void (*ssn_node_cleanup)(void *);
};

typedef std::map<ssn_tbl_key_t, ssn_node_t> ssn_tbl_t; 
typedef std::map<time_t, ssn_tbl_key_t> ssn_tbl_timeout_t; 

#define SSN_UNKNOWN         0
#define SSN_HANDSHAKE       1
#define SSN_ESTABLISHED     1<<1
#define SSN_CLOSING         1<<2
#define SSN_SEEN_SYN        1<<3
#define PKT_FROM_CLIENT     1
#define PKT_FROM_SERVER     1<<1

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
    SSN_STATE_OK,
    SSN_STATE_ERR,
    SSN_STATE_IGNORE,
    SSN_STATE_OUT_OF_ORDER,
    SSN_STATE_CLOSING,
    SSN_STATE_CLOSED,
    SSN_STATE_CAN_FLUSH
};

class segment_t
{
public:
    uint8_t buffer[JUMBO_MTU];
    uint32_t length;
    uint32_t sequence;

    segment_t(const tmod_pkt_t &pkt) {
        if(pkt.raw_size > JUMBO_MTU) abort();

        // XXX Track the original packet?
        // I'm inclined to buffer the entire packet instead.

        memcpy(buffer, pkt.payload, pkt.payload_size);
        length = pkt.payload_size;
        sequence = ntohl(pkt.tcph.rawtcp->seq);
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
#if 0
    ssn_state_t queue(const tmod_pkt_t &pkt);
    void flush();
    void flush_packet(const segment_t &seg);
#endif
};

class restream_ssn_t 
{
    uint64_t session_flags;
    uint64_t packet_flags;
    timeval time_start,
            time_last_pkt;
    
    tcp_endpoint_t client,
                   server;

    ssn_state_t close_session(const tmod_pkt_t &packet,
                             tcp_endpoint_t &endpoint);
    ssn_state_t add_session(const tmod_pkt_t &packet);
    ssn_state_t update_session(const tmod_pkt_t &packet, 
                               tcp_endpoint_t &endpoint);
    ssn_state_t update_session(const tmod_pkt_t &packet);

    bool is_client_side();
    ssn_state_t queue(const tmod_pkt_t &pkt, tcp_endpoint_t &ep);
    void flush(tcp_endpoint_t &ep);

    restream_ssn_t &operator=(const restream_ssn_t *ssn);
public:

    restream_ssn_t() {
        packet_flags = session_flags = 0;
        gettimeofday(&time_start, NULL);
    }
    ~restream_ssn_t() {
        flush();
    }
    ssn_state_t update(const tmod_pkt_t &packet);
    void flush();
    segment_t *next_server();
    segment_t *next_client();
    segment_t *next();
    void pop_server();
    void pop_client();
    void pop();
};

class restream_tracker_t
{
    ssn_tbl_timeout_t timeouts;
    ssn_tbl_t table;
    time_t timeout;

public:
    restream_tracker_t() { timeout = TIMEOUT_DEFAULT; }
    restream_ssn_t *find(const tmod_pkt_t &packet);
    restream_ssn_t *save(const tmod_pkt_t &packet);
    void clear(const tmod_pkt_t &packet);
    void update_timeouts();
};
