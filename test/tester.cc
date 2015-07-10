#include "decoder.h"
#include "restream.h"
#include "logger.h"
#include "eventing.h"
#include "stats.h"
#include "modeler.h"

#define TEST(passfail) do { if(!passfail) printf("Failed @ %d\n",__LINE__); } while(0) 

struct tester_ctx_t 
{
    restream_ctx_t *restream;
    tmod_logger_t *logger;
    tmod_event_t *event;
    tmod_modeler_t *modeler;
    tmod_stats_t *stats;
};

void pcap_cb(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt)
{
    tester_ctx_t *ctx = (tester_ctx_t *)user;

    tmod_pkt_t packet;

    if(!decode(packet, pkthdr, pkt)) {
        puts("Err decoding.");
        return;
    }

    restream_packet_process(ctx->restream, packet);
}

int test_pcap(tester_ctx_t &ctx, char *ifaceorfile, bool online, char *bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;

    if(online) {
        if(!(pcap = pcap_open_offline(ifaceorfile, errbuf))) {
            printf("Error opening pcap file @ %d\n", __LINE__);
            exit(-1);
        }
    }
    else {
        if(!(pcap = pcap_open_live(ifaceorfile, 65535, 1, 0, errbuf))) {
            printf("Error opening interface @ %d\n", __LINE__);
            exit(-1);
        }
    }

    bpf_u_int32 netmask = 0;
    struct bpf_program bpf;

    if(strlen(bpfstr)) {
        if(pcap_compile(pcap, &bpf, bpfstr, 1, netmask) < 0) {
            printf("Error compiling BPF: %s\n", bpfstr);
            exit(-1);
        }

        if(pcap_setfilter(pcap, &bpf) < 0) {
            printf("Error setting BPF @ %d\n", __LINE__);
            exit(-1);
        }

        pcap_freecode(&bpf);
    }

    if(pcap_loop(pcap, -1, pcap_cb, (u_char*)&ctx) == -1) {
        printf("Error while looping @ %d\n", __LINE__);
        return -1;
    }

    return 0;
}

#define MAX_DUMP 256

void packet_cb(void *user_ctx, restream_ctx_t *rs, tmod_pkt_t *packet)
{
    tester_ctx_t *ctx = (tester_ctx_t*)user_ctx;

    TMOD_DEBUG("Packet size: %d\n", packet->payload_size);

    //tmod_hex_dump(packet->payload, packet->payload_size);
    //ctx->logger->payload_save_hex(data, length);
    //ctx->logger->save_hex(data, length);
    ctx->event->search(*packet);
    ctx->stats->update(*packet);
    ctx->modeler->update(*packet);

    // Check /tmp/tmod/packstats ... more decoding and useful stats
    // and make packstats standalone-able.
}

void usage_and_exit()
{
    puts("Usage: \n"
        "   -r <pcap>\n"
        "   -i <interface>");
    exit(-1);
}

int main(int argc, char **argv) 
{
    tester_ctx_t ctx;

    ctx.restream = new restream_ctx_t(&ctx, packet_cb);
    ctx.logger = new tmod_logger_t();
    ctx.event = new tmod_event_t((char*)"test/patterns.conf");
    ctx.stats = new tmod_stats_t();
    ctx.modeler = new tmod_modeler_t();

    if(argc < 3) {
        usage_and_exit();
        return -1;
    }

    char bpf[4094];
    bpf[0] = 0;
    uint32_t offset = 0;
    int i;

    for(i=3; i<argc && offset < sizeof(bpf) - 1; i++) 
        snprintf(bpf + strlen(bpf), sizeof(bpf) - strlen(bpf), "%s ", argv[i]);

    if(!strcmp(argv[1], "-r"))
        test_pcap(ctx, argv[2], true, bpf);
    else if(!strcmp(argv[1], "-i"))
        test_pcap(ctx, argv[2], false, bpf);
    else {
        printf("Invalid argument %c\n", argv[2][0]);
        usage_and_exit();
    }

    restream_print_stats();

    return 0;
}
