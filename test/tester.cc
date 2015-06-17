#include "decoder.h"
#include "restream.h"

void hex_dump(const uint8_t *data, int size);

#define TEST(passfail) do { if(!passfail) printf("Failed @ %d\n",__LINE__); } while(0) 

void pcap_cb(u_char *user, 
             const struct pcap_pkthdr *pkthdr, 
             const u_char *pkt)
{
    restream_ctx_t *ctx = (restream_ctx_t *)user;

    restream_pkt_t packet;

    if(!decode(packet, pkthdr, pkt)) {
        puts("Err decoding.");
        return;
    }

    restream_packet_process(ctx, packet);
}

int test_pcap(restream_ctx_t *ctx, char *file, char *bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;

    if(!(pcap = pcap_open_offline(file, errbuf))) {
        printf("Error opening pcap file @ %d\n", __LINE__);
        return -1;
    }

    bpf_u_int32 netmask = 0;
    struct bpf_program bpf;

    if(pcap_compile(pcap, &bpf, bpfstr, 1, netmask) < 0) {
        printf("Error compiling BPF @ %d\n", __LINE__);
        return -1;
    }

    if(pcap_setfilter(pcap, &bpf) < 0) {
        printf("Error setting BPF @ %d\n", __LINE__);
        return -1;
    }

    pcap_freecode(&bpf);

    if(pcap_loop(pcap, -1, pcap_cb, (u_char*)ctx) == -1) {
        printf("Error while looping @ %d\n", __LINE__);
        return -1;
    }

    return 0;
}

#define MAX_DUMP 256

void packet_cb(restream_pkt_t &packet) 
{
    printf("Packet size: %d\n", packet.raw_size);
    hex_dump(packet.raw_pkt, packet.raw_size);
}

int main(int argc, char **argv) 
{
    restream_ctx_t *rctx = restream_new(&packet_cb);

    if(argc == 1) {
        puts("Usage: tester <pcap>");
        return -1;
    }

    char bpf[4094];
    bpf[0] = 0;
    uint32_t offset = 0;
    int i;

    for(i=2; i<argc && offset < sizeof(bpf) - 1; i++) {
        snprintf(bpf, sizeof(bpf) + strlen(bpf), "%s ", argv[i]);
        //offset += strlen(argv[i]);
        //strncat(bpf + offset, argv[i], sizeof(bpf) - offset)
        //offset++;
        //strncat(bpf + offset, " ", sizeof(bpf) - offset)
    }

    test_pcap(rctx, argv[1], bpf);

    restream_print_stats();

    return 0;
}
