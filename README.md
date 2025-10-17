# Reto1
Reto1 de redes
// sniffer_pcap.c
// Compilar: gcc -o sniffer_pcap sniffer_pcap.c -lpcap
// Ejecutar: sudo ./sniffer_pcap [interface]
// Si no pasas interfaz, usa la primera disponible.

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_timestamp(const struct timeval *tv) {
    char buf[64];
    struct tm *lt = localtime(&tv->tv_sec);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt);
    long ms = tv->tv_usec / 1000;
    printf("%s.%03ld  ", buf, ms);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Asumimos tramas Ethernet => IP empieza en offset 14
    const int ETHERNET_HEADER_LEN = 14;
    if (header->caplen < ETHERNET_HEADER_LEN + sizeof(struct ip)) return;

    const struct ip *ip_hdr = (struct ip *)(packet + ETHERNET_HEADER_LEN);
    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_buf, INET_ADDRSTRLEN);

    print_timestamp(&header->ts);
    uint8_t proto = ip_hdr->ip_p;
    const u_char *transport = packet + ETHERNET_HEADER_LEN + (ip_hdr->ip_hl * 4);
    if (proto == IPPROTO_TCP && header->caplen >= ETHERNET_HEADER_LEN + (ip_hdr->ip_hl*4) + sizeof(struct tcphdr)) {
        const struct tcphdr *tcp = (struct tcphdr *)transport;
        printf("%15s -> %-15s  TCP   sport=%u dport=%u  len=%u\n",
               src_buf, dst_buf, ntohs(tcp->th_sport), ntohs(tcp->th_dport), header->len);
    } else if (proto == IPPROTO_UDP && header->caplen >= ETHERNET_HEADER_LEN + (ip_hdr->ip_hl*4) + sizeof(struct udphdr)) {
        const struct udphdr *udp = (struct udphdr *)transport;
        printf("%15s -> %-15s  UDP   sport=%u dport=%u  len=%u\n",
               src_buf, dst_buf, ntohs(udp->uh_sport), ntohs(udp->uh_dport), header->len);
    } else {
        printf("%15s -> %-15s  OTRO  proto=%u  len=%u\n",
               src_buf, dst_buf, proto, header->len);
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *dev = NULL;

    if (argc >= 2) dev = argv[1];
    else {
        dev = pcap_lookupdev(errbuf);
        if (!dev) {
            fprintf(stderr, "No se encontró interfaz: %s\n", errbuf);
            return 1;
        }
    }

    printf("Usando interfaz: %s\n", dev);

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live falló: %s\n", errbuf);
        return 1;
    }

    // Opcional: sólo IP (descomenta si quieres)
    // struct bpf_program fp;
    // pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    printf("Iniciando captura (Ctrl-C para detener). Mostrando hora, IP origen -> IP destino, protocolo y puertos.\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
