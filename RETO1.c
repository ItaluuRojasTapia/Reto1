#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <time.h>

int main() {
    int sock_raw;
    struct sockaddr saddr;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    int data_size;

    printf("Sniffer de red basico iniciado...\n");
    printf("Presiona Ctrl + C para detener.\n\n");

    // Crear socket RAW
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Error al crear el socket");
        return 1;
    }

    while (1) {
        data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);
        if (data_size < 0) {
            perror("Error al recibir paquetes");
            break;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;

        // Solo procesar paquetes IP (0x0800)
        if (ntohs(eth->h_proto) == 0x0800) {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = ip->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = ip->daddr;

            // Obtener la hora actual
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char hora[9];
            strftime(hora, sizeof(hora), "%H:%M:%S", t);

            // Determinar protocolo
            char *protocolo;
            switch (ip->protocol) {
                case IPPROTO_TCP:
                    protocolo = "TCP";
                    break;
                case IPPROTO_UDP:
                    protocolo = "UDP";
                    break;
                case IPPROTO_ICMP:
                    protocolo = "ICMP";
                    break;
                default:
                    protocolo = "OTRO";
            }

            printf("[%s] Origen: %s  -->  Destino: %s  | Protocolo: %s\n",
                   hora,
                   inet_ntoa(source.sin_addr),
                   inet_ntoa(dest.sin_addr),
                   protocolo);
        }
    }

    close(sock_raw);
    free(buffer);
    return 0;
}

