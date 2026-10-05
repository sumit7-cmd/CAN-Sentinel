/*
 * CAN-Sentinel V2 — Linux SocketCAN raw-frame sniffer
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o build/can_sniffer src/can_sniffer.c
 *
 * Run:
 *   sudo ./build/can_sniffer vcan0
 *   sudo ./build/can_sniffer vcan0 data/can_capture.csv
 *
 * Intended for virtual CAN interfaces only.
 */

#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void stop_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <vcan-interface> [csv-output]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    if (strncmp(ifname, "vcan", 4) != 0) {
        fprintf(stderr, "Safety stop: this sniffer is limited to vcan* interfaces.\n");
        return EXIT_FAILURE;
    }

    FILE *csv = NULL;
    if (argc == 3) {
        csv = fopen(argv[2], "w");
        if (!csv) {
            perror("fopen");
            return EXIT_FAILURE;
        }
        fprintf(csv, "timestamp,id,dlc,b0,b1,b2,b3,b4,b5,b6,b7\n");
    }

    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    int sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock < 0) {
        perror("socket(PF_CAN)");
        if (csv) fclose(csv);
        return EXIT_FAILURE;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sock);
        if (csv) fclose(csv);
        return EXIT_FAILURE;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        if (csv) fclose(csv);
        return EXIT_FAILURE;
    }

    printf("CAN-Sentinel V2 raw sniffer listening on %s. Ctrl+C to stop.\n", ifname);

    while (running) {
        struct can_frame frame;
        ssize_t n = read(sock, &frame, sizeof(frame));

        if (n < 0) {
            if (errno == EINTR) continue;
            perror("read");
            break;
        }

        if ((size_t)n != sizeof(frame)) {
            fprintf(stderr, "Unexpected frame size: %zd\n", n);
            continue;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        unsigned int can_id = frame.can_id & CAN_EFF_MASK;

        printf("%ld.%09ld  ID=0x%03X  DLC=%u  DATA=",
               ts.tv_sec, ts.tv_nsec, can_id, frame.can_dlc);

        for (int i = 0; i < frame.can_dlc; i++) {
            printf("%02X%s", frame.data[i], i + 1 == frame.can_dlc ? "" : " ");
        }
        printf("\n");
        fflush(stdout);

        if (csv) {
            fprintf(csv, "%ld.%09ld,%u,%u",
                    ts.tv_sec, ts.tv_nsec, can_id, frame.can_dlc);
            for (int i = 0; i < 8; i++) {
                fprintf(csv, ",%u", i < frame.can_dlc ? frame.data[i] : 0);
            }
            fputc('\n', csv);
            fflush(csv);
        }
    }

    close(sock);
    if (csv) fclose(csv);
    puts("Sniffer stopped.");
    return EXIT_SUCCESS;
}
