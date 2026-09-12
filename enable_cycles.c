#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>

#include "inxpect/kperf_/mykperf_ioctl.h"

struct message {
    uint64_t event;
    uint64_t reg;
    int cpu;
};

int main(void)
{
    const uint64_t cycles_event = 0x003c;
    int fd;

    fd = open(DEVICE_FILE, O_RDWR);
    if (fd < 0) {
        perror("open " DEVICE_FILE);
        return 1;
    }

    struct message msg = {
        .event = cycles_event,
        .reg = 0,
        .cpu = 2,
    };

    printf("Enabling cycles event 0x%llx on all CPUs...\n",
           (unsigned long long)cycles_event);

    if (ioctl(fd, ENABLE_EVENT, &msg) < 0) {
        perror("ENABLE_EVENT");
        close(fd);
        return 1;
    }

    printf("\nSUCCESS\n");
    printf("cycles event enabled\n");
    printf("RDPMC counter index = %llu\n",
           (unsigned long long)msg.reg);

    printf("\nKeep this program running while testing BPF_RDPMC.\n");
    printf("Press ENTER to disable the event and exit...\n");

    getchar();

    struct message disable_msg = {
        .event = cycles_event,
        .reg = msg.reg,
        .cpu = 2,
    };

    if (ioctl(fd, DISABLE_EVENT, &disable_msg) < 0) {
        perror("DISABLE_EVENT");
        close(fd);
        return 1;
    }

    printf("Event disabled.\n");

    close(fd);
    return 0;
}
