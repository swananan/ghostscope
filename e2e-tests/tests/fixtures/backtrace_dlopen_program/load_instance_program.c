#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void stop(int signo)
{
    (void)signo;
    running = 0;
}

static void *load_instance(const char *path, int marker, int (**tick)(int))
{
    void *handle = dlmopen(LM_ID_NEWLM, path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlmopen: %s\n", dlerror());
        exit(2);
    }
    volatile int *value = dlsym(handle, "instance_marker");
    *tick = dlsym(handle, "instance_tick");
    if (!value || !*tick) {
        fprintf(stderr, "missing instance symbols\n");
        exit(2);
    }
    *value = marker;
    return handle;
}

static void mark_ready(int count)
{
    FILE *file = fopen("instance.ready", "w");
    if (!file) {
        perror("instance.ready");
        exit(2);
    }
    fprintf(file, "%d\n", count);
    fclose(file);
}

static void *map_read_only_copy(int (*first)(int), size_t page_size)
{
    int fd = open("./libload_instance.so", O_RDONLY);
    if (fd < 0) {
        perror("open library");
        exit(2);
    }
    uintptr_t page = (uintptr_t)first & ~(uintptr_t)(page_size - 1);
    void *mapping = MAP_FAILED;
    for (uintptr_t gap = 16U << 20; gap <= 256U << 20; gap += 16U << 20) {
        mapping = mmap((void *)(page - gap), page_size, PROT_READ,
                       MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, 0);
        if (mapping != MAP_FAILED) {
            break;
        }
    }
    close(fd);
    if (mapping == MAP_FAILED) {
        perror("mmap read-only library");
        exit(2);
    }
    return mapping;
}

int main(void)
{
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    int (*first)(int) = NULL;
    int (*second)(int) = NULL;
    void *one = load_instance("./libload_instance.so", 11, &first);
    void *two = NULL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *read_only = NULL;
    if (access("instance.readonly", F_OK) == 0) {
        read_only = map_read_only_copy(first, page_size);
    }
    mark_ready(1);
    while (running) {
        if (!two && access("instance.trigger", F_OK) == 0) {
            const char *path = access("instance.copy", F_OK) == 0
                ? "./libload_instance_copy.so" : "./libload_instance.so";
            two = load_instance(path, 22, &second);
            FILE *pc_file = fopen("instance.second_pc", "w");
            if (!pc_file) {
                perror("instance.second_pc");
                return 2;
            }
            fprintf(pc_file, "%llu\n", (unsigned long long)(uintptr_t)second);
            fclose(pc_file);
            mark_ready(2);
        }
        if (!first(11) || (second && !second(22))) {
            fprintf(stderr, "native instance value mismatch\n");
            return 3;
        }
        usleep(5000);
    }
    if (two) {
        dlclose(two);
    }
    dlclose(one);
    if (read_only) {
        munmap(read_only, page_size);
    }
    return 0;
}
