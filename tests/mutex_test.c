#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <time.h>

#define NUM_THREADS 100
#define DEVICE_PATH "/dev/dummy"

typedef enum { READER, WRITER } thread_type_t;

typedef struct {
    int id;
    thread_type_t type;
} thread_info_t;

void* writer_thread(void* arg) {
    thread_info_t* info = (thread_info_t*)arg;
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "Thread-%d says hello!\n", info->id);

    int fd = open(DEVICE_PATH, O_WRONLY);
    if (fd < 0) {
        perror("Writer: Failed to open device");
        pthread_exit(NULL);
    }

    ssize_t written = write(fd, buffer, strlen(buffer));
    if (written < 0) {
        perror("Writer: Failed to write");
    } else {
        printf("[Writer-%d] Wrote: \"%s\"\n", info->id, buffer);
    }

    close(fd);
    pthread_exit(NULL);
}

void* reader_thread(void* arg) {
    thread_info_t* info = (thread_info_t*)arg;
    char buffer[128] = {0};

    int fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("Reader: Failed to open device");
        pthread_exit(NULL);
    }

    ssize_t read_bytes = read(fd, buffer, sizeof(buffer) - 1);
    if (read_bytes < 0) {
        perror("Reader: Failed to read");
    } else {
        printf("[Reader-%d] Read: \"%s\"\n", info->id, buffer);
    }

    close(fd);
    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_THREADS];
    thread_info_t thread_data[NUM_THREADS];
    srand(time(NULL));

    printf("Starting test with %d mixed reader/writer threads...\n", NUM_THREADS);

    // Random mix of readers and writers
    for (int i = 0; i < NUM_THREADS; ++i) {
        thread_data[i].id = i + 1;
        thread_data[i].type = (rand() % 2 == 0) ? WRITER : READER;

        // Introduce slight delay to randomize interleaving
        usleep(rand() % 2000);

        if (thread_data[i].type == WRITER) {
            pthread_create(&threads[i], NULL, writer_thread, &thread_data[i]);
        } else {
            pthread_create(&threads[i], NULL, reader_thread, &thread_data[i]);
        }
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(threads[i], NULL);
    }

    printf("Test complete.\n");
    return 0;
}
