#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define PAGE_SIZE 4096

void print_page_faults(const char* label) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    printf("%s - Major (hard) page faults: %ld, Minor (soft) page faults: %ld\n", label,
           usage.ru_majflt, usage.ru_minflt);
  }
}

void print_pid() {
  printf("Process PID: %d\n", getpid());
  printf("----------------------------\n");
}

int main(int argc, char* argv[]) {
  const char* filename = "./test_page_fault_file.dat";

  print_pid();

  if (argc > 1 && strcmp(argv[1], "create") == 0) {
    // Step 1: Create the file
    printf("Creating file...\n");
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0600);
    if (fd == -1) {
      perror("open");
      return 1;
    }

    char buffer[PAGE_SIZE];
    memset(buffer, 'A', PAGE_SIZE);
    if (write(fd, buffer, PAGE_SIZE) != PAGE_SIZE) {
      perror("write");
      close(fd);
      return 1;
    }

    fsync(fd);
    close(fd);
    sync();

    printf("File created. Now run:\n");
    printf("  echo 3 | sudo tee /proc/sys/vm/drop_caches\n");
    printf("  ./page_fault access\n");
    return 0;
  } else if (argc > 1 && strcmp(argv[1], "access") == 0) {
    // Step 2: Access the file
    print_page_faults("Initial");

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
      perror("open");
      printf("Run './page_fault create' first\n");
      return 1;
    }

    // Map the file
    char* mapped_mem = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped_mem == MAP_FAILED) {
      perror("mmap");
      close(fd);
      return 1;
    }
    close(fd);

    print_page_faults("Before access");

    // Access the mapped memory - this should cause a hard page fault
    volatile char value = mapped_mem[0];

    print_page_faults("After access");
    printf("\nRead value: %c\n", value);

    munmap(mapped_mem, PAGE_SIZE);
    unlink(filename);
    return 0;
  } else {
    // Single-run version with immediate drop cache attempt
    print_page_faults("Initial");

    // Create file in current directory (likely ext4, not tmpfs)
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_DIRECT | O_SYNC, 0600);
    if (fd == -1) {
      // Fallback without O_DIRECT
      fd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0600);
      if (fd == -1) {
        perror("open");
        return 1;
      }
    }

    // Allocate aligned buffer for O_DIRECT
    void* buffer;
    if (posix_memalign(&buffer, PAGE_SIZE, PAGE_SIZE) != 0) {
      perror("posix_memalign");
      close(fd);
      return 1;
    }
    memset(buffer, 'A', PAGE_SIZE);

    if (write(fd, buffer, PAGE_SIZE) != PAGE_SIZE) {
      perror("write");
      free(buffer);
      close(fd);
      unlink(filename);
      return 1;
    }

    free(buffer);
    fsync(fd);
    close(fd);
    sync();

    // Try to drop caches
    int drop_fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (drop_fd != -1) {
      write(drop_fd, "3", 1);
      close(drop_fd);
      printf("Dropped caches (running as root)\n");
      sync();
      sleep(1); // Give time for cache drop
    } else {
      printf("Cannot drop caches (not root). Hard page fault unlikely.\n");
    }

    // Reopen and map
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
      perror("open");
      unlink(filename);
      return 1;
    }

    char* mapped_mem = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped_mem == MAP_FAILED) {
      perror("mmap");
      close(fd);
      unlink(filename);
      return 1;
    }
    close(fd);

    print_page_faults("Before access");

    // Access the memory
    volatile char value = mapped_mem[0];

    print_page_faults("After access");
    printf("\nRead value: %c\n", value);

    munmap(mapped_mem, PAGE_SIZE);
    unlink(filename);

    printf("\nFor best results ensuring a hard page fault:\n");
    printf("1. Run: ./page_fault create\n");
    printf("2. Run: echo 3 | sudo tee /proc/sys/vm/drop_caches\n");
    printf("3. Run: ./page_fault access\n");
  }

  return 0;
}
