/*
 * isolate - Infrastructureless container runner
 * Usage: isolate [options] <binary> [args...]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include "common.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] <binary> [args...]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <file>    Capability file (default: <binary>.caps)\n");
    fprintf(stderr, "  -v           Verbose output\n");
    fprintf(stderr, "  -n           No isolation (dry run)\n");
    fprintf(stderr, "  -h           Show this help\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *caps_file = NULL;
    const char *target_binary = NULL;
    int verbose = 0;
    int dry_run = 0;
    int opt;
    
    // Parse options
    while ((opt = getopt(argc, argv, "c:vnh")) != -1) {
        switch (opt) {
            case 'c':
                caps_file = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'n':
                dry_run = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
        }
    }
    
    // Need at least the target binary
    if (optind >= argc) {
        fprintf(stderr, "Error: No target binary specified\n");
        usage(argv[0]);
    }
    
    target_binary = argv[optind];
    
    // Auto-detect capability file if not specified
    if (!caps_file) {
        static char auto_caps[PATH_MAX];
        snprintf(auto_caps, sizeof(auto_caps), "%s.caps", target_binary);
        caps_file = auto_caps;
    }
    
    if (verbose) {
        printf("Target binary: %s\n", target_binary);
        printf("Capability file: %s\n", caps_file);
        printf("Arguments: ");
        for (int i = optind + 1; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        printf("\n");
    }
    
    // Load capabilities
    struct capabilities caps;
    int ret = load_capabilities(caps_file, &caps);
    if (ret != 0) {
        if (verbose || ret != ENOENT) {
            fprintf(stderr, "Warning: Could not load capabilities from %s: %s\n", 
                    caps_file, strerror(ret));
            fprintf(stderr, "Running without isolation.\n");
        }
        // Initialize with default (no isolation) capabilities
        init_default_capabilities(&caps);
    }
    
    if (verbose) {
        print_capabilities(&caps);
    }
    
    if (dry_run) {
        printf("Dry run - would execute with isolation.\n");
        return 0;
    }
    
    // Create isolation context
    if ((ret = create_isolation_context(&caps)) != 0) {
        fprintf(stderr, "Failed to create isolation context: %s\n", strerror(ret));
        return 1;
    }
    
    // Execute target binary with remaining args
    execv(target_binary, &argv[optind]);
    
    // If we get here, execv failed
    fprintf(stderr, "Failed to execute %s: %s\n", target_binary, strerror(errno));
    return 1;
}
