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
    fprintf(stderr, "       %s -d <binary> [output.caps]  # Detect capabilities\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Execution Options:\n");
    fprintf(stderr, "  -c <file>    Capability file (default: <binary>.caps)\n");
    fprintf(stderr, "  -v           Verbose output\n");
    fprintf(stderr, "  -n           No isolation (dry run)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Detection Options:\n");
    fprintf(stderr, "  -d           Detect and generate capability file\n");
    fprintf(stderr, "  -o <file>    Output capability file (with -d)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "General Options:\n");
    fprintf(stderr, "  -h           Show this help\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  # Generate capability file for an application\n");
    fprintf(stderr, "  %s -d ./myapp\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "  # Generate capability file with custom output\n");
    fprintf(stderr, "  %s -d ./myapp -o custom.caps\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "  # Run application with auto-detected capabilities\n");
    fprintf(stderr, "  %s -d ./myapp && doas %s ./myapp\n", prog, prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "  # Run with custom capability file\n");
    fprintf(stderr, "  doas %s -c custom.caps ./myapp arg1 arg2\n", prog);
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *caps_file = NULL;
    const char *target_binary = NULL;
    const char *output_file = NULL;
    int verbose = 0;
    int dry_run = 0;
    int detect_mode = 0;
    int opt;
    
    // Parse options
    while ((opt = getopt(argc, argv, "c:o:dvnh")) != -1) {
        switch (opt) {
            case 'c':
                caps_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'd':
                detect_mode = 1;
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
    
    // Handle detection mode
    if (detect_mode) {
        if (dry_run) {
            fprintf(stderr, "Error: Cannot use -n (dry run) with -d (detect)\n");
            return 1;
        }
        
        printf("Isolate Capability Detection\n");
        printf("============================\n\n");
        
        int ret = detect_capabilities(target_binary, output_file);
        if (ret == 0) {
            printf("\nNext steps:\n");
            printf("1. Review the generated capability file\n");
            printf("2. Edit capabilities as needed\n");
            printf("3. Run: doas %s %s\n", argv[0], target_binary);
        }
        return ret;
    }
    
    // Check for conflicting options
    if (output_file && !detect_mode) {
        fprintf(stderr, "Error: -o option can only be used with -d (detect mode)\n");
        return 1;
    }
    
    // Auto-detect capability file if not specified
    if (!caps_file) {
        static char auto_caps[PATH_MAX];
        snprintf(auto_caps, sizeof(auto_caps), "%s.caps", target_binary);
        caps_file = auto_caps;
    }
    
    if (verbose) {
        printf("Isolate Process Isolation\n");
        printf("=========================\n");
        printf("Target binary: %s\n", target_binary);
        printf("Capability file: %s\n", caps_file);
        printf("Arguments: ");
        for (int i = optind + 1; i < argc; i++) {
            printf("%s ", argv[i]);
        }
        printf("\n\n");
    }
    
    // Load capabilities
    struct capabilities caps;
    int ret = load_capabilities(caps_file, &caps);
    if (ret != 0) {
        if (verbose || ret != ENOENT) {
            fprintf(stderr, "Warning: Could not load capabilities from %s: %s\n", 
                    caps_file, strerror(ret));
            
            // Suggest using detection mode
            if (ret == ENOENT) {
                fprintf(stderr, "Suggestion: Run '%s -d %s' to generate capability file\n", 
                        argv[0], target_binary);
            }
            
            fprintf(stderr, "Running without isolation.\n\n");
        }
        // Initialize with default (no isolation) capabilities
        init_default_capabilities(&caps);
    }
    
    if (verbose) {
        print_capabilities(&caps);
        printf("\n");
    }
    
    if (dry_run) {
        printf("Dry run - would execute with the above isolation settings.\n");
        printf("Command would be: %s", target_binary);
        for (int i = optind + 1; i < argc; i++) {
            printf(" %s", argv[i]);
        }
        printf("\n");
        return 0;
    }
    
    // Check if we're running as root (required for isolation)
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Isolation requires root privileges\n");
        fprintf(stderr, "Run with: doas %s", argv[0]);
        for (int i = 1; i < argc; i++) {
            fprintf(stderr, " %s", argv[i]);
        }
        fprintf(stderr, "\n");
        return 1;
    }
    
    // Set environment variable so freebsd.c can access the binary path
    setenv("ISOLATE_TARGET_BINARY", target_binary, 1);
    
    if (verbose) {
        printf("Creating isolation context...\n");
    }
    
    // Create isolation context
    if ((ret = create_isolation_context(&caps)) != 0) {
        fprintf(stderr, "Failed to create isolation context: %s\n", strerror(ret));
        return 1;
    }
    
    if (verbose) {
        printf("Isolation context created successfully.\n");
        printf("Executing target binary...\n\n");
    }
    
    // Extract just the binary name for execution inside jail
    const char *binary_name = strrchr(target_binary, '/');
    if (binary_name) {
        binary_name++; // Skip the '/'
    } else {
        binary_name = target_binary;
    }
    
    // Execute target binary with remaining args (using just the filename now)
    argv[optind] = (char*)binary_name;  // Replace full path with just filename
    execv(binary_name, &argv[optind]);
    
    // If we get here, execv failed
    fprintf(stderr, "Failed to execute %s: %s\n", target_binary, strerror(errno));
    return 1;
}
