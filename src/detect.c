/*
 * Capability detection module for isolate
 * Analyzes binaries to suggest capability requirements
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include "common.h"

// Analyze binary dependencies using ldd
int analyze_binary_dependencies(const char *binary, struct detection_result *result) {
    char cmd[512];
    FILE *pipe;
    char line[256];
    
    printf("Analyzing library dependencies...\n");
    
    snprintf(cmd, sizeof(cmd), "ldd %s 2>/dev/null", binary);
    pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "Warning: Could not analyze dependencies\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), pipe) && result->hint_count < MAX_CAPABILITY_HINTS - 4) {
        struct capability_hint *hint = &result->hints[result->hint_count];
        
        if (strstr(line, "libc.so")) {
            strcpy(hint->description, "Standard C library - basic filesystem access");
            strcpy(hint->capability, "filesystem: /lib:r\nfilesystem: /usr/lib:r\nfilesystem: /libexec:r\nfilesystem: /usr/local/lib:r");
            hint->confidence = 95;
            result->hint_count++;
        }
        
        if (strstr(line, "libssl") || strstr(line, "libcrypto")) {
            strcpy(hint->description, "SSL/TLS library - likely needs network access");
            strcpy(hint->capability, "network: tcp:443:outbound\nnetwork: tcp:80:outbound");
            hint->confidence = 80;
            result->hint_count++;
        }
        
        if (strstr(line, "libpq")) {
            strcpy(hint->description, "PostgreSQL library - needs database connection");
            strcpy(hint->capability, "network: tcp:5432:outbound");
            hint->confidence = 85;
            result->hint_count++;
        }
        
        if (strstr(line, "libmysql") || strstr(line, "libmariadb")) {
            strcpy(hint->description, "MySQL library - needs database connection");
            strcpy(hint->capability, "network: tcp:3306:outbound");
            hint->confidence = 85;
            result->hint_count++;
        }
        
        if (strstr(line, "libX11") || strstr(line, "libgtk") || strstr(line, "libQt")) {
            strcpy(hint->description, "GUI library - needs X11 access");
            strcpy(hint->capability, "filesystem: /tmp/.X11-unix:rw\nenv: DISPLAY=/tmp/.X11-unix/X0");
            hint->confidence = 90;
            result->hint_count++;
        }
        
        if (strstr(line, "libcurl")) {
            strcpy(hint->description, "HTTP client library");
            strcpy(hint->capability, "network: tcp:80:outbound\nnetwork: tcp:443:outbound");
            hint->confidence = 85;
            result->hint_count++;
        }
    }
    
    pclose(pipe);
    return 0;
}

// Analyze binary symbols for system calls
int analyze_binary_symbols(const char *binary, struct detection_result *result) {
    char cmd[512];
    FILE *pipe;
    char line[256];
    
    printf("Analyzing dynamic symbols...\n");
    
    snprintf(cmd, sizeof(cmd), "objdump -T %s 2>/dev/null | grep -E '(socket|bind|listen|connect|open|read|write|fork|exec)'", binary);
    pipe = popen(cmd, "r");
    if (!pipe) {
        // Try nm as fallback
        snprintf(cmd, sizeof(cmd), "nm -D %s 2>/dev/null | grep -E '(socket|bind|listen|connect|open|read|write|fork|exec)'", binary);
        pipe = popen(cmd, "r");
        if (!pipe) {
            fprintf(stderr, "Warning: Could not analyze symbols\n");
            return -1;
        }
    }
    
    int has_socket = 0, has_bind = 0, has_file_ops = 0, has_process_ops = 0;
    
    while (fgets(line, sizeof(line), pipe)) {
        if (strstr(line, "socket")) has_socket = 1;
        if (strstr(line, "bind") || strstr(line, "listen")) has_bind = 1;
        if (strstr(line, "open") || strstr(line, "read") || strstr(line, "write")) has_file_ops = 1;
        if (strstr(line, "fork") || strstr(line, "exec")) has_process_ops = 1;
    }
    
    if (has_socket && result->hint_count < MAX_CAPABILITY_HINTS) {
        struct capability_hint *hint = &result->hints[result->hint_count++];
        strcpy(hint->description, "Socket operations detected");
        if (has_bind) {
            strcpy(hint->capability, "network: tcp:8080:inbound  # Server application");
            hint->confidence = 85;
        } else {
            strcpy(hint->capability, "network: tcp:80:outbound  # Client application");
            hint->confidence = 75;
        }
    }
    
    if (has_file_ops && result->hint_count < MAX_CAPABILITY_HINTS) {
        struct capability_hint *hint = &result->hints[result->hint_count++];
        strcpy(hint->description, "File operations detected");
        strcpy(hint->capability, "filesystem: /tmp:rw");
        hint->confidence = 70;
    }
    
    if (has_process_ops && result->hint_count < MAX_CAPABILITY_HINTS) {
        struct capability_hint *hint = &result->hints[result->hint_count++];
        strcpy(hint->description, "Process management detected");
        strcpy(hint->capability, "processes: 10  # Allow child processes");
        hint->confidence = 80;
    }
    
    pclose(pipe);
    return 0;
}

// Analyze embedded strings for paths and URLs
int analyze_binary_strings(const char *binary, struct detection_result *result) {
    char cmd[512];
    FILE *pipe;
    char line[256];
    
    printf("Analyzing embedded strings...\n");
    
    snprintf(cmd, sizeof(cmd), "strings %s | grep -E '^(/|http|ftp|.*\\.conf|.*\\.cfg)' | head -20", binary);
    pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "Warning: Could not analyze strings\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), pipe) && result->hint_count < MAX_CAPABILITY_HINTS - 2) {
        line[strcspn(line, "\n")] = 0; // Remove newline
        
        // Skip very long lines (likely not paths)
        if (strlen(line) > 200) continue;
        
        struct capability_hint *hint = &result->hints[result->hint_count];
        
        if (strncmp(line, "/etc/", 5) == 0) {
            snprintf(hint->description, sizeof(hint->description), 
                    "Configuration file: %s", line);
            snprintf(hint->capability, sizeof(hint->capability), 
                    "filesystem: %s:r", line);
            hint->confidence = 60;
            result->hint_count++;
        }
        else if (strncmp(line, "/var/", 5) == 0) {
            snprintf(hint->description, sizeof(hint->description), 
                    "Data directory: %s", line);
            snprintf(hint->capability, sizeof(hint->capability), 
                    "filesystem: %s:rw", line);
            hint->confidence = 65;
            result->hint_count++;
        }
        else if (strstr(line, "http://") || strstr(line, "https://")) {
            snprintf(hint->description, sizeof(hint->description), 
                    "HTTP URL found: %.50s%s", line, strlen(line) > 50 ? "..." : "");
            strcpy(hint->capability, "network: tcp:80:outbound\nnetwork: tcp:443:outbound");
            hint->confidence = 70;
            result->hint_count++;
        }
    }
    
    pclose(pipe);
    return 0;
}

// Check for common application patterns
int analyze_application_patterns(const char *binary, struct detection_result *result) {
    const char *basename = strrchr(binary, '/');
    if (basename) basename++; else basename = binary;
    
    printf("Analyzing application patterns...\n");
    
    struct {
        char *pattern;
        char *description;
        char *capabilities;
        int confidence;
    } patterns[] = {
        {"httpd", "Web server detected", "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 256M", 90},
        {"nginx", "Nginx web server", "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 128M", 90},
        {"apache", "Apache web server", "network: tcp:80:inbound\nnetwork: tcp:443:inbound\nfilesystem: /var/www:r\nmemory: 256M", 90},
        {"sshd", "SSH server", "network: tcp:22:inbound\nfilesystem: /etc/ssh:r\nprocesses: 20", 95},
        {"mysqld", "MySQL database server", "network: tcp:3306:inbound\nfilesystem: /var/lib/mysql:rw\nmemory: 512M\nprocesses: 50", 90},
        {"postgres", "PostgreSQL database", "network: tcp:5432:inbound\nfilesystem: /var/lib/postgresql:rw\nmemory: 256M\nprocesses: 20", 90},
        {"redis", "Redis server", "network: tcp:6379:inbound\nfilesystem: /var/lib/redis:rw\nmemory: 128M", 90},
        {"server", "Generic server application", "network: tcp:8080:inbound\nmemory: 128M", 60},
        {"client", "Generic client application", "network: tcp:80:outbound\nnetwork: tcp:443:outbound", 60},
        {"daemon", "System daemon", "processes: 5\nfilesystem: /var/run:rw\nfilesystem: /var/log:w", 70},
        {"bot", "Bot application", "network: tcp:443:outbound\nfilesystem: /tmp:rw\nmemory: 64M", 65},
        {NULL, NULL, NULL, 0}
    };
    
    for (int i = 0; patterns[i].pattern && result->hint_count < MAX_CAPABILITY_HINTS; i++) {
        if (strstr(basename, patterns[i].pattern)) {
            struct capability_hint *hint = &result->hints[result->hint_count++];
            strcpy(hint->description, patterns[i].description);
            strcpy(hint->capability, patterns[i].capabilities);
            hint->confidence = patterns[i].confidence;
            break; // Only match first pattern
        }
    }
    
    return 0;
}

// Generate capability file from detection results
int generate_capability_file(const char *binary, const char *output_file, struct detection_result *result) {
    FILE *file = fopen(output_file, "w");
    if (!file) {
        fprintf(stderr, "Cannot create %s: %s\n", output_file, strerror(errno));
        return -1;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(file, "# Auto-generated capability file for %s\n", binary);
    fprintf(file, "# Generated on: %s\n", timestamp);
    fprintf(file, "# Review and modify capabilities as needed\n");
    fprintf(file, "# Remove or comment out unnecessary capabilities\n\n");
    
    fprintf(file, "# User context - creates ephemeral user automatically\n");
    fprintf(file, "user: auto\n\n");
    
    fprintf(file, "# Default resource limits (adjust based on application needs)\n");
    fprintf(file, "memory: 128M    # Adjust based on application requirements\n");
    fprintf(file, "processes: 5    # Adjust if application spawns child processes\n");
    fprintf(file, "files: 256      # File descriptor limit\n\n");
    
    // Sort and deduplicate hints by confidence
    fprintf(file, "# Detected capabilities (sorted by confidence)\n");
    fprintf(file, "# Higher confidence suggestions are listed first\n\n");
    
    // Track added capabilities to avoid duplicates
    char added_caps[MAX_CAPABILITY_HINTS][512];
    int added_count = 0;
    
    for (int conf_threshold = 90; conf_threshold >= 50; conf_threshold -= 10) {
        int section_written = 0;
        
        for (int i = 0; i < result->hint_count; i++) {
            if (result->hints[i].confidence >= conf_threshold && 
                result->hints[i].confidence < conf_threshold + 10) {
                
                // Check for duplicates
                int duplicate = 0;
                for (int j = 0; j < added_count; j++) {
                    if (strcmp(added_caps[j], result->hints[i].capability) == 0) {
                        duplicate = 1;
                        break;
                    }
                }
                
                if (!duplicate) {
                    if (!section_written) {
                        fprintf(file, "# Confidence: %d-%d%%\n", conf_threshold, conf_threshold + 9);
                        section_written = 1;
                    }
                    
                    fprintf(file, "# %s\n", result->hints[i].description);
                    
                    // Split multi-line capabilities
                    char *cap_copy = strdup(result->hints[i].capability);
                    char *line = strtok(cap_copy, "\n");
                    while (line) {
                        fprintf(file, "%s\n", line);
                        line = strtok(NULL, "\n");
                    }
                    free(cap_copy);
                    
                    fprintf(file, "\n");
                    
                    // Remember this capability
                    strcpy(added_caps[added_count], result->hints[i].capability);
                    added_count++;
                }
            }
        }
        
        if (section_written) {
            fprintf(file, "\n");
        }
    }
    
    // Add some commented examples
    fprintf(file, "# Additional capability examples (commented out):\n");
    fprintf(file, "# network: udp:53:outbound     # DNS queries\n");
    fprintf(file, "# filesystem: /home/user:rw    # User home directory\n");
    fprintf(file, "# env: PATH=/usr/bin:/bin      # Custom environment\n");
    fprintf(file, "# cpu: 50                      # CPU limit (percentage)\n");
    
    fclose(file);
    return 0;
}

// Main detection function
int detect_capabilities(const char *binary, const char *output_file) {
    struct detection_result result = {0};
    char default_output[PATH_MAX];
    
    printf("Detecting capabilities for: %s\n", binary);
    
    // Check if binary exists and is executable
    if (access(binary, F_OK) != 0) {
        fprintf(stderr, "Error: Binary %s not found\n", binary);
        return -1;
    }
    
    if (access(binary, X_OK) != 0) {
        fprintf(stderr, "Warning: Binary %s is not executable\n", binary);
    }
    
    // Determine output file
    if (!output_file) {
        snprintf(default_output, sizeof(default_output), "%s.caps", binary);
        output_file = default_output;
    }
    
    printf("Output capability file: %s\n\n", output_file);
    
    // Run all analysis methods
    analyze_binary_dependencies(binary, &result);
    analyze_binary_symbols(binary, &result);
    analyze_binary_strings(binary, &result);
    analyze_application_patterns(binary, &result);
    
    // Display results summary
    printf("\nDetection Summary:\n");
    printf("==================\n");
    printf("Found %d capability hints\n", result.hint_count);
    
    if (result.hint_count == 0) {
        printf("No specific capabilities detected. Using minimal defaults.\n");
        
        // Add a basic hint for minimal capabilities
        struct capability_hint *hint = &result.hints[result.hint_count++];
        strcpy(hint->description, "Minimal capabilities for unknown application");
        strcpy(hint->capability, "filesystem: /tmp:rw");
        hint->confidence = 50;
    }
    
    // Generate capability file
    if (generate_capability_file(binary, output_file, &result) == 0) {
        printf("\nGenerated capability file: %s\n", output_file);
        printf("Review and edit the file before using with isolate.\n");
        return 0;
    } else {
        return -1;
    }
}
