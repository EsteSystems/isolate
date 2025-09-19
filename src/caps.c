/*
 * Capability file parsing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include "common.h"

void init_default_capabilities(struct capabilities *caps) {
    memset(caps, 0, sizeof(*caps));
    strcpy(caps->username, "auto");
    caps->create_user = 1;
    caps->network_default_deny = 0;  /* Allow all by default */
    caps->fs_default_deny = 0;       /* Allow all by default */
    caps->env_clear = 0;             /* Inherit environment */
}

static char *trim_whitespace(char *str) {
    char *end;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

static int parse_key_value(char *line, char **key, char **value) {
    char *colon = strchr(line, ':');
    if (!colon) return -1;
    
    *colon = '\0';
    *key = trim_whitespace(line);
    *value = trim_whitespace(colon + 1);
    
    return 0;
}

int parse_memory_size(const char *size_str, size_t *bytes) {
    char *endptr;
    double value = strtod(size_str, &endptr);
    
    if (value < 0) return -1;
    
    size_t multiplier = 1;
    if (endptr && *endptr) {
        switch (toupper(*endptr)) {
            case 'K': multiplier = 1024; break;
            case 'M': multiplier = 1024 * 1024; break;
            case 'G': multiplier = 1024 * 1024 * 1024; break;
            case 'B': multiplier = 1; break;
            default: return -1;
        }
    }
    
    *bytes = (size_t)(value * multiplier);
    return 0;
}

int parse_network_rule(const char *rule_str, struct network_rule *rule) {
    /* Examples:
     * tcp:8080
     * udp:53:outbound
     * tcp:192.168.1.1:80
     * unix:/tmp/socket
     * none
     */
    
    memset(rule, 0, sizeof(*rule));
    
    if (strcmp(rule_str, "none") == 0) {
        strcpy(rule->protocol, "none");
        return 0;
    }
    
    char *rule_copy = strdup(rule_str);
    char *proto = strtok(rule_copy, ":");
    char *addr_or_port = strtok(NULL, ":");
    char *port_or_dir = strtok(NULL, ":");
    char *direction = strtok(NULL, ":");
    
    if (!proto) {
        free(rule_copy);
        return -1;
    }
    
    strncpy(rule->protocol, proto, sizeof(rule->protocol) - 1);
    
    if (strcmp(proto, "unix") == 0) {
        /* Unix socket path */
        if (addr_or_port) {
            strncpy(rule->address, addr_or_port, sizeof(rule->address) - 1);
        }
        rule->port = -1;
    } else {
        /* TCP/UDP */
        if (addr_or_port) {
            /* Check if it's a port number or address */
            char *endptr;
            long port = strtol(addr_or_port, &endptr, 10);
            if (*endptr == '\0' && port > 0 && port < 65536) {
                /* It's just a port */
                rule->port = port;
                strcpy(rule->address, "0.0.0.0");
            } else {
                /* It's an address */
                strncpy(rule->address, addr_or_port, sizeof(rule->address) - 1);
                if (port_or_dir) {
                    rule->port = atoi(port_or_dir);
                    direction = strtok(NULL, ":");
                } else {
                    rule->port = -1;  /* Any port */
                }
            }
        }
    }
    
    /* Parse direction */
    rule->direction = 0;  /* Both by default */
    if (direction) {
        if (strcmp(direction, "outbound") == 0 || strcmp(direction, "out") == 0) {
            rule->direction = 1;
        } else if (strcmp(direction, "inbound") == 0 || strcmp(direction, "in") == 0) {
            rule->direction = 2;
        }
    }
    
    free(rule_copy);
    return 0;
}

int parse_file_rule(const char *rule_str, struct file_rule *rule) {
    /* Examples:
     * /tmp/myapp:rw
     * /etc/resolv.conf:r
     * /var/log:w
     * /usr/bin/myapp:rx
     */
    
    memset(rule, 0, sizeof(*rule));
    
    char *rule_copy = strdup(rule_str);
    char *path = strtok(rule_copy, ":");
    char *perms = strtok(NULL, ":");
    
    if (!path) {
        free(rule_copy);
        return -1;
    }
    
    strncpy(rule->path, path, sizeof(rule->path) - 1);
    
    /* Parse permissions */
    rule->permissions = 0;
    if (perms) {
        if (strchr(perms, 'r') || strchr(perms, 'R')) rule->permissions |= R_OK;
        if (strchr(perms, 'w') || strchr(perms, 'W')) rule->permissions |= W_OK;
        if (strchr(perms, 'x') || strchr(perms, 'X')) rule->permissions |= X_OK;
    } else {
        /* Default to read-only */
        rule->permissions = R_OK;
    }
    
    free(rule_copy);
    return 0;
}

int load_capabilities(const char *filename, struct capabilities *caps) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return errno;
    }
    
    init_default_capabilities(caps);
    
    char line[1024];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        /* Remove newline */
        line[strcspn(line, "\n")] = 0;
        
        /* Skip empty lines and comments */
        char *trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#') continue;
        
        char *key, *value;
        if (parse_key_value(trimmed, &key, &value) != 0) {
            fprintf(stderr, "Warning: Invalid syntax at line %d: %s\n", line_num, line);
            continue;
        }
        
        /* Parse different capability types */
        if (strcmp(key, "user") == 0) {
            strncpy(caps->username, value, sizeof(caps->username) - 1);
            caps->create_user = (strcmp(value, "auto") == 0);
            
        } else if (strcmp(key, "memory") == 0) {
            if (parse_memory_size(value, &caps->limits.memory_bytes) != 0) {
                fprintf(stderr, "Warning: Invalid memory size at line %d: %s\n", line_num, value);
            }
            
        } else if (strcmp(key, "processes") == 0) {
            caps->limits.max_processes = atoi(value);
            
        } else if (strcmp(key, "files") == 0) {
            caps->limits.max_files = atoi(value);
            
        } else if (strcmp(key, "cpu") == 0) {
            caps->limits.max_cpu_percent = atoi(value);
            
        } else if (strcmp(key, "network") == 0) {
            if (caps->network_count < MAX_NETWORK_RULES) {
                if (parse_network_rule(value, &caps->network[caps->network_count]) == 0) {
                    caps->network_count++;
                } else {
                    fprintf(stderr, "Warning: Invalid network rule at line %d: %s\n", line_num, value);
                }
            }
            
        } else if (strcmp(key, "filesystem") == 0 || strcmp(key, "file") == 0) {
            if (caps->file_count < MAX_FILE_RULES) {
                if (parse_file_rule(value, &caps->files[caps->file_count]) == 0) {
                    caps->file_count++;
                } else {
                    fprintf(stderr, "Warning: Invalid file rule at line %d: %s\n", line_num, value);
                }
            }
            
        } else if (strcmp(key, "env") == 0) {
            if (caps->env_count < MAX_ENV_VARS) {
                char *eq = strchr(value, '=');
                if (eq) {
                    *eq = '\0';
                    strncpy(caps->env_vars[caps->env_count].name, value, 
                            sizeof(caps->env_vars[caps->env_count].name) - 1);
                    strncpy(caps->env_vars[caps->env_count].value, eq + 1, 
                            sizeof(caps->env_vars[caps->env_count].value) - 1);
                    caps->env_count++;
                }
            }
            
        } else if (strcmp(key, "network_default") == 0) {
            caps->network_default_deny = (strcmp(value, "deny") == 0);
            
        } else if (strcmp(key, "filesystem_default") == 0) {
            caps->fs_default_deny = (strcmp(value, "deny") == 0);
            
        } else if (strcmp(key, "env_clear") == 0) {
            caps->env_clear = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            
        } else {
            fprintf(stderr, "Warning: Unknown capability at line %d: %s\n", line_num, key);
        }
    }
    
    fclose(file);
    return 0;
}

void print_capabilities(const struct capabilities *caps) {
    printf("Capabilities:\n");
    printf("  User: %s%s\n", caps->username, caps->create_user ? " (auto-create)" : "");
    
    if (caps->limits.memory_bytes > 0) {
        printf("  Memory: %zu bytes\n", caps->limits.memory_bytes);
    }
    if (caps->limits.max_processes > 0) {
        printf("  Processes: %d\n", caps->limits.max_processes);
    }
    if (caps->limits.max_files > 0) {
        printf("  Files: %d\n", caps->limits.max_files);
    }
    
    printf("  Network rules: %d\n", caps->network_count);
    for (int i = 0; i < caps->network_count; i++) {
        const struct network_rule *rule = &caps->network[i];
        printf("    %s:", rule->protocol);
        if (rule->port > 0) printf("%d", rule->port);
        if (strlen(rule->address) > 0) printf("%s", rule->address);
        printf("\n");
    }
    
    printf("  File rules: %d\n", caps->file_count);
    for (int i = 0; i < caps->file_count; i++) {
        const struct file_rule *rule = &caps->files[i];
        printf("    %s (", rule->path);
        if (rule->permissions & R_OK) printf("r");
        if (rule->permissions & W_OK) printf("w");
        if (rule->permissions & X_OK) printf("x");
        printf(")\n");
    }
}
