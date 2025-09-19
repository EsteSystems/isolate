#ifndef ISOLATE_COMMON_H
#define ISOLATE_COMMON_H

#include <sys/types.h>
#include <limits.h>

#define MAX_NETWORK_RULES 16
#define MAX_FILE_RULES 32
#define MAX_ENV_VARS 32

/* Network access rule */
struct network_rule {
    char protocol[8];    /* tcp, udp, unix */
    char address[256];   /* IP or path for unix sockets */
    int port;           /* -1 for any port */
    int direction;      /* 0=both, 1=outbound, 2=inbound */
};

/* File access rule */
struct file_rule {
    char path[PATH_MAX];
    int permissions;    /* R_OK, W_OK, X_OK bitfield */
};

/* Environment variable rule */
struct env_var {
    char name[256];
    char value[1024];
};

/* Resource limits */
struct resource_limits {
    size_t memory_bytes;    /* 0 = no limit */
    int max_processes;      /* 0 = no limit */
    int max_files;          /* 0 = no limit */
    int max_cpu_percent;    /* 0 = no limit */
};

/* Complete capability specification */
struct capabilities {
    /* User context */
    char username[64];      /* "auto" for auto-generation */
    int create_user;        /* 1 if user should be created */
    
    /* Network access */
    int network_count;
    struct network_rule network[MAX_NETWORK_RULES];
    int network_default_deny;  /* 1 = deny by default */
    
    /* File system access */
    int file_count;
    struct file_rule files[MAX_FILE_RULES];
    int fs_default_deny;    /* 1 = deny by default */
    
    /* Environment */
    int env_count;
    struct env_var env_vars[MAX_ENV_VARS];
    int env_clear;          /* 1 = clear all env vars first */
    
    /* Resource limits */
    struct resource_limits limits;
    
    /* Platform-specific data */
    void *platform_data;
};

/* Function prototypes */

/* Capability file parsing */
int load_capabilities(const char *filename, struct capabilities *caps);
void init_default_capabilities(struct capabilities *caps);
void print_capabilities(const struct capabilities *caps);

/* Platform abstraction */
int create_isolation_context(const struct capabilities *caps);

/* Platform-specific implementations */
#ifdef __FreeBSD__
int freebsd_create_isolation(const struct capabilities *caps);
#endif

#ifdef __linux__
int linux_create_isolation(const struct capabilities *caps);
#endif

/* Utility functions */
int parse_memory_size(const char *size_str, size_t *bytes);
int parse_network_rule(const char *rule_str, struct network_rule *rule);
int parse_file_rule(const char *rule_str, struct file_rule *rule);

#endif /* ISOLATE_COMMON_H */
