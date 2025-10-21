#ifndef ISOLATE_COMMON_H
#define ISOLATE_COMMON_H

#include <sys/types.h>
#include <limits.h>

#define MAX_NETWORK_RULES 16
#define MAX_FILE_RULES 32
#define MAX_ENV_VARS 32
#define MAX_CAPABILITY_HINTS 64

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
    uid_t target_uid;       /* UID to run as (0 = not set) */
    gid_t target_gid;       /* GID to run as (0 = not set) */

    /* Workspace */
    char workspace_path[PATH_MAX];  /* Host path to mount as /workspace */
    
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

/* Capability detection structures */
struct capability_hint {
    char description[256];
    char capability[512];
    int confidence;  /* 0-100 */
};

struct detection_result {
    struct capability_hint hints[MAX_CAPABILITY_HINTS];
    int hint_count;
};

/* Function prototypes */

/* Capability file parsing */
int load_capabilities(const char *filename, struct capabilities *caps);
void init_default_capabilities(struct capabilities *caps);
void print_capabilities(const struct capabilities *caps);

/* Capability detection */
int detect_capabilities(const char *binary, const char *output_file);
int analyze_binary_dependencies(const char *binary, struct detection_result *result);
int analyze_binary_symbols(const char *binary, struct detection_result *result);
int analyze_binary_strings(const char *binary, struct detection_result *result);
int analyze_application_patterns(const char *binary, struct detection_result *result);
int generate_capability_file(const char *binary, const char *output_file, struct detection_result *result);

/* Platform abstraction */
int create_isolation_context(const struct capabilities *caps);
void cleanup_isolation_context(void);

/* Platform-specific implementations */
#ifdef __FreeBSD__
int freebsd_create_isolation(const struct capabilities *caps);
void freebsd_cleanup_isolation(void);
void freebsd_set_jail_id(int jid);
void freebsd_set_username(const char *username);
void freebsd_set_jail_path(const char *path);
int freebsd_get_jail_id(void);
const char* freebsd_get_username(void);
const char* freebsd_get_jail_path(void);
#endif

#ifdef __linux__
int linux_create_isolation(const struct capabilities *caps);
void linux_cleanup_isolation(void);
#endif

/* Utility functions */
int parse_memory_size(const char *size_str, size_t *bytes);
int parse_network_rule(const char *rule_str, struct network_rule *rule);
int parse_file_rule(const char *rule_str, struct file_rule *rule);

#endif /* ISOLATE_COMMON_H */
