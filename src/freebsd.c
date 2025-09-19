/*
 * FreeBSD-specific isolation implementation
 */

#ifdef __FreeBSD__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/rctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <jail.h>  // For jailparam functions
#include <errno.h>
#include <fcntl.h>
#include "common.h"

static char ephemeral_username[64];
static int created_jail_id = -1;

static int create_ephemeral_user(const char *username) {
    struct passwd *pw;
    char cmd[256];
    int ret;
    
    // Check if user already exists
    pw = getpwnam(username);
    if (pw != NULL) {
        printf("User %s already exists, using existing user\n", username);
        return 0;
    }
    
    printf("Creating ephemeral user: %s\n", username);
    
    // Create user with pw command
    // -n: name, -s: shell (nologin), -d: home dir, -c: comment
    snprintf(cmd, sizeof(cmd), 
             "pw useradd -n %s -s /usr/sbin/nologin -d /tmp -c 'Isolate ephemeral user' >/dev/null 2>&1", 
             username);
    
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to create user %s: %s\n", username, strerror(errno));
        return -1;
    }
    
    // Verify user was created
    pw = getpwnam(username);
    if (pw == NULL) {
        fprintf(stderr, "User creation appeared to succeed but user not found\n");
        return -1;
    }
    
    printf("Created user %s with UID %d\n", username, pw->pw_uid);
    return 0;
}

static int cleanup_ephemeral_user(const char *username) {
    char cmd[256];
    
    printf("Cleaning up ephemeral user: %s\n", username);
    snprintf(cmd, sizeof(cmd), "pw userdel -n %s >/dev/null 2>&1", username);
    system(cmd);  // Best effort cleanup
    
    return 0;
}

static int setup_resource_limits(const char *jail_name, const struct resource_limits *limits) {
    char rule[256];
    char outbuf[256];  // Buffer for rctl output
    int ret;
    
    if (limits->memory_bytes > 0) {
        printf("Setting memory limit: %zu bytes\n", limits->memory_bytes);
        snprintf(rule, sizeof(rule), "jail:%s:memoryuse:deny=%zu", jail_name, limits->memory_bytes);
        
        ret = rctl_add_rule(rule, strlen(rule) + 1, outbuf, sizeof(outbuf));
        if (ret != 0) {
            fprintf(stderr, "Warning: Failed to set memory limit: %s\n", strerror(errno));
            // Continue anyway - some systems may not have rctl enabled
        }
    }
    
    if (limits->max_processes > 0) {
        printf("Setting process limit: %d\n", limits->max_processes);
        snprintf(rule, sizeof(rule), "jail:%s:maxproc:deny=%d", jail_name, limits->max_processes);
        
        ret = rctl_add_rule(rule, strlen(rule) + 1, outbuf, sizeof(outbuf));
        if (ret != 0) {
            fprintf(stderr, "Warning: Failed to set process limit: %s\n", strerror(errno));
        }
    }
    
    if (limits->max_files > 0) {
        printf("Setting file descriptor limit: %d\n", limits->max_files);
        snprintf(rule, sizeof(rule), "jail:%s:openfiles:deny=%d", jail_name, limits->max_files);
        
        ret = rctl_add_rule(rule, strlen(rule) + 1, outbuf, sizeof(outbuf));
        if (ret != 0) {
            fprintf(stderr, "Warning: Failed to set file limit: %s\n", strerror(errno));
        }
    }
    
    return 0;
}

static int create_jail(const char *jail_name, const char *jail_path) {
    struct jail jail_params;
    int jid;
    
    // Initialize jail parameters
    memset(&jail_params, 0, sizeof(jail_params));
    jail_params.version = JAIL_API_VERSION;
    
    // Set up jail parameters - need more parameters for network access
    struct jailparam params[8];
    jailparam_init(&params[0], "name");
    jailparam_import(&params[0], jail_name);
    
    jailparam_init(&params[1], "path");
    jailparam_import(&params[1], jail_path);  // Use isolated filesystem
    
    jailparam_init(&params[2], "persist");  // Keep jail alive
    jailparam_import(&params[2], NULL);
    
    jailparam_init(&params[3], "allow.raw_sockets");
    jailparam_import(&params[3], "false");
    
    // Allow normal socket operations
    jailparam_init(&params[4], "allow.socket_af");
    jailparam_import(&params[4], "true");
    
    // Allow network access
    jailparam_init(&params[5], "ip4");
    jailparam_import(&params[5], "inherit");  // Inherit host IP
    
    jailparam_init(&params[6], "ip6");
    jailparam_import(&params[6], "inherit");  // Inherit host IPv6
    
    // Allow system V IPC
    jailparam_init(&params[7], "allow.sysvipc");
    jailparam_import(&params[7], "false");
    
    printf("Creating jail: %s at %s\n", jail_name, jail_path);
    
    // Create the jail
    jid = jailparam_set(params, 8, JAIL_CREATE);
    
    // Free parameters
    jailparam_free(params, 8);
    
    if (jid < 0) {
        fprintf(stderr, "Failed to create jail: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Created jail %s with JID %d\n", jail_name, jid);
    created_jail_id = jid;
    
    return jid;
}

static int attach_to_jail(int jid) {
    printf("Attaching to jail JID %d\n", jid);
    
    if (jail_attach(jid) != 0) {
        fprintf(stderr, "Failed to attach to jail: %s\n", strerror(errno));
        return -1;
    }
    
    return 0;
}

static int switch_to_user(const char *username) {
    struct passwd *pw;
    
    // Try to find user in the jail's passwd file first
    pw = getpwnam(username);
    if (pw == NULL) {
        fprintf(stderr, "User %s not found in jail passwd database\n", username);
        
        // Fallback: try to look up the user by parsing /etc/passwd manually
        FILE *passwd_file = fopen("/etc/passwd", "r");
        if (passwd_file) {
            char line[1024];
            while (fgets(line, sizeof(line), passwd_file)) {
                if (strstr(line, username)) {
                    printf("Found user %s in passwd file: %s", username, line);
                    // Parse the line manually
                    char *name = strtok(line, ":");
                    strtok(NULL, ":");  // skip password
                    char *uid_str = strtok(NULL, ":");
                    char *gid_str = strtok(NULL, ":");
                    
                    if (name && uid_str && gid_str && strcmp(name, username) == 0) {
                        uid_t uid = atoi(uid_str);
                        gid_t gid = atoi(gid_str);
                        
                        printf("Switching to user %s (UID %d, GID %d) via manual parsing\n", username, uid, gid);
                        
                        if (setgid(gid) != 0) {
                            fprintf(stderr, "Failed to set GID: %s\n", strerror(errno));
                            fclose(passwd_file);
                            return -1;
                        }
                        
                        if (setuid(uid) != 0) {
                            fprintf(stderr, "Failed to set UID: %s\n", strerror(errno));
                            fclose(passwd_file);
                            return -1;
                        }
                        
                        fclose(passwd_file);
                        return 0;
                    }
                    break;
                }
            }
            fclose(passwd_file);
        }
        
        return -1;
    }
    
    printf("Switching to user %s (UID %d)\n", username, pw->pw_uid);
    
    // Set groups
    if (setgid(pw->pw_gid) != 0) {
        fprintf(stderr, "Failed to set GID: %s\n", strerror(errno));
        return -1;
    }
    
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        fprintf(stderr, "Failed to initialize groups: %s\n", strerror(errno));
        return -1;
    }
    
    // Set user
    if (setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "Failed to set UID: %s\n", strerror(errno));
        return -1;
    }
    
    // Set environment
    setenv("USER", pw->pw_name, 1);
    setenv("HOME", pw->pw_dir, 1);
    setenv("SHELL", pw->pw_shell, 1);
    
    return 0;
}

static char jail_root_path[PATH_MAX];

static void cleanup_jail(void) {
    char cmd[512];
    
    if (created_jail_id >= 0) {
        printf("Cleaning up jail JID %d\n", created_jail_id);
        jail_remove(created_jail_id);
        created_jail_id = -1;
    }
    
    // Cleanup jail filesystem
    if (strlen(jail_root_path) > 0) {
        printf("Cleaning up jail filesystem: %s\n", jail_root_path);
        
        // Unmount filesystems
        snprintf(cmd, sizeof(cmd), "umount %s/dev 2>/dev/null", jail_root_path);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "umount %s/bin 2>/dev/null", jail_root_path);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "umount %s/lib 2>/dev/null", jail_root_path);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "umount %s/libexec 2>/dev/null", jail_root_path);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "umount %s/usr/lib 2>/dev/null", jail_root_path);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "umount %s/usr/local/lib 2>/dev/null", jail_root_path);
        system(cmd);
        
        // Remove jail directory
        snprintf(cmd, sizeof(cmd), "rm -rf %s", jail_root_path);
        system(cmd);
        
        jail_root_path[0] = '\0';
    }
    
    if (strlen(ephemeral_username) > 0) {
        cleanup_ephemeral_user(ephemeral_username);
        ephemeral_username[0] = '\0';
    }
}

static int setup_network_isolation(const struct network_rule *rules, int count) {
    // For now, just basic network restrictions via jail
    // TODO: Implement vnet jails for full network isolation
    (void)rules;
    (void)count;
    
    printf("Network isolation: Using basic jail networking\n");
    
    // Basic jail already provides some network isolation
    // Advanced networking would require vnet jails and additional setup
    
    return 0;
}

static int setup_filesystem_isolation(const struct file_rule *rules, int count, const char *jail_path, const char *target_binary) {
    char cmd[512];
    int ret;
    
    printf("Setting up filesystem isolation in %s\n", jail_path);
    
    // Create basic directory structure
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/bin", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/lib", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/usr/lib", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/usr/local/lib", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/dev", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/tmp", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/libexec", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/etc", jail_path);
    system(cmd);
    
    // Copy target binary into jail
    char binary_name[256];
    const char *slash = strrchr(target_binary, '/');
    if (slash) {
        strcpy(binary_name, slash + 1);
    } else {
        strcpy(binary_name, target_binary);
    }
    
    snprintf(cmd, sizeof(cmd), "cp %s %s/%s", target_binary, jail_path, binary_name);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to copy binary to jail\n");
        return -1;
    }
    
    // Make binary executable
    snprintf(cmd, sizeof(cmd), "chmod +x %s/%s", jail_path, binary_name);
    system(cmd);
    
    // Copy essential files for user resolution
    snprintf(cmd, sizeof(cmd), "cp /etc/passwd %s/etc/", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "cp /etc/group %s/etc/", jail_path);
    system(cmd);
    
    // Mount essential system directories (read-only)
    printf("Mounting system directories...\n");
    
    snprintf(cmd, sizeof(cmd), "mount -t nullfs -o ro /lib %s/lib", jail_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to mount /lib\n");
    }
    
    snprintf(cmd, sizeof(cmd), "mount -t nullfs -o ro /usr/lib %s/usr/lib", jail_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to mount /usr/lib\n");
    }
    
    // Mount libexec for the dynamic linker
    snprintf(cmd, sizeof(cmd), "mount -t nullfs -o ro /libexec %s/libexec", jail_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to mount /libexec\n");
    }
    
    // Mount devfs for stdout/stderr/null access
    snprintf(cmd, sizeof(cmd), "mount -t devfs devfs %s/dev", jail_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to mount devfs\n");
    }
    
    // Set permissions on tmp
    snprintf(cmd, sizeof(cmd), "chmod 1777 %s/tmp", jail_path);
    system(cmd);
    
    printf("Jail filesystem setup complete\n");
    return 0;
}

static int create_jail_filesystem(char *jail_path, size_t jail_path_size, const char *jail_name) {
    // Create temporary jail root directory
    snprintf(jail_path, jail_path_size, "/tmp/isolate-%s", jail_name);
    
    printf("Creating jail filesystem: %s\n", jail_path);
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", jail_path);
    system(cmd);  // Clean up any previous jail
    
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", jail_path);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to create jail directory: %s\n", jail_path);
        return -1;
    }
    
    return 0;
}

int freebsd_create_isolation(const struct capabilities *caps) {
    int ret;
    char jail_name[64];
    char username[64];
    const char *target_binary = getenv("ISOLATE_TARGET_BINARY");
    
    if (!target_binary) {
        fprintf(stderr, "Target binary not specified\n");
        return -1;
    }
    
    printf("Creating FreeBSD isolation context...\n");
    
    // Generate unique jail name
    snprintf(jail_name, sizeof(jail_name), "isolate-%d", getpid());
    
    // Determine username and create user FIRST
    if (caps->create_user && strcmp(caps->username, "auto") == 0) {
        snprintf(username, sizeof(username), "app-%d", getpid());
        strncpy(ephemeral_username, username, sizeof(ephemeral_username) - 1);
        
        ret = create_ephemeral_user(username);
        if (ret != 0) {
            return ret;
        }
    } else {
        strncpy(username, caps->username, sizeof(username) - 1);
    }
    
    // Create isolated jail filesystem
    ret = create_jail_filesystem(jail_root_path, sizeof(jail_root_path), jail_name);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Set up filesystem isolation (now that user exists)
    ret = setup_filesystem_isolation(caps->files, caps->file_count, jail_root_path, target_binary);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Create jail with isolated filesystem
    int jid = create_jail(jail_name, jail_root_path);
    if (jid < 0) {
        cleanup_jail();
        return -1;
    }
    
    // Set resource limits
    ret = setup_resource_limits(jail_name, &caps->limits);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Set up network isolation
    ret = setup_network_isolation(caps->network, caps->network_count);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Attach to jail
    ret = attach_to_jail(jid);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Switch to target user
    ret = switch_to_user(username);
    if (ret != 0) {
        cleanup_jail();
        return ret;
    }
    
    // Register cleanup handler for normal exit
    atexit(cleanup_jail);
    
    printf("FreeBSD isolation context created successfully\n");
    printf("Running in jail %s as user %s\n", jail_name, username);
    printf("Jail filesystem: %s\n", jail_root_path);
    
    return 0;
}

#endif /* __FreeBSD__ */
