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
#include <sys/stat.h>
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
static char jail_root_path[PATH_MAX];

// Functions to set jail info from parent process
void freebsd_set_jail_id(int jid) {
    created_jail_id = jid;
}

void freebsd_set_username(const char *username) {
    strncpy(ephemeral_username, username, sizeof(ephemeral_username) - 1);
    ephemeral_username[sizeof(ephemeral_username) - 1] = '\0';
}

void freebsd_set_jail_path(const char *path) {
    strncpy(jail_root_path, path, sizeof(jail_root_path) - 1);
    jail_root_path[sizeof(jail_root_path) - 1] = '\0';
}

// Functions to get jail info for IPC
int freebsd_get_jail_id(void) {
    return created_jail_id;
}

const char* freebsd_get_username(void) {
    return ephemeral_username;
}

const char* freebsd_get_jail_path(void) {
    return jail_root_path;
}

static int create_ephemeral_user(const char *username, uid_t *out_uid, gid_t *out_gid) {
    struct passwd *pw;
    char cmd[256];
    int ret;

    // Check if user already exists
    pw = getpwnam(username);
    if (pw != NULL) {
        printf("User %s already exists, using existing user\n", username);
        if (out_uid) *out_uid = pw->pw_uid;
        if (out_gid) *out_gid = pw->pw_gid;
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

    // Verify user was created and get UID/GID
    pw = getpwnam(username);
    if (pw == NULL) {
        fprintf(stderr, "User creation appeared to succeed but user not found\n");
        return -1;
    }

    printf("Created user %s with UID %d, GID %d\n", username, pw->pw_uid, pw->pw_gid);
    if (out_uid) *out_uid = pw->pw_uid;
    if (out_gid) *out_gid = pw->pw_gid;
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

static int switch_to_user(uid_t uid, gid_t gid, const char *username_for_display) {
    printf("Switching to user %s (UID %d, GID %d)\n",
           username_for_display, uid, gid);

    // Set GID first (must be done before dropping privileges)
    if (setgid(gid) != 0) {
        fprintf(stderr, "Failed to set GID %d: %s\n", gid, strerror(errno));
        return -1;
    }

    // Set UID (drops privileges)
    if (setuid(uid) != 0) {
        fprintf(stderr, "Failed to set UID %d: %s\n", uid, strerror(errno));
        return -1;
    }

    // Set minimal environment
    setenv("USER", username_for_display, 1);
    setenv("HOME", "/tmp", 1);
    setenv("LD_LIBRARY_PATH", "/usr/local/lib:/usr/lib:/lib", 1);

    return 0;
}

void freebsd_cleanup_isolation(void) {
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

static int setup_filesystem_isolation(const struct capabilities *caps, const char *jail_path, const char *target_binary, uid_t target_uid, gid_t target_gid, const char *username) {
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
    
    printf("Creating standard application directories...\n");
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/var/log", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/var/tmp", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/var/run", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "chmod 1777 %s/tmp", jail_path);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "chmod 755 %s/var/log %s/var/tmp %s/var/run", 
	     jail_path, jail_path, jail_path);
    system(cmd);

    // Mount workspace directory if specified
    if (strlen(caps->workspace_path) > 0) {
	printf("Setting up workspace: %s -> /workspace\n", caps->workspace_path);
	snprintf(cmd, sizeof(cmd), "mkdir -p %s/workspace", jail_path);
	system(cmd);

	snprintf(cmd, sizeof(cmd), "mount -t nullfs -o rw %s %s/workspace", 
		 caps->workspace_path, jail_path);
	ret = system(cmd);
	if (ret != 0) {
	    fprintf(stderr, "Failed to mount workspace directory %s\n", caps->workspace_path);
	    return -1;
	}
	printf("Workspace mounted successfully\n");
    }
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

    // Create minimal passwd file for jail (only root and the isolated user)
    char passwd_path[PATH_MAX];
    snprintf(passwd_path, sizeof(passwd_path), "%s/etc/passwd", jail_path);

    FILE *passwd_file = fopen(passwd_path, "w");
    if (passwd_file) {
        fprintf(passwd_file,
                "root:*:0:0:System Administrator:/root:/usr/sbin/nologin\n"
                "%s:*:%u:%u:Isolated Application:/tmp:/usr/sbin/nologin\n",
                username, target_uid, target_gid);
        fclose(passwd_file);
        printf("Created minimal passwd file in jail (uid=%u, gid=%u)\n", target_uid, target_gid);
    } else {
        fprintf(stderr, "Warning: Failed to create passwd file in jail\n");
    }

    // Create minimal group file
    char group_path[PATH_MAX];
    snprintf(group_path, sizeof(group_path), "%s/etc/group", jail_path);

    FILE *group_file = fopen(group_path, "w");
    if (group_file) {
        fprintf(group_file,
                "wheel:*:0:root\n"
                "%s:*:%u:\n",
                username, target_gid);
        fclose(group_file);
        printf("Created minimal group file in jail\n");
    } else {
        fprintf(stderr, "Warning: Failed to create group file in jail\n");
    }
    
    // Mount essential system directories (read-only)
    printf("Mounting system directories...\n");
      
    // Mount devfs for stdout/stderr/null access
    snprintf(cmd, sizeof(cmd), "mount -t devfs devfs %s/dev", jail_path);
    ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Warning: Failed to mount devfs\n");
    }

    printf("Processing capability filesystem rules...\n");
    for (int i = 0; i < caps->file_count; i++) {
	const struct file_rule *rule = &caps->files[i];

	// Only mount directories that exist and are readable
	if (rule->permissions & R_OK) {
	    struct stat st;
	    if (stat(rule->path, &st) == 0 && S_ISDIR(st.st_mode)) {
		char mount_point[PATH_MAX];
		snprintf(mount_point, sizeof(mount_point), "%s%s", jail_path, rule->path);

		// Create mount point
		snprintf(cmd, sizeof(cmd), "mkdir -p %s", mount_point);
		system(cmd);

		// Mount the directory
		const char *mount_opts = (rule->permissions & W_OK) ? "rw" : "ro";
		snprintf(cmd, sizeof(cmd), "mount -t nullfs -o %s %s %s", 
			 mount_opts, rule->path, mount_point);

		printf("Mounting %s -> %s (%s)\n", rule->path, mount_point, mount_opts);
		ret = system(cmd);
		if (ret != 0) {
		    fprintf(stderr, "Warning: Failed to mount %s\n", rule->path);
		}
	    }
	}
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
    uid_t target_uid = 0;
    gid_t target_gid = 0;
    const char *target_binary = getenv("ISOLATE_TARGET_BINARY");

    if (!target_binary) {
        fprintf(stderr, "Target binary not specified\n");
        return -1;
    }

    printf("Creating FreeBSD isolation context...\n");

    // Generate unique jail name
    snprintf(jail_name, sizeof(jail_name), "isolate-%d", getpid());

    // Determine username and create user FIRST, capture UID/GID
    if (caps->create_user && strcmp(caps->username, "auto") == 0) {
        snprintf(username, sizeof(username), "app-%d", getpid());
        strncpy(ephemeral_username, username, sizeof(ephemeral_username) - 1);

        ret = create_ephemeral_user(username, &target_uid, &target_gid);
        if (ret != 0) {
            return ret;
        }
    } else {
        strncpy(username, caps->username, sizeof(username) - 1);

        // For non-auto users, look up UID/GID on host before entering jail
        struct passwd *pw = getpwnam(caps->username);
        if (pw == NULL) {
            fprintf(stderr, "User %s not found\n", caps->username);
            return -1;
        }
        target_uid = pw->pw_uid;
        target_gid = pw->pw_gid;
        printf("Using existing user %s (UID %d, GID %d)\n", username, target_uid, target_gid);
    }
    
    // Create isolated jail filesystem
    ret = create_jail_filesystem(jail_root_path, sizeof(jail_root_path), jail_name);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Set up filesystem isolation (now that user exists and UID/GID are known)
    ret = setup_filesystem_isolation(caps, jail_root_path, target_binary, target_uid, target_gid, username);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Create jail with isolated filesystem
    int jid = create_jail(jail_name, jail_root_path);
    if (jid < 0) {
        freebsd_cleanup_isolation();
        return -1;
    }

    // Set resource limits
    ret = setup_resource_limits(jail_name, &caps->limits);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Set up network isolation
    ret = setup_network_isolation(caps->network, caps->network_count);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Attach to jail
    ret = attach_to_jail(jid);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Switch to target user using pre-resolved UID/GID
    ret = switch_to_user(target_uid, target_gid, username);
    if (ret != 0) {
        freebsd_cleanup_isolation();
        return ret;
    }

    // Register cleanup handler for normal exit in child process
    atexit(freebsd_cleanup_isolation);
    
    printf("FreeBSD isolation context created successfully\n");
    printf("Running in jail %s as user %s\n", jail_name, username);
    printf("Jail filesystem: %s\n", jail_root_path);
    
    return 0;
}

#endif /* __FreeBSD__ */
