/*
 * Platform abstraction layer for isolation
 */

#include <stdio.h>
#include <errno.h>
#include "common.h"

int create_isolation_context(const struct capabilities *caps) {
#ifdef __FreeBSD__
    return freebsd_create_isolation(caps);
#elif defined(__linux__)
    return linux_create_isolation(caps);
#else
    fprintf(stderr, "Isolation not implemented for this platform\n");
    return ENOSYS;
#endif
}

void cleanup_isolation_context(void) {
#ifdef __FreeBSD__
    freebsd_cleanup_isolation();
#elif defined(__linux__)
    linux_cleanup_isolation();
#endif
}
