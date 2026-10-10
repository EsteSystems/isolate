/*
 * Process lookups that need struct kinfo_proc.
 *
 * This is C rather than Zig because <sys/user.h> does not survive
 * translate-c in Zig 0.16 (it pulls in <sys/time.h>, whose bintime helpers
 * are mistranslated). freebsd.zig declares the function below as extern.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <stddef.h>

/* The parent pid of `pid`, or -1 if there is no such process. */
int
isolate_parent_pid(int pid)
{
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
	struct kinfo_proc kp;
	size_t len = sizeof(kp);

	if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len == 0)
		return (-1);
	return ((int)kp.ki_ppid);
}
