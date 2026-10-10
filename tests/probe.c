/*
 * Test helper run inside a jail by tests/scenarios.sh.
 *
 *   probe procs            fork until it fails; report how many succeeded
 *   probe files            open until it fails; report how many succeeded
 *   probe mem <ms>         touch 8 MB every <ms> milliseconds, up to 256 MB
 *   probe conn ip port ... try a TCP connection to each address, 2 s timeout
 *   probe args ...         report the number of arguments after "args"
 *   probe fds              list open file descriptors from 3 upwards
 *   probe ignore-term      ignore SIGTERM and SIGINT, sleep until killed
 */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
probe_procs(void)
{
	pid_t kids[64];
	int n;

	for (n = 0; n < 64; n++) {
		pid_t p = fork();
		if (p < 0) {
			printf("procs: fork failed after %d children: %s\n", n, strerror(errno));
			break;
		}
		if (p == 0) {
			pause();
			_exit(0);
		}
		kids[n] = p;
	}
	if (n == 64)
		printf("procs: no limit reached after 64 children\n");
	for (int i = 0; i < n; i++)
		kill(kids[i], SIGKILL);
	while (wait(NULL) > 0)
		;
	return (0);
}

static int
probe_files(void)
{
	int n;

	for (n = 0; n < 4096; n++) {
		if (open("/dev/null", O_RDONLY) < 0) {
			printf("files: open failed after %d extra descriptors: %s\n", n, strerror(errno));
			return (0);
		}
	}
	printf("files: no limit reached after 4096 descriptors\n");
	return (0);
}

static int
probe_mem(int delay_ms)
{
	const size_t chunk = 8u << 20;
	size_t total = 0;

	for (int i = 0; i < 32; i++) {
		char *p = malloc(chunk);
		if (p == NULL) {
			printf("mem: malloc failed after %zu MB\n", total >> 20);
			return (0);
		}
		memset(p, 1, chunk);
		total += chunk;
		if (delay_ms > 0)
			usleep((useconds_t)delay_ms * 1000);
	}
	printf("mem: touched %zu MB, no limit reached\n", total >> 20);
	if (delay_ms > 0)
		sleep(3);
	return (0);
}

static int
probe_conn(int argc, char **argv)
{
	for (int i = 0; i + 1 < argc; i += 2) {
		struct sockaddr_in a;
		int s, r, e;

		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) {
			printf("conn: %s:%s socket failed: %s\n", argv[i], argv[i + 1], strerror(errno));
			continue;
		}
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons((unsigned short)atoi(argv[i + 1]));
		inet_pton(AF_INET, argv[i], &a.sin_addr);
		fcntl(s, F_SETFL, O_NONBLOCK);
		r = connect(s, (struct sockaddr *)&a, sizeof(a));
		e = errno;
		if (r < 0 && e == EINPROGRESS) {
			struct timeval tv = { 2, 0 };
			fd_set w;

			FD_ZERO(&w);
			FD_SET(s, &w);
			if (select(s + 1, NULL, &w, NULL, &tv) <= 0) {
				r = -1;
				e = ETIMEDOUT;
			} else {
				socklen_t l = sizeof(e);
				getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &l);
				r = e ? -1 : 0;
			}
		}
		if (r == 0)
			printf("conn: %s:%s connected\n", argv[i], argv[i + 1]);
		else
			printf("conn: %s:%s failed: %s\n", argv[i], argv[i + 1], strerror(e));
		close(s);
	}
	return (0);
}

static int
probe_fds(void)
{
	int found = 0;

	for (int fd = 3; fd < 256; fd++) {
		if (fcntl(fd, F_GETFD) != -1) {
			printf("fds: descriptor %d is open\n", fd);
			found++;
		}
	}
	printf("fds: %d inherited\n", found);
	return (0);
}

static int
probe_ignore_term(void)
{
	signal(SIGTERM, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	printf("ignore-term: running\n");
	for (;;)
		sleep(1);
}

int
main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc < 2)
		return (2);
	if (strcmp(argv[1], "procs") == 0)
		return (probe_procs());
	if (strcmp(argv[1], "files") == 0)
		return (probe_files());
	if (strcmp(argv[1], "mem") == 0)
		return (probe_mem(argc > 2 ? atoi(argv[2]) : 0));
	if (strcmp(argv[1], "conn") == 0)
		return (probe_conn(argc - 2, argv + 2));
	if (strcmp(argv[1], "args") == 0) {
		printf("args: %d\n", argc - 2);
		return (0);
	}
	if (strcmp(argv[1], "fds") == 0)
		return (probe_fds());
	if (strcmp(argv[1], "ignore-term") == 0)
		return (probe_ignore_term());
	return (2);
}
