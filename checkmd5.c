/*
** checkmd5 - Tool for checking the integrity of multiple files as one unit.
** Unlike md5sum, the user can abort the check by pressing Escape.
** This tool also indicates progress and supports verbose logging to a file.
**
** Copyright (C) 2023 by AK-47.
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <termios.h>
#include "md5.h"

#define BUFFER_BLOCKS 32
#define HASH_SIZE 16 // MD5 hash

#define HASH_HEX_SIZE (2*HASH_SIZE)

enum ExitValues {
	EXIT_OK = 0,
	EXIT_BADCHECK = 1,
	EXIT_ABORTED = 2,
	EXIT_SYSTEM = 3,
	EXIT_CKSUM = 4
};

struct CheckTarget {
	off_t size;
	blksize_t blksize;
	char hash[HASH_HEX_SIZE];
	char path[];
};
static struct CheckTarget **getTargets(size_t *restrict pchkcount, const char **sumfiles, int nsumfiles);
static int checkmd5(struct CheckTarget **targets, size_t ntargets, bool gauge);

static int g_signal = 0;
static void sighandler(int sigraised);
static FILE *g_logfile = NULL;
static void logprint(const char *fmt, ...)
{
	va_list ap;
	if(g_logfile) {
		va_start(ap, fmt);
		vfprintf(g_logfile, fmt, ap);
		va_end(ap);
	}
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, const char **argv)
{
	bool gauge = false;
	if(argc<1) {
		fprintf(stderr, "No name argument.\n");
		return EXIT_SYSTEM;
	}

	const char **sumfiles = argv+1;
	int nsumfiles = argc-1;
	while(nsumfiles>0) {
		const char *arg = sumfiles[0];
		if(!strncmp(arg, "--log", 5)) {
			const char *lfname = "/var/log/checkmd5.log";
			if(arg[5]=='=' && arg[6]!='\0') lfname = arg+5;
			else if(arg[5]!='\0') {
				nsumfiles = 0; // Trigger usage message.
				break;
			}
			g_logfile = fopen(lfname, "w");
			if(!g_logfile) {
				fprintf(stderr, "ERROR: Unable to open log file: %s\n", lfname);
				return EXIT_SYSTEM;
			}
			++sumfiles;--nsumfiles;
		} else if(!strcmp(arg, "--gauge")) {
			gauge = true;
			++sumfiles; --nsumfiles;
		} else {
			break; // Remainder of arguments are checksum files.
		}
	}
	if(nsumfiles<1) {
		fprintf(stderr, "Usage: checkmd5 [--log <logfile>] [--gauge] <checksum-file> ...\n");
		return EXIT_CKSUM;
	}

	if(g_logfile) {
		// Log all command line arguments used to invoke this instance.
		fputs(argv[0], g_logfile);
		for(int i=1; i<argc; ++i) {
			fprintf(g_logfile, " %s", argv[i]);
		}
		fputc('\n', g_logfile);
	}

	int rc = 0;
	size_t ntargets = 0;
	struct CheckTarget **targets = getTargets(&ntargets, sumfiles, nsumfiles);
	if(!targets) {
		rc = EXIT_CKSUM;
		goto END;
	}

	struct sigaction sa = { .sa_handler = &sighandler };
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGXCPU, &sa, NULL);
	sigaction(SIGXFSZ, &sa, NULL);
	sigaction(SIGVTALRM, &sa, NULL);
	sigaction(SIGPROF, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	printf("Press [Esc] to abort the integrity check.\n");
	struct termios tio;
	tcgetattr(0, &tio);
	const tcflag_t oldlflag = tio.c_lflag;
	tio.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(0, TCSANOW, &tio);

	rc = checkmd5(targets, ntargets, gauge);

	tio.c_lflag = oldlflag;
	tcsetattr(0, TCSANOW, &tio);

 END:
	if(g_logfile) {
		fprintf(g_logfile, "Exit code: %d\n", rc);
		fclose(g_logfile);
	}
	return rc;
}

static void sighandler(int sigraised)
{
	g_signal = sigraised;
}

static struct CheckTarget **getTargets(size_t *restrict pntargets, const char **sumfiles, int nsumfiles)
{
	struct CheckTarget **targets = NULL;
	size_t ntargets = 0;
	for(int i = 0; i < nsumfiles; ++i) {
		const char *filename = sumfiles[i];
		FILE *sumfile = fopen(filename, "r");
		if(!sumfile) {
			logprint("ERROR: Cannot open: %s\n", filename);
			goto ERROR;
		}

		char line[HASH_HEX_SIZE+16+PATH_MAX]; // md5 + spaces + path
		int nline = 0;
		const char *error = NULL, *errparam = NULL;
		while(fgets(line, sizeof(line), sumfile)) {
			++nline;
			size_t len = strlen(line);
			while(line[len] <= ' ') line[len--] = '\0'; // Trim leading whitespace.
			if(len < (HASH_HEX_SIZE+1+1)) { // Minimum 32x md5 + 1x space + 1x path
				error = "line too short";
				break;
			}

			// Validate hex and convert to upper case.
			int nhex = 0;
			while(nhex<HASH_HEX_SIZE) {
				char c = line[nhex];
				if(c>='a') c = 'A'+(c-'a'); // Convert to upper-case.
				if((c<'0' || c>'9') && (c<'A' || c >'F')) break; // Invalid hex.
				line[nhex++] = c;
			}
			if(nhex!=HASH_HEX_SIZE) {
				error = "invalid hex or too short for MD5";
				break;
			}

			// Validate at least one space.
			int endspace = nhex;
			while(endspace<len) {
				if(line[endspace] != ' ' && line[endspace] != '\t') break;
				++endspace;
			}
			if(endspace<=nhex || endspace==len) {
				error = "no space or path";
				break;
			}

			// Add to the check list.
			struct CheckTarget **newtargets = reallocarray(targets,
				ntargets+1, sizeof(struct CheckTarget *));
			if(!newtargets) {
				error = "not enough memory";
				break;
			}
			targets = newtargets;
			len -= endspace-2; // +1 end space offset, +1 null terminator.
			struct CheckTarget *target = malloc(sizeof(struct CheckTarget) + len);
			if(!target) {
				error = "not enough memory";
				break;
			}
			targets[ntargets++] = target;

			memcpy(target->hash, line, HASH_HEX_SIZE);
			memcpy(target->path, line+endspace, len);
			// Obtain file size
			int fd = open(target->path, O_RDONLY);
			if (fd == -1) error = "cannot open";
			else {
				struct stat sb;
				if (!error && fstat(fd, &sb)!=0) error = "cannot stat";
				target->size = sb.st_size;
				target->blksize = sb.st_blksize;
				close(fd);
			}
			if(error) {
				errparam = target->path;
				break;
			}
		}
		fclose(sumfile);
		if(error) {
			if(errparam) logprint("ERROR: %s: %s\n", error, errparam);
			else logprint("ERROR (%s line %d): %s.\n", filename, nline, error);
			goto ERROR;
		}
	}
	*pntargets = ntargets;
	return targets;

ERROR:
	if(targets) {
		for(size_t i = 0; i < ntargets; ++i) free(targets[i]);
		free(targets);
	}
	return NULL;
}

static int checkmd5(struct CheckTarget **targets, size_t ntargets, bool gauge)
{
	int rc = 0;
	// Calculate total size
	unsigned long long total = 0;
	size_t bufsize = 0;
	for(size_t i = 0; i < ntargets; ++i) {
		struct CheckTarget *restrict target = targets[i];
		total += target->size;
		if(bufsize < target->blksize) bufsize = target->blksize;
	}
	bufsize *= BUFFER_BLOCKS;
	unsigned char *buffer = aligned_alloc((size_t)sysconf(_SC_PAGESIZE), bufsize);
	if(!buffer) {
		logprint("ERROR: Out of memory.\n");
		rc = EXIT_SYSTEM; goto END;
	}

	// Check each file
	unsigned long long nprocessed = 0;
	for(size_t ixtarget = 0; ixtarget < ntargets; ++ixtarget) {
		struct CheckTarget *target = targets[ixtarget];
		if(g_logfile) {
			fprintf(g_logfile, "Target: %s MD5=%.*s size=%llu\n", target->path,
				HASH_HEX_SIZE,target->hash, (unsigned long long)target->size);
		}
		int targetfd = open(target->path, O_RDONLY);
		if (targetfd < 0) {
			logprint("ERROR: Cannot open target: %s\n", target->path);
			rc = EXIT_BADCHECK; goto END;
		}

		unsigned int oldprog = 1001;
		struct MD5Context md5ctx;
		MD5Init(&md5ctx);
		if(!gauge) printf("\rChecking...");
		for(off_t remain=target->size; remain>0;) {
			off_t nread = (remain>bufsize ? bufsize : remain);
			nread = read(targetfd, buffer, nread);
			MD5Update(&md5ctx, buffer, (unsigned int)nread);
			remain -= nread;
			nprocessed += nread;

			// Progress indication and user cancel request handling.
			const unsigned int prog = (1000*nprocessed) / total;
			if(prog != oldprog) {
				if(gauge && (prog%10)==0) printf("%u\n", prog/10);
				else printf("\rChecking: %.1F%%", (float)prog/10.0);
				fflush(stdout);
				oldprog = prog;

				// Check if the user has requested an early exit.
				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(0, &fds);
				if(g_signal || (select(1, &fds, NULL, NULL, &(struct timeval){0}) && getchar() == 27)) {
					putchar('\n');
					logprint("Aborted at: %.1F%% ", (float)prog/10.0);
					if(!g_signal) logprint("(ESC)\n");
					else logprint("(signal %d)\n", g_signal);
					rc = EXIT_ABORTED; goto END;
				}
			}
		}

		close(targetfd);
		unsigned char digest[HASH_SIZE];
		MD5Final(digest, &md5ctx);
		// Convert the hash to hex and compare with the expected hash.
		char hash[HASH_HEX_SIZE+1] = {0};
		for(int i=0; i<HASH_SIZE;++i) {
			snprintf(hash+(2*i), 3, "%02X", digest[i]);
		}
		const int result = memcmp(target->hash, hash, HASH_HEX_SIZE);
		if(g_logfile) {
			fprintf(g_logfile, "Result: %s MD5=%s ", target->path, hash);
			if(result==0) fprintf(g_logfile, "(PASS)\n");
			else fprintf(g_logfile, "(FAIL=%d)\n", result);
		}
		if(result!=0) {
			putchar('\n');
			logprint("Checksum mismatch: %s\n", target->path);
			logprint("Expected: %.*s\nObtained: %s\n", HASH_HEX_SIZE,target->hash, hash);
			rc = EXIT_BADCHECK; goto END;
		}
	}
	putchar('\n');

 END:
	if(buffer) free(buffer);
	return rc;
}
