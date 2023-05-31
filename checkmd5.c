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
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <termios.h>
#ifdef I18N
	#include <libintl.h>
	#define TR(S) gettext(S)
#else
	#define TR(S)
#endif // !I18N
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
static int checkmd5(struct CheckTarget **targets, size_t ntargets, bool force, bool gauge, bool verbose);

static int g_signal = 0;
static void sighandler(int sigraised);

static FILE *g_logfile = NULL;
static void logprint(bool console, const char *fmt, ...)
{
	va_list ap;
	if(g_logfile) {
		va_start(ap, fmt);
		vfprintf(g_logfile, fmt, ap);
		va_end(ap);
	}
	if(console) {
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
}

int main(int argc, const char **argv)
{
	if(argc<1) return EXIT_SYSTEM;
	#if I18N
	setlocale (LC_ALL, "");
	bindtextdomain("checkmd5", "/usr/share/locale/");
	textdomain("checkmd5");
	#endif

	++argv; --argc;
	bool force=false, gauge=false, verbose=false;
	while(argc>0 && (*argv)[0]=='-') {
		const char *arg = argv[0];
		if(!strcmp(arg, "--force")) force = true;
		else if(!strcmp(arg, "--gauge")) gauge = true;
		else if(!strcmp(arg, "--verbose")) verbose = true;
		else if(!strncmp(arg, "--log=", 6) && arg[6]!='\0') {
			const char *lfname = arg+6;
			g_logfile = fopen(lfname, "w");
			if(!g_logfile) {
				fprintf(stderr, "ERROR: %s: %s\n", strerror(errno), lfname);
				return EXIT_SYSTEM;
			}
		} else {
			if(strcmp(arg, "--")) argc = 0; // Triggers usage message.
			break; // The remaining arguments are checksum list files.
		}
		++argv;
		--argc;
	}
	if(argc<1) {
		fprintf(stderr, "Usage: checkmd5 [--force] [--verbose]"
			" [--log=<logfile>] [--gauge] [--] <checksum-file> ...\n");
		return EXIT_CKSUM;
	}

	// Log the start time and all of the list file names on the command line.
	const time_t tnow = time(NULL);
	logprint(false, "Start: %sLists:", ctime(&tnow));
	for(int i=0; i<argc; ++i) {
		logprint(false, " %s", argv[i]);
	}
	logprint(false, "\n");

	int rc = 0;
	size_t ntargets = 0;
	struct CheckTarget **targets = getTargets(&ntargets, argv, argc);
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

	puts(TR("Press [Esc] to abort the integrity check."));
	struct termios tio;
	tcgetattr(0, &tio);
	const tcflag_t oldlflag = tio.c_lflag;
	tio.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(0, TCSANOW, &tio);

	rc = checkmd5(targets, ntargets, force, gauge, verbose);

	switch(rc){
		case 0: puts(TR("Integrity check passed.")); break;
		case 2: puts(TR("Integrity check aborted.")); break;
		default: puts(TR("Integrity check failed.")); break;
	}
	tio.c_lflag = oldlflag;
	tcsetattr(0, TCSANOW, &tio);

 END:
	logprint(false, "Exit: %d\n", rc);
	if(g_logfile) fclose(g_logfile);
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
			logprint(true, "ERROR: %s: %s\n", strerror(errno), filename);
			goto ERROR;
		}

		char line[HASH_HEX_SIZE+16+PATH_MAX]; // md5 + spaces + path
		int nline = 0;
		const char *error = NULL;
		errno = 0;
		while(fgets(line, sizeof(line), sumfile)) {
			++nline;
			size_t len = strlen(line);
			while(line[len] <= ' ') line[len--] = '\0'; // Trim leading whitespace.
			if(len < (HASH_HEX_SIZE+1+1)) { // Minimum 32x md5 + 1x space + 1x path
				error = TR("Line too short");
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
				error = TR("Invalid hex or too short for MD5");
				break;
			}

			// Validate at least one space.
			int endspace = nhex;
			while(endspace<len) {
				if(line[endspace] != ' ' && line[endspace] != '\t') break;
				++endspace;
			}
			if(endspace<=nhex || endspace==len) {
				error = TR("No space or path");
				break;
			}

			// Add to the check list.
			struct CheckTarget **newtargets = reallocarray(targets,
				ntargets+1, sizeof(struct CheckTarget *));
			if(!newtargets) break;
			targets = newtargets;
			len -= endspace-2; // +1 end space offset, +1 null terminator.
			struct CheckTarget *target = malloc(sizeof(struct CheckTarget) + len);
			if(!target) break;
			targets[ntargets++] = target;

			memcpy(target->hash, line, HASH_HEX_SIZE);
			memcpy(target->path, line+endspace, len);
			// Obtain file size
			int fd = open(target->path, O_RDONLY);
			if (fd == -1) error = TR("Cannot open");
			else {
				struct stat sb;
				if (!error && fstat(fd, &sb)!=0) error = TR("Cannot stat");
				target->size = sb.st_size;
				target->blksize = sb.st_blksize;
				close(fd);
			}
			if(error) break;
		}
		fclose(sumfile);
		if(error) {
			if(!errno) logprint(true, "ERROR (%s line %d): %s.\n", filename, nline, error);
			else if(!error) logprint(true, "ERROR: %s\n", strerror(errno));
			else {
				logprint(true, "ERROR: %s (%s): %s\n",
					error, strerror(errno), targets[ntargets-1]->path);
			}
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

static int checkmd5(struct CheckTarget **targets, size_t ntargets, bool force, bool gauge, bool verbose)
{
	int rc = 0;
	// Calculate total size
	unsigned long long nbtotal = 0;
	size_t bufsize = 0;
	for(size_t i = 0; i < ntargets; ++i) {
		struct CheckTarget *restrict target = targets[i];
		nbtotal += target->size;
		if(bufsize < target->blksize) bufsize = target->blksize;
	}
	bufsize *= BUFFER_BLOCKS;
	unsigned char *buffer = aligned_alloc((size_t)sysconf(_SC_PAGESIZE), bufsize);
	if(!buffer) {
		logprint(true, "ERROR: %s\n", strerror(errno));
		rc = EXIT_SYSTEM; goto END;
	}

	// Check each file
	size_t npassed=0;
	unsigned long long nbproc=0, nbpassed=0;
	const char *checkmsg = TR("Checking");
	for(size_t ixtarget = 0; ixtarget < ntargets; ++ixtarget) {
		struct CheckTarget *target = targets[ixtarget];
		logprint(verbose, "Target: %.*s %s\n", HASH_HEX_SIZE,target->hash, target->path);
		int targetfd = open(target->path, O_RDONLY);
		if (targetfd < 0) {
			logprint(true, "%s: %s\n", strerror(errno), target->path);
			rc = EXIT_BADCHECK;
			if(!force) goto END;
			nbproc += target->size;
			continue;
		}

		unsigned int oldprog = 1001;
		struct MD5Context md5ctx;
		MD5Init(&md5ctx);
		static const char *checkfmt = "\r%s: %.1F%%";
		if(!gauge) {
			printf(checkfmt, checkmsg, 0.0);
			fflush(stdout);
		}
		for(off_t remain=target->size; remain>0;) {
			off_t nread = (remain>bufsize ? bufsize : remain);
			nread = read(targetfd, buffer, nread);
			MD5Update(&md5ctx, buffer, (unsigned int)nread);
			remain -= nread;
			nbproc += nread;

			// Progress indication and user cancel request handling.
			const unsigned int prog = (1000*nbproc) / nbtotal;
			if(prog != oldprog) {
				int rp = 0;
				if(!gauge) rp = printf(checkfmt, checkmsg, (float)prog/10.0);
				else if ((prog%10)==0) rp = printf("%u\n", prog/10);
				if(rp>0) fflush(stdout);

				oldprog = prog;

				// Check if the user has requested an early exit.
				fd_set fds;
				FD_ZERO(&fds);
				FD_SET(0, &fds);
				if(g_signal || (select(1, &fds, NULL, NULL, &(struct timeval){0}) && getchar() == 27)) {
					putchar('\n');
					logprint(verbose, "Aborted: %.1F%% ", (float)prog/10.0);
					if(!g_signal) logprint(verbose, "(ESC)\n");
					else logprint(verbose, "(signal %d)\n", g_signal);
					rc = EXIT_ABORTED; goto END;
				}
			}
		}
		close(targetfd);
		if(verbose) putchar('\n');

		unsigned char digest[HASH_SIZE];
		MD5Final(digest, &md5ctx);
		// Convert the hash to hex and compare with the expected hash.
		char hash[HASH_HEX_SIZE+1] = {0};
		for(int i=0; i<HASH_SIZE;++i) {
			snprintf(hash+(2*i), 3, "%02X", digest[i]);
		}
		const int result = memcmp(target->hash, hash, HASH_HEX_SIZE);
		logprint(verbose, "%s: %s %s\n", (result?"Failed":"Passed"), hash, target->path);
		if(result==0) {
			++npassed;
			nbpassed += target->size;
			if(!verbose && nbproc==nbtotal) putchar('\n');
		} else {
			if(!verbose) putchar('\n');
			printf("%s: %s\n", TR("Checksum mismatch"), target->path);
			rc = EXIT_BADCHECK;
			if(!force) goto END;
		}
	}
	logprint(verbose, "Result: %zu/%zu targets (%llu/%llu bytes) passed\n",
		npassed, ntargets, nbpassed, nbtotal);

 END:
	if(buffer) free(buffer);
	return rc;
}
