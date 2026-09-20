/*
** platsupp.c - Platform interface support scaffold (C wrapper).
** This wrapper is a buffer for structures that change from OS to OS.
** This file is a part of the checkmd5 tool.
**
** Copyright (C) 2026 by AK-47.
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

#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

long platformPageSize(void)
{
	errno = 0;
	return sysconf(_SC_PAGESIZE);
}

struct platform_stat {
	long long size;
	size_t blksize;
};
int platformStat(const char *restrict path, struct platform_stat *restrict ast)
{
	struct stat sb;
	if (stat(path, &sb)!=0) {
		return errno;
	}
	ast->size = sb.st_size;
	ast->blksize = sb.st_blksize;
	return 0;
}

int platformFileOpenSequentialRO(const char *restrict path)
{
	int fd = open(path, O_RDONLY);
	if (fd > 0) {
		posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	}
	return fd;
}
long long platformFileRead(int fd, void *restrict buffer, size_t size)
{
	return read(fd, buffer, size);
}
void platformFileClose(int fd)
{
	close(fd);
}
