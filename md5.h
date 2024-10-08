#ifndef MD5_H
#define MD5_H

#include <stdint.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bytes[2];
	uint8_t in[64];
};

void MD5Init(struct MD5Context *restrict const context);
void MD5Update(struct MD5Context *restrict const context, const uint8_t *restrict buf, size_t len);
void MD5Final(uint8_t digest[16], struct MD5Context *restrict const context);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#endif /* !MD5_H */
