#include <sys/stat.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/md5.h>

#include "cas.h"

#define DIGEST_LENGTH 16

char *cacheFile(const char *user, const char *ticket, const pam_cas_config_t *config)
{
  MD5_CTX context;
  MD5_Init(&context);
  MD5_Update(&context, config->service, strlen(config->service));
  MD5_Update(&context, user, strlen(user));
  MD5_Update(&context, ticket, strlen(ticket));
  unsigned char digest[DIGEST_LENGTH];
  MD5_Final(digest, &context);

  int n;
  unsigned char c;
  char *d;
  const char *s;

  char *f;
  if ((f = malloc(strlen(config->cacheDirectory) + strlen(user) + 2 * DIGEST_LENGTH + 3))) {
    for (s = config->cacheDirectory, d = f;*s;) *d++ = *s++;
    *d++ = '/';
    for (s = user;*s;) *d++ = *s++;
    *d++ = ',';
    for (s = (const char *) digest, n = DIGEST_LENGTH;--n >= 0;) {
      c = *s++;
      *d++ = (c >>  4) + ((c >>  4) < 10 ? '0' : 'a' - 10);
      *d++ = (c & 0xf) + ((c & 0xf) < 10 ? '0' : 'a' - 10);
    }
    *d = 0;
    if (config->debug == DEBUG_LOCAL) printf("cacheFile %s\n", f);
  }
  return f;
}

int hasCache(const char *f)
{
  static struct timespec times[2] = {{0, UTIME_NOW},{0, UTIME_OMIT}};
  // update last usage time so we know the ticket is still in use
  return utimensat(0, f, times, 0) == 0;
}

void setCache(const char *f)
{
  int d;
  if ((d = open(f, O_CREAT, 0600)) >= 0) close(d);
}
