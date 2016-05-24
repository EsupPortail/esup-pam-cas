#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/md5.h>

#include "cas.h"

#define DIGEST_LENGTH 16

void create(const char *file) {
  FILE *f = fopen(file, "w");
  if (f != NULL) fclose(f);
}

char *cacheFile(const char *service, const char *user, const char *ticket, const pam_cas_config_t *config)
{
  MD5_CTX context;
  MD5_Init(&context);
  MD5_Update(&context, service, strlen(service));
  MD5_Update(&context, user, strlen(user));
  MD5_Update(&context, ticket, strlen(ticket));
  unsigned char digest[DIGEST_LENGTH];
  MD5_Final(digest, &context);

  char hash[DIGEST_LENGTH*2+1];

  int n;
  for (n = 0; n < DIGEST_LENGTH; ++n) {
    sprintf(&(hash[n*2]), "%02x", (unsigned int) digest[n]);
  }
 
  int len = strlen(config->cacheDirectory) + 1 + strlen(user) + 1 + sizeof(hash);
  char *f = malloc(len);
  snprintf(f, len, "%s/%s,%s", config->cacheDirectory, user, hash);

  if (config->debug == DEBUG_LOCAL) printf("cacheFile %s\n", f);
  
  return f;
}

int update_atime(const char *f)
{
  struct timespec times[2];
  times[0].tv_sec = 0;
  times[0].tv_nsec = UTIME_NOW;
  times[1].tv_sec = 0;
  times[1].tv_nsec = UTIME_OMIT;
  return utimensat(0, f, times, 0);
}

int hasCache(const char *service, const char *user, const char *ticket, const pam_cas_config_t *config)
{
  char *f = cacheFile(service, user, ticket, config);

  int has = access(f, F_OK) != -1;
  if (has) {
    // update last modified time so we know the ticket is still in use
    update_atime(f);
  }

  free(f);
  return has;
}

void setCache(const char *service, const char *user, const char *ticket, const pam_cas_config_t *config)
{
  char *f = cacheFile(service, user, ticket, config);
  create(f);
  free(f);
}
