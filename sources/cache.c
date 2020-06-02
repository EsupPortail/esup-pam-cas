#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/md5.h>
#include <security/pam_appl.h>

#include "cas.h"

#define DIGEST_LENGTH 16

char *cacheFilename(const char *service, const char *user, const char *ticket, const pam_cas_config_t *config)
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

int update_atime(FILE *f)
{
  struct timespec times[2];
  times[0].tv_sec = 0;
  times[0].tv_nsec = UTIME_NOW;
  times[1].tv_sec = 0;
  times[1].tv_nsec = UTIME_OMIT;
  return futimens(fileno(f), times);
}

int readCacheFile(FILE *f)
{
  rewind(f);
  int ret;
  char c;
  if (fscanf(f, "%d%c", &ret, &c) == 2 && c == '\n') {
      printf("readCacheFile found %d <%c>\n", ret, c);
      if (ret == PAM_SUCCESS || ret == PAM_AUTH_ERR) return ret;
  }
  return -1;
}

int readCache_or_lockCache(const char *service, const char *user, const char *ticket, const pam_cas_config_t *config, FILE **cacheFile)
{
  char *filename = cacheFilename(service, user, ticket, config);
  FILE *f = fopen(filename, "a+");
  free(filename);

  if (f == NULL) {
      fprintf(stderr, "could not open cache file: %s\n", strerror(errno));
      return -1;
  }  

  int ret = readCacheFile(f);
  if (ret !=  -1) {
      // cool, the normal easy case
      update_atime(f);
      fclose(f);
      return ret;
  }

  // ensure only one pam_cas is validating the ticket
  lockf(fileno(f), F_LOCK, 0);

  // check if someone did the work while we were waiting for the lock
  ret = readCacheFile(f);
  if (ret !=  -1) {
      fclose(f); // NB: releases the lock
      return ret;
  } else {
    // this pam_cas is responsable for validating the proxy ticket.
    // keeping file open and locked
    *cacheFile = f;
    return -1; 
  }
}

void setCache(FILE *cacheFile, int status)
{
  rewind(cacheFile); ftruncate(fileno(cacheFile), 0); // just in case?

  fprintf(cacheFile, "%d\n", status);
  fclose(cacheFile); // NB: releases the lock
}
