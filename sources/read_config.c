/* read_config.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syslog.h"
#include <errno.h>

#include "cas.h"

#define FALSE 0
#define TRUE 1

#define LOG(X, Y)  do { if (debug) { \
  if (debug == DEBUG_LOCAL) printf((X), (Y)); \
  else if (debug == DEBUG_SYSLOG) syslog(LOG_DEBUG, (X), (Y)); \
} \
} while (0);


#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    free_config(presult); \
    return CAS_ERROR_MEMORY_ALLOC; \
} \
} while (0)

static int alloc_config (pam_cas_config_t ** presult);
static char **add_proxy(char **proxies, const char *proxy);
static void free_proxies(char **proxies);

static char *defaultConfigFile = DEFAULT_CONFIG_NAME;
static int debug;


int
read_config (const char *configFile, pam_cas_config_t ** presult, int localDebug)
{
  FILE *fp;
  char b[BUFSIZ];
  pam_cas_config_t *result;

  debug = localDebug;
  
  if (alloc_config (presult) != TRUE)
  {
      return CAS_ERROR_MEMORY_ALLOC;
  }

  result = *presult;
  if (configFile == NULL)
  {
      configFile = defaultConfigFile;
  }
  fp = fopen (configFile, "r");

  if (fp == NULL)
  {
      LOG("unable to open config file \"%s\"\n", configFile);
      return CAS_READCONF_FAILURE;
  }
  else
  LOG("configFile = %s\n", configFile);


  while (fgets (b, sizeof (b), fp) != NULL)
  {
      char *k, *v;
      int len;

      if (*b == '\n' || *b == '#')
	      continue;

      k = b;
      v = k;
      while (*v != '\0' && *v != ' ' && *v != '\t')
	      v++;

      if (*v == '\0')
	      continue;

      *(v++) = '\0';
      while (*v == ' ' || *v == '\t')
	      v++;
      len = strlen (v) - 1;
      while (v[len] == ' ' || v[len] == '\t' || v[len] == '\n'|| v[len] == '\r')
	      --len;
      v[len + 1] = '\0';

      if ((!strcasecmp (k, "host")) && (result->host == NULL))
      {
	  CHECKPOINTER (result->host = strdup (v));
      }
      else if ((!strcasecmp (k, "port")) && (result->port == NULL))
      {
	  CHECKPOINTER (result->port = strdup (v));
      }
      else if ((!strcasecmp (k, "uriValidate"))&& (result->uriValidate == NULL))
      {
	  CHECKPOINTER (result->uriValidate = strdup (v));
      }
      else if ((!strcasecmp (k, "trusted_ca")) && (result->trusted_ca == NULL))
      {
	  CHECKPOINTER (result->trusted_ca = strdup (v));
      }
      else if (!strcasecmp (k, "ssl"))
      {
          result->ssl = strcasecmp (v, "on") ? 0 : 1;
      }
      else if (!strcasecmp (k, "debug"))
      {
          result->debug = strcasecmp (v, "on") ? 0 : 1;
      }
      else if (!strcasecmp (k, "proxy"))
      {
          result->proxies = add_proxy(result->proxies, v);
          if (result->proxies == NULL)
	  {
             fclose(fp);
             return CAS_ERROR_MEMORY_ALLOC;
          }
      }
  }
  if (! result->host)
  {
      LOG("missing \"host\" in file \"%s\"\n",  configFile);
      return CAS_ERROR_CONFIG;
  }
  if (! result->uriValidate)
  {
	  CHECKPOINTER (result->uriValidate = strdup (DEFAULT_URI_VALIDATE));
  }
  if ((result->ssl) && (! result->trusted_ca))
  {
      LOG("missing \"trusted_ca\" while ssl in file \"%s\"\n", configFile);
      return CAS_ERROR_CONFIG;
  }

  if (! result->port)
  {
    result->port = result->ssl ? strdup("443") : strdup("80");
  }

  fclose (fp);

  /* can't use _pam_overwrite because it only goes to end of string,
   * not the buffer
   */
  memset (b, 0, BUFSIZ);
  return CAS_SUCCESS;
}


static int alloc_config (pam_cas_config_t ** presult)
{
  pam_cas_config_t *result;
  if (*presult != NULL)
    free_config(presult);
  *presult = (pam_cas_config_t *) calloc (1, sizeof (*result));
  if (*presult == NULL)
    return FALSE;
  result = *presult;
  result->host = NULL;
  result->port = 0;
  result->uriValidate = NULL;
  result->service = NULL;
  result->trusted_ca = NULL;
  result->ssl = 1;
  result->debug = 0;
  result->proxies = (char **)malloc(sizeof(char **));
  if (result->proxies == NULL)
  {
    free(*presult);
    *presult = NULL;
    return FALSE;
  }
  result->proxies[0] = NULL;
  return TRUE;
}

/* adds another proxy to the proxy array, NULL-terminating it */
static char **add_proxy(char **proxies, const char *p) {

    char *proxy, **oldProxies;
    int i = 0;

    oldProxies = proxies;
    proxy = strdup(p);
    if (proxy == NULL)
    {
      free_proxies(proxies);
      return NULL;
    }

    /* find the end of the proxy array */
    while(proxies[i++]);

    /* realloc proxies to be sizeof(proxies + new_proxy + NULL) */
    proxies = (char **)realloc(oldProxies, sizeof(*proxies) * (i + 1));
    if (proxies == NULL)
    {
      free_proxies(oldProxies);
      return NULL;
    }
    proxies[i-1] = proxy;
    proxies[i] = NULL;
    return proxies;
}

void free_proxies(char **proxies) 
{
    int i = 0;
    if (proxies != NULL)
    {
      for (i = 0; proxies[i]; i++)
      {
	free(proxies[i]);
      }
    free(proxies);
    }
}

void free_config(pam_cas_config_t ** pstConfig)
{
  pam_cas_config_t *conf;
  if (pstConfig == NULL)
    return;
  conf = *pstConfig;
  if (conf == NULL)
    return;
  if (conf->host != NULL)
    free(conf->host);
  if (conf->port != NULL)
    free(conf->port);
  if (conf->uriValidate != NULL)
    free(conf->uriValidate);
  if (conf->service != NULL)
    free(conf->service);
  if (conf->trusted_ca != NULL)
    free(conf->trusted_ca);
  if (conf->proxies != NULL)
    free_proxies(conf->proxies);
  free(conf);
  *pstConfig = NULL;
}
