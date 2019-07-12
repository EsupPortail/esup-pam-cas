/*
 *  Copyright (c) 2000-2003 Yale University. All rights reserved.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS," AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE EXPRESSLY
 *  DISCLAIMED. IN NO EVENT SHALL YALE UNIVERSITY OR ITS EMPLOYEES BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED, THE COSTS OF
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED IN ADVANCE OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 *  Redistribution and use of this software in source or binary forms,
 *  with or without modification, are permitted, provided that the
 *  following conditions are met:
 *
 *  1. Any redistribution must include the above copyright notice and
 *  disclaimer and this list of conditions in any related documentation
 *  and, if feasible, in the redistributed software.
 *
 *  2. Any redistribution must include the acknowledgment, "This product
 *  includes software developed by Yale University," in any related
 *  documentation and, if feasible, in the redistributed software.
 *
 *  3. The names "Yale" and "Yale University" must not be used to endorse
 *  or promote products derived from this software.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cas.h"


/* dumb, simple test of cas_validate() function
four parameters :
  - service
  - login attribute name
  - config File (default to /etc/cas.conf)
  - ticket (ST or PT) to validate
*/
  
int main(int argc, char **argv) {
  pam_cas_config_t *pstConfig = NULL;
  char *configFile = NULL;
  char *ticket = NULL;
  char *service = NULL;
  char *attribute = NULL;
  char *cachefile = NULL;
  char netid[CAS_LEN_NETID];
  int retour, i;

  for(;--argc > 0;) {
	  if (!strncmp(*++argv, "-s", 2))
		  service = *argv + 2;
	  else if (!strncmp(*argv, "-a", 2))
		  attribute = *argv + 2;
	  else if (!strncmp(*argv, "-f", 2))
		  configFile = *argv + 2;
	  else if (**argv != '-')
		  ticket = *argv;
	  else {
		  printf("invalid option %s\n", *argv);
		  printf("Options: [-s<service>] [-a<attribute>] [-f<configFile>] [<proxyTicket>]\n");
		  return 1;
	  }
  }

  retour = read_config (service, attribute, configFile, &pstConfig, DEBUG_LOCAL);
  if (retour != CAS_SUCCESS)
  {
    printf("Error while reading config file. Error %d\n", retour);
    if (retour == CAS_READCONF_FAILURE)
      printf("cannot open it\n");
    else if (retour == CAS_ERROR_MEMORY_ALLOC)
      printf("memory allocation\n");
    else if (retour == CAS_READCONF_FAILURE)
      printf("missing parameter\n");


    return 1;
  }

  printf("---------------------------------------------------------------\n");
  printf("                    Parameters from test : \n\n");
  printf("host = %s\n", pstConfig->host);
  printf("port = %s\n", pstConfig->port);
  printf("uri = %s\n", pstConfig->uriValidate);
  printf("ssl = %s\n", pstConfig->ssl ? "on":"off");
  printf("trusted_ca = %s\n", pstConfig->trusted_ca ? pstConfig->trusted_ca : "nothing");
  printf("trusted_path = %s\n", pstConfig->trusted_path ? pstConfig->trusted_path : "nothing");
  printf("cacheDirectory = %s\n", pstConfig->cacheDirectory ? pstConfig->cacheDirectory : "disabled");
  printf("debug = localtest\n");
  i = 0;
  if ((pstConfig->proxies) && (pstConfig->proxies[i]))
  {
    for (i = 0; pstConfig->proxies[i]; i++)
      printf("proxy = %s\n", pstConfig->proxies[i]);
  }
  else
      printf("no proxy\n");
  if (!pstConfig->service) {
    pstConfig->service = strdup("https://foo.fr");
  }
  printf("service = %s\n", pstConfig->service);
  if (!pstConfig->attribute || !*pstConfig->attribute)
  	printf("username attribute not used\n");
  else
    printf("username attribute = %s\n", pstConfig->attribute);
  if (!ticket || !*ticket)
     ticket = "PT-1-xxx";
  printf("ticket = %s\n\n\n", ticket);
  printf("---------------------------------------------------------------\n\n");

  pstConfig->debug = DEBUG_LOCAL;

  if (pstConfig->cacheDirectory != NULL &&
      ((cachefile = cacheFile("foo", ticket, pstConfig)) != NULL) &&
      hasCache(cachefile)) {
    printf("found ticket in cache\n");
  }
  
  retour = cas_validate(ticket, netid, sizeof(netid), pstConfig);
  printf("---------------------------------------------------------------\n\n");
    if (retour == CAS_SUCCESS)
    printf("valid ticket for '%s'\n", netid);
  else
    printf("invalid ticket : %s\n\n", getErrorMessage(retour));
  
  if (cachefile)
    free(cachefile);
  free_config(&pstConfig);
  return 0;

}
