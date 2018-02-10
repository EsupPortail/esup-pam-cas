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

#include "cas.h"


/* dumb, simple test of cas_validate() function
three parameters :
  - service
  - ticket (ST or PT) to validate
  - config File (default to /etc/cas.conf)
*/
  
int main(int argc, char **argv) {
  pam_cas_config_t *pstConfig = NULL;
  char *configFile = NULL;
  char *ticket = "PT-1-xxx";
  char *service = "https://foo.fr";
  char netid[CAS_LEN_NETID];
  int retour, i;

  if (argc > 1) 
    service = argv[1];
  if (argc > 2)
    ticket = argv[2];
  if (argc >  3)
    configFile = argv[3];

  retour = read_config (configFile, &pstConfig, DEBUG_LOCAL);
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
  printf("service = %s\n", service);
  printf("ticket = %s\n\n\n", ticket);
  printf("---------------------------------------------------------------\n\n");

  pstConfig->debug = DEBUG_LOCAL;

  if (pstConfig->cacheDirectory != NULL &&
      hasCache(service, "foo", ticket, pstConfig)) {
    printf("found ticket in cache\n");
  }
  
  retour = cas_validate(ticket, service, netid, sizeof(netid), pstConfig);
  printf("---------------------------------------------------------------\n\n");
    if (retour == CAS_SUCCESS)
    printf("valid ticket for '%s'\n", netid);
  else
    printf("invalid ticket : %s\n\n", getErrorMessage(retour));
  
  free_config(&pstConfig);
  return 0;

}
