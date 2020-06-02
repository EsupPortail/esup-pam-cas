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
/*
 *
 * modify by esup consortium : http://esup-portail.org/
 * 
 */

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include "cas.h"

#define END(x) { ret = (x); goto end; }

static char *ErrorMessage[] = {
  "",
  "reading failure",
  "bad parameter", 
  "bad CAS ticket",
  "error in memory allocation",
  "error with ssl initialization",
  "error loading local certificate",
  "error validating server certificate",
  "error with ssl connection",
  "error with network connection",
  "error with http(s) connection",
  "error CAS protocol",
  "error CAS bad proxy",
  NULL
};

static int _get_authtok (pam_handle_t * pamh);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, 
     const char **argv)
{
    pam_cas_config_t *pstConfig = NULL;
    char *configFile = NULL;
    FILE *cacheFile = NULL;
    char *user, *pw;
    char *service = NULL;
    char netid[CAS_LEN_NETID];
    int i, success, res, ret;

    /* prepare log */
    openlog("PAM_cas", LOG_PID, LOG_AUTH);

    /* get username and password */
    if (pam_get_user(pamh, (const char**) &user, NULL) != PAM_SUCCESS){
	syslog(LOG_ERR, "Cannot get username");
	END(PAM_AUTH_ERR);
    }
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void**) &pw) != PAM_SUCCESS){
	syslog(LOG_ERR, "Cannot get password (ticket)");
	END(PAM_AUTH_ERR);
    }

   if (!pw)
   {
      if (_get_authtok(pamh) != PAM_SUCCESS){
	 syslog(LOG_ERR, "Cannot get_authtok from pamh");
         END(PAM_AUTH_ERR);
      }
      if (pam_get_item(pamh, PAM_AUTHTOK, (const void**) &pw) != PAM_SUCCESS){
	syslog(LOG_ERR, "Cannot get password (ticket) item from pamh");
	END(PAM_AUTH_ERR);
      }
   }

    /*
     * Abort if the password doesn't look like a ticket.  This speeds things
     * up and reduces the likelihood that the user's password will end up
     * in an HTTPD log.
     */
   if ((strncmp(CAS_BEGIN_PT, pw, strlen(CAS_BEGIN_PT)) != 0)
       && (strncmp(CAS_BEGIN_ST, pw, strlen(CAS_BEGIN_ST)) != 0))
         END(PAM_AUTH_ERR);

    /* check arguments */
    for (i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "-s", 2)) {
	    service = strdup(argv[i] + 2);
	} else if (!strncmp(argv[i], "-f", 2)) {
	    configFile = strdup(argv[i] + 2);
        } else if (!strncmp(argv[i], "-e", 2)) {
	    /* don't let the username pass through if it's excluded */
	    if (!strcmp(argv[i] + 2, user)) {
		syslog(LOG_NOTICE, "user '%s' is excluded from the CAS PAM",
		    user);
		END(PAM_AUTH_ERR);
	    }
	} else
	    syslog(LOG_ERR, "invalid option '%s'", argv[i]);
    }
    res = read_config (configFile, &pstConfig, DEBUG_NO);
    if (res != CAS_SUCCESS)
    {
      syslog(LOG_ERR, "Error with config file %s : %s\n", configFile, ErrorMessage[res]);
      END(PAM_AUTH_ERR);
    }

    if (pstConfig->cacheDirectory != NULL) {
        ret = readCache_or_lockCache(service, user, pw, pstConfig, &cacheFile);
        if (ret != -1) {
            if (pstConfig->debug)
                syslog(LOG_NOTICE, "USER '%s' %s WITH CACHED CAS PT:%s", user, ret == PAM_SUCCESS ? "AUTHENTICATED" : "FAILED", pw);
            goto end;
        }
    }
    
    /* determine the CAS-authenticated username */
    success = cas_validate(pw, 
                           service, 
                           netid, 
                           sizeof(netid),
			   pstConfig); 


    /* Confirm the user and return appropriately. */
    if ((success == CAS_SUCCESS) && (!strcasecmp(user, netid))) {
	if (pstConfig->debug)
	  syslog(LOG_NOTICE, "USER '%s' AUTHENTICATED WITH CAS PT:%s", user, pw);

        END(PAM_SUCCESS);
    } else {
        if (strcmp(user, netid) && (success == CAS_SUCCESS)) {
            syslog(LOG_NOTICE,
              "authentication failure : PAM login (%s) different from CAS login (%s)", user, netid);
	} else {
          if (pstConfig->debug)
            syslog(LOG_NOTICE,
              "authentication failure for user '%s' : %s. PT=%s", user, ErrorMessage[success],pw);
          else
            syslog(LOG_NOTICE,
              "authentication failure for user '%s' : %s.", user, ErrorMessage[success]);
       }
       END(PAM_AUTH_ERR);
    }

end:
  if (cacheFile != NULL)
    setCache(cacheFile, ret);
  closelog();
  if (service)
    free(service);
  if (configFile)
    free(configFile);
  //  if (pstConfig)
  //free_config(&pstConfig);
  return ret;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
     const char **argv)
{
    return PAM_SUCCESS;
}

static int _get_authtok (pam_handle_t * pamh)
{
  int rc;
  char *p;
  struct pam_message msg[1], *pmsg[1];
  struct pam_response *resp;
  struct pam_conv *conv;

  pmsg[0] = &msg[0];
  msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
  msg[0].msg = "Password: ";
  resp = NULL;

  rc = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
  if (rc == PAM_SUCCESS)
  {
      rc = conv->conv (1,
		       (const struct pam_message **) pmsg,
		       &resp, conv->appdata_ptr);
  }
  else
  {
      return rc;
  }
  if (resp != NULL)
  {
      if (resp[0].resp == NULL)
      {
	  free (resp);
	  return PAM_AUTH_ERR;
      }

      p = resp[0].resp;
      /* leak if resp[0].resp is malloced. */
      resp[0].resp = NULL;
  }
  else
  {
      return PAM_CONV_ERR;
  }
  free (resp);
  pam_set_item (pamh, PAM_AUTHTOK, p);

  return PAM_SUCCESS;
}

char * getErrorMessage(int index)
{
  return ErrorMessage[index];
}
