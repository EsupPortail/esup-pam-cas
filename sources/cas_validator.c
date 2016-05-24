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
 * CAS 2.0 service- and proxy-ticket validator in C, using OpenSSL.
 *
 * Originally by Shawn Bayern, Yale ITS Technology and Planning.
 * Patches submitted by Vincent Mathieu, University of Nancy, France.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <syslog.h>
#include "cas.h"
#include "xml.h"


#define END(x) { ret = (x); goto end; }
#define FAIL END(CAS_ERROR)
#define SUCCEED END(CAS_SUCCESS)


#define LOG(X, Y)  do { if (debug) { \
  if (debug == DEBUG_LOCAL) printf((X), (Y)); \
  else if (debug == DEBUG_SYSLOG) syslog(LOG_DEBUG, (X), (Y)); \
} \
} while (0);

static int debug = 0;

static int arrayContains(char *array[], char *element);


/** Returns status of ticket by filling 'buf' with a NetID if the ticket
 *  is valid and buf is large enough and returning 1.  If not, 0 is
 *  returned.
 */
int cas_validate(
    char *ticket, char *service, char *outbuf, int outbuflen, pam_cas_config_t *config)
{
  int b, ret, total;
  SSL_CTX *ctx = NULL;
  BIO * bio = NULL;
  SSL *ssl = NULL;
  char buf[4096];
  char *full_request = NULL, *str;
  char netid[CAS_LEN_NETID];
  char parsebuf[128];

  debug = config->debug;

  if (config->ssl)
  {
    /* Set up the SSL library */
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Set up the SSL context */
    ctx = SSL_CTX_new(SSLv23_client_method());

    /* Load the trust store */
    if(! SSL_CTX_load_verify_locations(ctx, config->trusted_ca, NULL))
    {
      syslog(LOG_ERR, "Error loading certificate store. %s\n",ERR_reason_error_string(ERR_get_error()));
      LOG("Error loading certificate store : %s\n", ERR_reason_error_string(ERR_get_error()));
      END(CAS_SSL_ERROR_CERT_LOAD);
    }

    /* Setup the connection */
    bio = BIO_new_ssl_connect(ctx);

    /* Set the SSL_MODE_AUTO_RETRY flag :
       if the server suddenly wants a new handshake, OpenSSL handles it in the background */
    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    /* Create and setup the connection */
    BIO_set_conn_hostname(bio, config->host);
    BIO_set_conn_port(bio, config->port);
    if(BIO_do_connect(bio) <= 0)
    {
      LOG("Error attempting to connect : %s\n", ERR_reason_error_string(ERR_get_error()));
      END(CAS_SSL_ERROR_CONN);
    }

    /* Check the certificate */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
      LOG("Certificate verification error: %ld\n", SSL_get_verify_result(ssl));
      END(CAS_SSL_ERROR_CERT_VALID);
    }
  }
  else  /* no ssl */
  {    
    bio = BIO_new_connect(config->host);
    BIO_set_conn_port(bio, config->port);
    if(BIO_do_connect(bio) <= 0)
    {
      LOG("Error attempting to connect : %s\n", config->host);
      END(CAS_ERROR_CONN);
    }
  }

  /* build request */
  full_request = malloc(strlen(CAS_METHOD) + strlen(" ")
    + strlen(config->uriValidate) + strlen("?ticket=") + strlen(ticket) + 
    + strlen("&service=") + strlen(service) + strlen(" ") 
    + strlen(CAS_PROT) + strlen("\n\n") + 1);
  if (full_request == NULL)
  {
      LOG("Error memory allocation%s\n", "");
      END(CAS_ERROR_MEMORY_ALLOC);
  }
  sprintf(full_request, "%s %s?ticket=%s&service=%s %s\n\n",
    CAS_METHOD, config->uriValidate, ticket, service, CAS_PROT);

  /* send request */
  if (BIO_write(bio, full_request, strlen(full_request)) != strlen(full_request))
  {
    LOG("Unable to correctly send request to %s\n", config->host);
    END(CAS_ERROR_HTTP);
  }

  /* Read the response */
  total = 0;
  do 
  {
    b = BIO_read(bio, buf + total, (sizeof(buf) - 1) - total);
    total += b;
  } while (b > 0);
  buf[total] = '\0';

  if (b != 0 || total >= sizeof(buf) - 1)
  {
    LOG("Unexpected read error or response too large from %s\n", config->host);
    LOG("b = %d\n", b);
    LOG("total = %d\n", total);
    LOG("buf = %s\n", buf);
    END(CAS_ERROR_HTTP);		// unexpected read error or response too large
  }

  str = (char *)strstr(buf, "\r\n\r\n");  // find the end of the header

  if (!str)
  {
    LOG("no header in response%s\n", "");
    END(CAS_ERROR_HTTP);			  // no header
  }
  
  /*
   * 'str' now points to the beginning of the body, which should be an
   * XML document
   */

  // make sure that the authentication succeeded
  
  if (!element_body(
    str, "cas:authenticationSuccess", 1, parsebuf, sizeof(parsebuf))) {
    LOG("authentication failure\n%s\n", str);
    LOG("   for request%s\n", full_request);
    END(CAS_BAD_TICKET);
  }

  // retrieve the NetID
  if (!element_body(str, "cas:user", 1, netid, sizeof(netid))) {
    LOG("unable to determine username%s\n", "");
    END(CAS_PROTOCOL_FAILURE);
  }


  // check the first proxy (if present)
  if ((config->proxies) && (config->proxies[0]))
    if (element_body(str, "cas:proxies", 1, parsebuf, sizeof(parsebuf)))
      if (element_body(str, "cas:proxy", 1, parsebuf, sizeof(parsebuf)))
        if (!arrayContains(config->proxies, parsebuf)) {
          LOG("bad proxy: %s\n", parsebuf);
          END(CAS_BAD_PROXY);
        }

  /*
   * without enough space, fail entirely, since a partial NetID could
   * be dangerous
   */
  if (outbuflen < strlen(netid) + 1) 
  {
    LOG("output buffer too short%s\n", "");
    END(CAS_PROTOCOL_FAILURE);
  }

  strcpy(outbuf, netid);
  SUCCEED;

   /* cleanup and return */

end:
  if (ctx)
    SSL_CTX_free(ctx);
  if (bio)
    BIO_free_all(bio);
  if (full_request)
    free(full_request);
  return ret;
}

// returns 1 if a char* array contains the given element, 0 otherwise
static int arrayContains(char *array[], char *element) {
  char *p;
  int i = 0;

  for (p = array[0]; p; p = array[++i]) {
    LOG("  checking element %s\n", p);
    if (!strcmp(p, element))
      return 1;
  }
  return 0;
}
