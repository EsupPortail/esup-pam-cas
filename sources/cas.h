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


#define DEFAULT_CONFIG_NAME     "/etc/pam_cas.conf"
#define DEFAULT_URI_VALIDATE    "/proxyValidate"

#define CAS_LEN_NETID          32
#define HTTP_1_1               // a commenter pour http 1.0


/*#################################################################################
    ne pas modifier ce qui suit
#################################################################################*/

#define CAS_METHOD "GET"

#ifdef HTTP_1_1
#  define GENERIC_HEADERS "HTTP/1.1\nConnection: close"
#  define HEADER_HOST_NAME "Host"
#else
#  define GENERIC_HEADERS "HTTP/1.0"
#endif

typedef struct pam_cas_config
{
    char *host;                 // CAS server
    char *port;                 // port TCP from CAS server
    char *uriValidate;          // URI to validate PT or ST
    char *service;              // URL from service
    char *trusted_ca;           // Contents trusted certificate
    char **proxies;             // proxies authorized
    int ssl;                    // http or https
    int debug;                  // debug level
}pam_cas_config_t;


/**
 * Ticket identifiers to avoid needless validating passwords that
 * aren't tickets
 */
#define CAS_BEGIN_PT "PT-"
#define CAS_BEGIN_ST "ST-"


/* Error codes (decided upon by ESUP-Portail group) */
#define CAS_SUCCESS                 0
#define CAS_READCONF_FAILURE        1
#define CAS_ERROR_CONFIG            2
#define CAS_BAD_TICKET              3
#define CAS_ERROR_MEMORY_ALLOC      4
#define CAS_SSL_ERROR_INIT          5
#define CAS_SSL_ERROR_CERT_LOAD     6
#define CAS_SSL_ERROR_CERT_VALID    7
#define CAS_SSL_ERROR_CONN          8
#define CAS_ERROR_CONN              9
#define CAS_ERROR_HTTP              10
#define CAS_PROTOCOL_FAILURE        11
#define CAS_BAD_PROXY               12


/* debug types */
#define DEBUG_NO            0
#define DEBUG_SYSLOG        1
#define DEBUG_LOCAL         2


int cas_validate(
	     char *ticket, char *service, char *outbuf, int outbuflen, pam_cas_config_t *config);

int read_config (const char *configFile, pam_cas_config_t ** presult, int localDebug);
void free_config(pam_cas_config_t ** pstConfig);
char * getErrorMessage(int index);
