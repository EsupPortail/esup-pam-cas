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

/* Simple XML pseudo-parsing logic. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
int main(int argc, char **argv) {
  char *s = "<cas:a><cas:b><cas:c>one</cas:c></cas:b><cas:c>two</cas:c><cas:c>three</cas:c></cas:a>";
  char buf[1024];
  printf("%s\n", element_body(s, "c", 1, buf, sizeof(buf)));
  printf("%s\n", element_body(s, "c", 2, buf, sizeof(buf)));
  printf("%s\n", element_body(s, "c", 3, buf, sizeof(buf)));
  printf("%s\n", element_body(s, "a", 1, buf, sizeof(buf)));
}
*/

/*
 * Fills buf (up to buflen characters) with all characters (including
 * those representing other elements) within the nth element in the
 * document with the name provided by tagname.
 */
char *element_body(const char *doc, const char *tagname, int n, char *buf, int buflen) {
  int len = strlen("<cas:>") + strlen(tagname);
  const char *body_start, *body_end, *s;
  char *d0, *d1, *ret;
  char *start_tag_pattern = d0 =  malloc(len + 1);
  char *end_tag_pattern = d1 = malloc(len + 2);

  if (!d0 || !d1)
    goto return_null;

  *d0++ = *d1++ = '<';
  *d1++ = '/';
  *d0++ = *d1++ = 'c';
  *d0++ = *d1++ = 'a';
  *d0++ = *d1++ = 's';
  *d0++ = *d1++ = ':';
  for (s = tagname;*s;) *d0++ = *d1++ = *s++;
  *d0++ = *d1++ = '>';
  *d0 = *d1 = 0;

  body_start = doc;
  while (--n >= 0) {
    body_start = strstr(body_start, start_tag_pattern);
    if (!body_start)
      goto return_null;
    body_start += len;
  }
  body_end = strstr(body_start, end_tag_pattern);
  if (!body_end) {
 return_null:
    ret = NULL;
    goto end;
  }
  if ((len = body_end - body_start) >= buflen)
      len = buflen - 1;
  for (d0 = ret = buf, s = body_start;--len >= 0;) *d0++ = *s++;
  *d0 = 0;

  end:
    if (start_tag_pattern)
      free(start_tag_pattern);
    if (end_tag_pattern)
      free(end_tag_pattern);
    return ret;
}
