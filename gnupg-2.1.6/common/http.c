/* http.c  -  HTTP protocol handler
 * Copyright (C) 1999, 2001, 2002, 2003, 2004, 2006, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 * Copyright (C) 2015 g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Simple HTTP client implementation.  We try to keep the code as
   self-contained as possible.  There are some contraints however:

  - estream is required.  We now require estream because it provides a
    very useful and portable asprintf implementation and the fopencookie
    function.
  - stpcpy is required
  - fixme: list other requirements.


  - With HTTP_USE_NTBTLS or HTTP_USE_GNUTLS support for https is
    provided (this also requires estream).

  - With HTTP_NO_WSASTARTUP the socket initialization is not done
    under Windows.  This is useful if the socket layer has already
    been initialized elsewhere.  This also avoids the installation of
    an exit handler to cleanup the socket layer.
*/

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <time.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /*!HAVE_W32_SYSTEM*/

#ifdef WITHOUT_NPTH /* Give the Makefile a chance to build without Pth.  */
# undef USE_NPTH
#endif

#ifdef USE_NPTH
# include <npth.h>
#endif

#if defined (HTTP_USE_GNUTLS) && defined (HTTP_USE_NTBTLS)
# error Both, HTTP_USE_GNUTLS and HTTP_USE_NTBTLS, are defined.
#endif

#ifdef HTTP_USE_NTBTLS
# include <ntbtls.h>
#elif HTTP_USE_GNUTLS
# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
#endif /*HTTP_USE_GNUTLS*/


#include "util.h"
#include "i18n.h"
#include "http.h"
#ifdef USE_DNS_SRV
# include "srv.h"
#else /*!USE_DNS_SRV*/
  /* If we are not compiling with SRV record support we provide stub
     data structures. */
# ifndef MAXDNAME
#  define MAXDNAME 1025
# endif
struct srventry
{
  unsigned short priority;
  unsigned short weight;
  unsigned short port;
  int run_count;
  char target[MAXDNAME];
};
#endif/*!USE_DNS_SRV*/


#ifdef USE_NPTH
# define my_select(a,b,c,d,e)  npth_select ((a), (b), (c), (d), (e))
# define my_connect(a,b,c)     npth_connect ((a), (b), (c))
# define my_accept(a,b,c)      npth_accept ((a), (b), (c))
#else
# define my_select(a,b,c,d,e)  select ((a), (b), (c), (d), (e))
# define my_connect(a,b,c)     connect ((a), (b), (c))
# define my_accept(a,b,c)      accept ((a), (b), (c))
#endif

#ifdef HAVE_W32_SYSTEM
#define sock_close(a)  closesocket(a)
#else
#define sock_close(a)  close(a)
#endif

#ifndef EAGAIN
#define EAGAIN  EWOULDBLOCK
#endif
#ifndef INADDR_NONE  /* Slowaris is missing that.  */
#define INADDR_NONE  ((unsigned long)(-1))
#endif /*INADDR_NONE*/

#define HTTP_PROXY_ENV           "http_proxy"
#define MAX_LINELEN 20000  /* Max. length of a HTTP header line. */
#define VALID_URI_CHARS "abcdefghijklmnopqrstuvwxyz"   \
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"   \
                        "01234567890@"                 \
                        "!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* A long counter type.  */
#ifdef HAVE_STRTOULL
typedef unsigned long long longcounter_t;
# define counter_strtoul(a) strtoull ((a), NULL, 10)
#else
typedef unsigned long longcounter_t;
# define counter_strtoul(a) strtoul ((a), NULL, 10)
#endif

#if HTTP_USE_NTBTLS
typedef ntbtls_t         tls_session_t;
# define USE_TLS 1
#elif HTTP_USE_GNUTLS
typedef gnutls_session_t tls_session_t;
# define USE_TLS 1
#else
typedef void *tls_session_t;
# undef USE_TLS
#endif

static gpg_err_code_t do_parse_uri (parsed_uri_t uri, int only_local_part,
                                    int no_scheme_check, int force_tls);
static gpg_error_t parse_uri (parsed_uri_t *ret_uri, const char *uri,
                              int no_scheme_check, int force_tls);
static int remove_escapes (char *string);
static int insert_escapes (char *buffer, const char *string,
                           const char *special);
static uri_tuple_t parse_tuple (char *string);
static gpg_error_t send_request (http_t hd, const char *httphost,
                                 const char *auth,const char *proxy,
				 const char *srvtag,strlist_t headers);
static char *build_rel_path (parsed_uri_t uri);
static gpg_error_t parse_response (http_t hd);

static int connect_server (const char *server, unsigned short port,
                           unsigned int flags, const char *srvtag,
                           int *r_host_not_found);
static gpg_error_t write_server (int sock, const char *data, size_t length);

static ssize_t cookie_read (void *cookie, void *buffer, size_t size);
static ssize_t cookie_write (void *cookie, const void *buffer, size_t size);
static int cookie_close (void *cookie);


/* A socket object used to a allow ref counting of sockets.  */
struct my_socket_s
{
  int fd;       /* The actual socket - shall never be -1.  */
  int refcount; /* Number of references to this socket.  */
};
typedef struct my_socket_s *my_socket_t;


/* Cookie function structure and cookie object.  */
static es_cookie_io_functions_t cookie_functions =
  {
    cookie_read,
    cookie_write,
    NULL,
    cookie_close
  };

struct cookie_s
{
  /* Socket object or NULL if already closed. */
  my_socket_t sock;

  /* The session object or NULL if not used. */
  http_session_t session;

  /* True if TLS is to be used.  */
  int use_tls;

  /* The remaining content length and a flag telling whether to use
     the content length.  */
  longcounter_t content_length;
  unsigned int content_length_valid:1;
};
typedef struct cookie_s *cookie_t;

/* The session object. */
struct http_session_s
{
  int refcount;    /* Number of references to this object.  */
#ifdef HTTP_USE_GNUTLS
  gnutls_certificate_credentials_t certcred;
#endif /*HTTP_USE_GNUTLS*/
#ifdef USE_TLS
  tls_session_t tls_session;
  struct {
    int done;      /* Verifciation has been done.  */
    int rc;        /* TLS verification return code.  */
    unsigned int status; /* Verification status.  */
  } verify;
  char *servername; /* Malloced server name.  */
#endif /*USE_TLS*/
  /* A callback function to log details of TLS certifciates.  */
  void (*cert_log_cb) (http_session_t, gpg_error_t, const char *,
                       const void **, size_t *);
};


/* An object to save header lines. */
struct header_s
{
  struct header_s *next;
  char *value;    /* The value of the header (malloced).  */
  char name[1];   /* The name of the header (canonicalized). */
};
typedef struct header_s *header_t;


/* Our handle context. */
struct http_context_s
{
  unsigned int status_code;
  my_socket_t sock;
  unsigned int in_data:1;
  unsigned int is_http_0_9:1;
  estream_t fp_read;
  estream_t fp_write;
  void *write_cookie;
  void *read_cookie;
  http_session_t session;
  parsed_uri_t uri;
  http_req_t req_type;
  char *buffer;          /* Line buffer. */
  size_t buffer_size;
  unsigned int flags;
  header_t headers;      /* Received headers. */
};


/* The global callback for the verification fucntion.  */
static gpg_error_t (*tls_callback) (http_t, http_session_t, int);

/* The list of files with trusted CA certificates.  */
static strlist_t tls_ca_certlist;



#if defined(HAVE_W32_SYSTEM) && !defined(HTTP_NO_WSASTARTUP)

#if GNUPG_MAJOR_VERSION == 1
#define REQ_WINSOCK_MAJOR  1
#define REQ_WINSOCK_MINOR  1
#else
#define REQ_WINSOCK_MAJOR  2
#define REQ_WINSOCK_MINOR  2
#endif


static void
deinit_sockets (void)
{
  WSACleanup();
}

static void
init_sockets (void)
{
  static int initialized;
  static WSADATA wsdata;

  if (initialized)
    return;

  if ( WSAStartup( MAKEWORD (REQ_WINSOCK_MINOR, REQ_WINSOCK_MAJOR), &wsdata ) )
    {
      log_error ("error initializing socket library: ec=%d\n",
                 (int)WSAGetLastError () );
      return;
    }
  if ( LOBYTE(wsdata.wVersion) != REQ_WINSOCK_MAJOR
       || HIBYTE(wsdata.wVersion) != REQ_WINSOCK_MINOR )
    {
      log_error ("socket library version is %x.%x - but %d.%d needed\n",
                 LOBYTE(wsdata.wVersion), HIBYTE(wsdata.wVersion),
                 REQ_WINSOCK_MAJOR, REQ_WINSOCK_MINOR);
      WSACleanup();
      return;
    }
  atexit ( deinit_sockets );
  initialized = 1;
}
#endif /*HAVE_W32_SYSTEM && !HTTP_NO_WSASTARTUP*/


/* Create a new socket object.  Returns NULL and closes FD if not
   enough memory is available.  */
static my_socket_t
_my_socket_new (int lnr, int fd)
{
  my_socket_t so;

  so = xtrymalloc (sizeof *so);
  if (!so)
    {
      int save_errno = errno;
      sock_close (fd);
      gpg_err_set_errno (save_errno);
      return NULL;
    }
  so->fd = fd;
  so->refcount = 1;
  /* log_debug ("http.c:socket_new(%d): object %p for fd %d created\n", */
  /*            lnr, so, so->fd); */
  (void)lnr;
  return so;
}
#define my_socket_new(a) _my_socket_new (__LINE__, (a))

/* Bump up the reference counter for the socket object SO.  */
static my_socket_t
_my_socket_ref (int lnr, my_socket_t so)
{
  so->refcount++;
  /* log_debug ("http.c:socket_ref(%d) object %p for fd %d refcount now %d\n", */
  /*            lnr, so, so->fd, so->refcount); */
  (void)lnr;
  return so;
}
#define my_socket_ref(a) _my_socket_ref (__LINE__,(a))


/* Bump down the reference counter for the socket object SO.  If SO
   has no more references, close the socket and release the
   object.  */
static void
_my_socket_unref (int lnr, my_socket_t so,
                  void (*preclose)(void*), void *preclosearg)
{
  if (so)
    {
      so->refcount--;
      /* log_debug ("http.c:socket_unref(%d): object %p for fd %d ref now %d\n", */
      /*            lnr, so, so->fd, so->refcount); */
      (void)lnr;
      if (!so->refcount)
        {
          if (preclose)
            preclose (preclosearg);
          sock_close (so->fd);
          xfree (so);
        }
    }
}
#define my_socket_unref(a,b,c) _my_socket_unref (__LINE__,(a),(b),(c))


#if defined (USE_NPTH) && defined(HTTP_USE_GNUTLS)
static ssize_t
my_npth_read (gnutls_transport_ptr_t ptr, void *buffer, size_t size)
{
  my_socket_t sock = ptr;
  return npth_read (sock->fd, buffer, size);
}
static ssize_t
my_npth_write (gnutls_transport_ptr_t ptr, const void *buffer, size_t size)
{
  my_socket_t sock = ptr;
  return npth_write (sock->fd, buffer, size);
}
#endif /*USE_NPTH && HTTP_USE_GNUTLS*/




/* This notification function is called by estream whenever stream is
   closed.  Its purpose is to mark the closing in the handle so
   that a http_close won't accidentally close the estream.  The function
   http_close removes this notification so that it won't be called if
   http_close was used before an es_fclose.  */
static void
fp_onclose_notification (estream_t stream, void *opaque)
{
  http_t hd = opaque;

  if (hd->fp_read && hd->fp_read == stream)
    hd->fp_read = NULL;
  else if (hd->fp_write && hd->fp_write == stream)
    hd->fp_write = NULL;
}


/*
 * Helper function to create an HTTP header with hex encoded data.  A
 * new buffer is returned.  This buffer is the concatenation of the
 * string PREFIX, the hex-encoded DATA of length LEN and the string
 * SUFFIX.  On error NULL is returned and ERRNO set.
 */
static char *
make_header_line (const char *prefix, const char *suffix,
                  const void *data, size_t len )
{
  static unsigned char bintoasc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
  const unsigned char *s = data;
  char *buffer, *p;

  buffer = xtrymalloc (strlen (prefix) + (len+2)/3*4 + strlen (suffix) + 1);
  if (!buffer)
    return NULL;
  p = stpcpy (buffer, prefix);
  for ( ; len >= 3 ; len -= 3, s += 3 )
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(((s[0] <<4)&060)|((s[1] >> 4)&017))&077];
      *p++ = bintoasc[(((s[1]<<2)&074)|((s[2]>>6)&03))&077];
      *p++ = bintoasc[s[2]&077];
      *p = 0;
    }
  if ( len == 2 )
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(((s[0] <<4)&060)|((s[1] >> 4)&017))&077];
      *p++ = bintoasc[((s[1]<<2)&074)];
      *p++ = '=';
    }
  else if ( len == 1 )
    {
      *p++ = bintoasc[(s[0] >> 2) & 077];
      *p++ = bintoasc[(s[0] <<4)&060];
      *p++ = '=';
      *p++ = '=';
    }
  *p = 0;
  strcpy (p, suffix);
  return buffer;
}




/* Register a non-standard global TLS callback function.  If no
   verification is desired a callback needs to be registered which
   always returns NULL.  */
void
http_register_tls_callback (gpg_error_t (*cb)(http_t, http_session_t, int))
{
  tls_callback = cb;
}


/* Register a CA certificate for future use.  The certificate is
   expected to be in FNAME.  PEM format is assume if FNAME has a
   suffix of ".pem".  If FNAME is NULL the list of CA files is
   removed.  */
void
http_register_tls_ca (const char *fname)
{
  strlist_t sl;

  if (!fname)
    {
      free_strlist (tls_ca_certlist);
      tls_ca_certlist = NULL;
    }
  else
    {
      sl = add_to_strlist (&tls_ca_certlist, fname);
      if (*sl->d && !strcmp (sl->d + strlen (sl->d) - 4, ".pem"))
        sl->flags = 1;
    }
}


/* Release a session.  Take care not to release it while it is being
   used by a http context object.  */
static void
session_unref (int lnr, http_session_t sess)
{
  if (!sess)
    return;

  sess->refcount--;
  /* log_debug ("http.c:session_unref(%d): sess %p ref now %d\n", */
  /*            lnr, sess, sess->refcount); */
  (void)lnr;
  if (sess->refcount)
    return;

#ifdef USE_TLS
# ifdef HTTP_USE_GNUTLS
  if (sess->tls_session)
    {
      my_socket_t sock = gnutls_transport_get_ptr (sess->tls_session);
      my_socket_unref (sock, NULL, NULL);
      gnutls_deinit (sess->tls_session);
    }
  if (sess->certcred)
    gnutls_certificate_free_credentials (sess->certcred);
# endif /*HTTP_USE_GNUTLS*/
  xfree (sess->servername);
#endif /*USE_TLS*/

  xfree (sess);
}
#define http_session_unref(a) session_unref (__LINE__, (a))

void
http_session_release (http_session_t sess)
{
  http_session_unref (sess);
}


/* Create a new session object which is currently used to enable TLS
   support.  It may eventually allow reusing existing connections.  */
gpg_error_t
http_session_new (http_session_t *r_session, const char *tls_priority)
{
  gpg_error_t err;
  http_session_t sess;

  *r_session = NULL;

  sess = xtrycalloc (1, sizeof *sess);
  if (!sess)
    return gpg_error_from_syserror ();
  sess->refcount = 1;

#if HTTP_USE_NTBTLS
  {
    (void)tls_priority;

    err = ntbtls_new (&sess->tls_session, NTBTLS_CLIENT);
    if (err)
      {
        log_error ("ntbtls_new failed: %s\n", gpg_strerror (err));
        goto leave;
      }
  }
#elif HTTP_USE_GNUTLS
  {
    const char *errpos;
    int rc;
    strlist_t sl;

    rc = gnutls_certificate_allocate_credentials (&sess->certcred);
    if (rc < 0)
      {
        log_error ("gnutls_certificate_allocate_credentials failed: %s\n",
                   gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }

    for (sl = tls_ca_certlist; sl; sl = sl->next)
      {
        rc = gnutls_certificate_set_x509_trust_file
          (sess->certcred, sl->d,
           (sl->flags & 1)? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER);
        if (rc < 0)
          log_info ("setting CA from file '%s' failed: %s\n",
                    sl->d, gnutls_strerror (rc));
      }

    rc = gnutls_init (&sess->tls_session, GNUTLS_CLIENT);
    if (rc < 0)
      {
        log_error ("gnutls_init failed: %s\n", gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }
    /* A new session has the transport ptr set to (void*(-1), we need
       it to be NULL.  */
    gnutls_transport_set_ptr (sess->tls_session, NULL);

    rc = gnutls_priority_set_direct (sess->tls_session,
                                     tls_priority? tls_priority : "NORMAL",
                                     &errpos);
    if (rc < 0)
      {
        log_error ("gnutls_priority_set_direct failed at '%s': %s\n",
                   errpos, gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }

    rc = gnutls_credentials_set (sess->tls_session,
                                 GNUTLS_CRD_CERTIFICATE, sess->certcred);
    if (rc < 0)
      {
        log_error ("gnutls_credentials_set failed: %s\n", gnutls_strerror (rc));
        err = gpg_error (GPG_ERR_GENERAL);
        goto leave;
      }
  }
#else /*!HTTP_USE_GNUTLS*/
  {
    (void)tls_priority;
  }
#endif /*!HTTP_USE_GNUTLS*/

  /* log_debug ("http.c:session_new: sess %p created\n", sess); */
  err = 0;

#if USE_TLS
 leave:
#endif /*USE_TLS*/
  if (err)
    http_session_unref (sess);
  else
    *r_session = sess;

  return err;
}


/* Increment the reference count for session SESS.  Passing NULL for
   SESS is allowed. */
http_session_t
http_session_ref (http_session_t sess)
{
  if (sess)
    {
      sess->refcount++;
      /* log_debug ("http.c:session_ref: sess %p ref now %d\n", sess, */
      /*            sess->refcount); */
    }
  return sess;
}


void
http_session_set_log_cb (http_session_t sess,
                         void (*cb)(http_session_t, gpg_error_t,
                                    const char *hostname,
                                    const void **certs, size_t *certlens))
{
  sess->cert_log_cb = cb;
}




/* Start a HTTP retrieval and on success store at R_HD a context
   pointer for completing the request and to wait for the response.
   If HTTPHOST is not NULL it is used hor the Host header instead of a
   Host header derived from the URL. */
gpg_error_t
http_open (http_t *r_hd, http_req_t reqtype, const char *url,
           const char *httphost,
           const char *auth, unsigned int flags, const char *proxy,
           http_session_t session, const char *srvtag, strlist_t headers)
{
  gpg_error_t err;
  http_t hd;

  *r_hd = NULL;

  if (!(reqtype == HTTP_REQ_GET || reqtype == HTTP_REQ_POST))
    return gpg_err_make (default_errsource, GPG_ERR_INV_ARG);

  /* Create the handle. */
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->req_type = reqtype;
  hd->flags = flags;
  hd->session = http_session_ref (session);

  err = parse_uri (&hd->uri, url, 0, !!(flags & HTTP_FLAG_FORCE_TLS));
  if (!err)
    err = send_request (hd, httphost, auth, proxy, srvtag, headers);

  if (err)
    {
      my_socket_unref (hd->sock, NULL, NULL);
      if (hd->fp_read)
        es_fclose (hd->fp_read);
      if (hd->fp_write)
        es_fclose (hd->fp_write);
      http_session_unref (hd->session);
      xfree (hd);
    }
  else
    *r_hd = hd;
  return err;
}


/* This function is useful to connect to a generic TCP service using
   this http abstraction layer.  This has the advantage of providing
   service tags and an estream interface.  */
gpg_error_t
http_raw_connect (http_t *r_hd, const char *server, unsigned short port,
                  unsigned int flags, const char *srvtag)
{
  gpg_error_t err = 0;
  int sock;
  http_t hd;
  cookie_t cookie;
  int hnf;

  *r_hd = NULL;

  /* Create the handle. */
  hd = xtrycalloc (1, sizeof *hd);
  if (!hd)
    return gpg_error_from_syserror ();
  hd->req_type = HTTP_REQ_OPAQUE;
  hd->flags = flags;

  /* Connect.  */
  sock = connect_server (server, port, hd->flags, srvtag, &hnf);
  if (sock == -1)
    {
      err = gpg_err_make (default_errsource,
                          (hnf? GPG_ERR_UNKNOWN_HOST
                              : gpg_err_code_from_syserror ()));
      xfree (hd);
      return err;
    }
  hd->sock = my_socket_new (sock);
  if (!hd->sock)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      xfree (hd);
      return err;
    }

  /* Setup estreams for reading and writing.  */
  cookie = xtrycalloc (1, sizeof *cookie);
  if (!cookie)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      goto leave;
    }
  cookie->sock = my_socket_ref (hd->sock);
  hd->fp_write = es_fopencookie (cookie, "w", cookie_functions);
  if (!hd->fp_write)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      my_socket_unref (cookie->sock, NULL, NULL);
      xfree (cookie);
      goto leave;
    }
  hd->write_cookie = cookie; /* Cookie now owned by FP_WRITE.  */

  cookie = xtrycalloc (1, sizeof *cookie);
  if (!cookie)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      goto leave;
    }
  cookie->sock = my_socket_ref (hd->sock);
  hd->fp_read = es_fopencookie (cookie, "r", cookie_functions);
  if (!hd->fp_read)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      my_socket_unref (cookie->sock, NULL, NULL);
      xfree (cookie);
      goto leave;
    }
  hd->read_cookie = cookie; /* Cookie now owned by FP_READ.  */

  /* Register close notification to interlock the use of es_fclose in
     http_close and in user code.  */
  err = es_onclose (hd->fp_write, 1, fp_onclose_notification, hd);
  if (!err)
    err = es_onclose (hd->fp_read, 1, fp_onclose_notification, hd);

 leave:
  if (err)
    {
      if (hd->fp_read)
        es_fclose (hd->fp_read);
      if (hd->fp_write)
        es_fclose (hd->fp_write);
      my_socket_unref (hd->sock, NULL, NULL);
      xfree (hd);
    }
  else
    *r_hd = hd;
  return err;
}




void
http_start_data (http_t hd)
{
  if (!hd->in_data)
    {
      es_fputs ("\r\n", hd->fp_write);
      es_fflush (hd->fp_write);
      hd->in_data = 1;
    }
  else
    es_fflush (hd->fp_write);
}


gpg_error_t
http_wait_response (http_t hd)
{
  gpg_error_t err;
  cookie_t cookie;

  /* Make sure that we are in the data. */
  http_start_data (hd);

  /* Close the write stream.  Note that the reference counted socket
     object keeps the actual system socket open.  */
  cookie = hd->write_cookie;
  if (!cookie)
    return gpg_err_make (default_errsource, GPG_ERR_INTERNAL);

  es_fclose (hd->fp_write);
  hd->fp_write = NULL;
  /* The close has released the cookie and thus we better set it to NULL.  */
  hd->write_cookie = NULL;

  /* Shutdown one end of the socket is desired.  As per HTTP/1.0 this
     is not required but some very old servers (e.g. the original pksd
     key server didn't worked without it.  */
  if ((hd->flags & HTTP_FLAG_SHUTDOWN))
    shutdown (hd->sock->fd, 1);
  hd->in_data = 0;

  /* Create a new cookie and a stream for reading.  */
  cookie = xtrycalloc (1, sizeof *cookie);
  if (!cookie)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
  cookie->sock = my_socket_ref (hd->sock);
  cookie->session = http_session_ref (hd->session);
  cookie->use_tls = hd->uri->use_tls;

  hd->read_cookie = cookie;
  hd->fp_read = es_fopencookie (cookie, "r", cookie_functions);
  if (!hd->fp_read)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      my_socket_unref (cookie->sock, NULL, NULL);
      http_session_unref (cookie->session);
      xfree (cookie);
      hd->read_cookie = NULL;
      return err;
    }

  err = parse_response (hd);

  if (!err)
    err = es_onclose (hd->fp_read, 1, fp_onclose_notification, hd);

  return err;
}


/* Convenience function to send a request and wait for the response.
   Closes the handle on error.  If PROXY is not NULL, this value will
   be used as an HTTP proxy and any enabled $http_proxy gets
   ignored. */
gpg_error_t
http_open_document (http_t *r_hd, const char *document,
                    const char *auth, unsigned int flags, const char *proxy,
                    http_session_t session,
                    const char *srvtag, strlist_t headers)
{
  gpg_error_t err;

  err = http_open (r_hd, HTTP_REQ_GET, document, NULL, auth, flags,
                   proxy, session, srvtag, headers);
  if (err)
    return err;

  err = http_wait_response (*r_hd);
  if (err)
    http_close (*r_hd, 0);

  return err;
}


void
http_close (http_t hd, int keep_read_stream)
{
  if (!hd)
    return;

  /* First remove the close notifications for the streams.  */
  if (hd->fp_read)
    es_onclose (hd->fp_read, 0, fp_onclose_notification, hd);
  if (hd->fp_write)
    es_onclose (hd->fp_write, 0, fp_onclose_notification, hd);

  /* Now we can close the streams.  */
  my_socket_unref (hd->sock, NULL, NULL);
  if (hd->fp_read && !keep_read_stream)
    es_fclose (hd->fp_read);
  if (hd->fp_write)
    es_fclose (hd->fp_write);
  http_session_unref (hd->session);
  http_release_parsed_uri (hd->uri);
  while (hd->headers)
    {
      header_t tmp = hd->headers->next;
      xfree (hd->headers->value);
      xfree (hd->headers);
      hd->headers = tmp;
    }
  xfree (hd->buffer);
  xfree (hd);
}


estream_t
http_get_read_ptr (http_t hd)
{
  return hd?hd->fp_read:NULL;
}

estream_t
http_get_write_ptr (http_t hd)
{
  return hd?hd->fp_write:NULL;
}

unsigned int
http_get_status_code (http_t hd)
{
  return hd?hd->status_code:0;
}

/* Return information pertaining to TLS.  If TLS is not in use for HD,
   NULL is returned.  WHAT is used ask for specific information:

     (NULL) := Only check whether TLS is is use.  Returns an
               unspecified string if TLS is in use.  That string may
               even be the empty string.
 */
const char *
http_get_tls_info (http_t hd, const char *what)
{
  (void)what;

  if (!hd)
    return NULL;

  return hd->uri->use_tls? "":NULL;
}



static gpg_error_t
parse_uri (parsed_uri_t *ret_uri, const char *uri,
           int no_scheme_check, int force_tls)
{
  gpg_err_code_t ec;

  *ret_uri = xtrycalloc (1, sizeof **ret_uri + strlen (uri));
  if (!*ret_uri)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
  strcpy ((*ret_uri)->buffer, uri);
  ec = do_parse_uri (*ret_uri, 0, no_scheme_check, force_tls);
  if (ec)
    {
      xfree (*ret_uri);
      *ret_uri = NULL;
    }
  return gpg_err_make (default_errsource, ec);
}


/*
 * Parse an URI and put the result into the newly allocated RET_URI.
 * On success the caller must use http_release_parsed_uri() to
 * releases the resources.  If NO_SCHEME_CHECK is set, the function
 * tries to parse the URL in the same way it would do for an HTTP
 * style URI.
 */
gpg_error_t
http_parse_uri (parsed_uri_t *ret_uri, const char *uri,
                int no_scheme_check)
{
  return parse_uri (ret_uri, uri, no_scheme_check, 0);
}


void
http_release_parsed_uri (parsed_uri_t uri)
{
  if (uri)
    {
      uri_tuple_t r, r2;

      for (r = uri->query; r; r = r2)
	{
	  r2 = r->next;
	  xfree (r);
	}
      xfree (uri);
    }
}


static gpg_err_code_t
do_parse_uri (parsed_uri_t uri, int only_local_part,
              int no_scheme_check, int force_tls)
{
  uri_tuple_t *tail;
  char *p, *p2, *p3, *pp;
  int n;

  p = uri->buffer;
  n = strlen (uri->buffer);

  /* Initialize all fields to an empty string or an empty list. */
  uri->scheme = uri->host = uri->path = p + n;
  uri->port = 0;
  uri->params = uri->query = NULL;
  uri->use_tls = 0;
  uri->is_http = 0;
  uri->opaque = 0;
  uri->v6lit = 0;

  /* A quick validity check. */
  if (strspn (p, VALID_URI_CHARS) != n)
    return GPG_ERR_BAD_URI;	/* Invalid characters found. */

  if (!only_local_part)
    {
      /* Find the scheme. */
      if (!(p2 = strchr (p, ':')) || p2 == p)
	return GPG_ERR_BAD_URI; /* No scheme. */
      *p2++ = 0;
      for (pp=p; *pp; pp++)
       *pp = tolower (*(unsigned char*)pp);
      uri->scheme = p;
      if (!strcmp (uri->scheme, "http") && !force_tls)
        {
          uri->port = 80;
          uri->is_http = 1;
        }
      else if (!strcmp (uri->scheme, "hkp") && !force_tls)
        {
          uri->port = 11371;
          uri->is_http = 1;
        }
#ifdef USE_TLS
      else if (!strcmp (uri->scheme, "https") || !strcmp (uri->scheme,"hkps")
               || (force_tls && (!strcmp (uri->scheme, "http")
                                 || !strcmp (uri->scheme,"hkp"))))
        {
          uri->port = 443;
          uri->is_http = 1;
          uri->use_tls = 1;
        }
#endif /*USE_TLS*/
      else if (!no_scheme_check)
	return GPG_ERR_INV_URI; /* Unsupported scheme */

      p = p2;

      if (*p == '/' && p[1] == '/' ) /* There seems to be a hostname. */
	{
          p += 2;
	  if ((p2 = strchr (p, '/')))
	    *p2++ = 0;

          /* Check for username/password encoding */
          if ((p3 = strchr (p, '@')))
            {
              uri->auth = p;
              *p3++ = '\0';
              p = p3;
            }

          for (pp=p; *pp; pp++)
            *pp = tolower (*(unsigned char*)pp);

	  /* Handle an IPv6 literal */
	  if( *p == '[' && (p3=strchr( p, ']' )) )
	    {
	      *p3++ = '\0';
	      /* worst case, uri->host should have length 0, points to \0 */
	      uri->host = p + 1;
              uri->v6lit = 1;
	      p = p3;
	    }
	  else
	    uri->host = p;

	  if ((p3 = strchr (p, ':')))
	    {
	      *p3++ = '\0';
	      uri->port = atoi (p3);
	    }

	  if ((n = remove_escapes (uri->host)) < 0)
	    return GPG_ERR_BAD_URI;
	  if (n != strlen (uri->host))
	    return GPG_ERR_BAD_URI;	/* Hostname incudes a Nul. */
	  p = p2 ? p2 : NULL;
	}
      else if (uri->is_http)
	return GPG_ERR_INV_URI; /* No Leading double slash for HTTP.  */
      else
        {
          uri->opaque = 1;
          uri->path = p;
          return 0;
        }

    } /* End global URI part. */

  /* Parse the pathname part */
  if (!p || !*p)
    return 0;  /* We don't have a path.  Okay. */

  /* TODO: Here we have to check params. */

  /* Do we have a query part? */
  if ((p2 = strchr (p, '?')))
    *p2++ = 0;

  uri->path = p;
  if ((n = remove_escapes (p)) < 0)
    return GPG_ERR_BAD_URI;
  if (n != strlen (p))
    return GPG_ERR_BAD_URI;	/* Path includes a Nul. */
  p = p2 ? p2 : NULL;

  if (!p || !*p)
    return 0; /* We don't have a query string.  Okay. */

  /* Now parse the query string. */
  tail = &uri->query;
  for (;;)
    {
      uri_tuple_t elem;

      if ((p2 = strchr (p, '&')))
	*p2++ = 0;
      if (!(elem = parse_tuple (p)))
	return GPG_ERR_BAD_URI;
      *tail = elem;
      tail = &elem->next;

      if (!p2)
	break; /* Ready. */
      p = p2;
    }

  return 0;
}


/*
 * Remove all %xx escapes; this is done in-place.  Returns: New length
 * of the string.
 */
static int
remove_escapes (char *string)
{
  int n = 0;
  unsigned char *p, *s;

  for (p = s = (unsigned char*)string; *s; s++)
    {
      if (*s == '%')
	{
	  if (s[1] && s[2] && isxdigit (s[1]) && isxdigit (s[2]))
	    {
	      s++;
	      *p = *s >= '0' && *s <= '9' ? *s - '0' :
		*s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
	      *p <<= 4;
	      s++;
	      *p |= *s >= '0' && *s <= '9' ? *s - '0' :
		*s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : *s - 'a' + 10;
	      p++;
	      n++;
	    }
	  else
	    {
	      *p++ = *s++;
	      if (*s)
		*p++ = *s++;
	      if (*s)
		*p++ = *s++;
	      if (*s)
		*p = 0;
	      return -1; /* Bad URI. */
	    }
	}
      else
	{
	  *p++ = *s;
	  n++;
	}
    }
  *p = 0; /* Make sure to keep a string terminator. */
  return n;
}


/* If SPECIAL is NULL this function escapes in forms mode.  */
static size_t
escape_data (char *buffer, const void *data, size_t datalen,
             const char *special)
{
  int forms = !special;
  const unsigned char *s;
  size_t n = 0;

  if (forms)
    special = "%;?&=";

  for (s = data; datalen; s++, datalen--)
    {
      if (forms && *s == ' ')
        {
	  if (buffer)
	    *buffer++ = '+';
	  n++;
        }
      else if (forms && *s == '\n')
        {
	  if (buffer)
	    memcpy (buffer, "%0D%0A", 6);
	  n += 6;
        }
      else if (forms && *s == '\r' && datalen > 1 && s[1] == '\n')
        {
	  if (buffer)
	    memcpy (buffer, "%0D%0A", 6);
	  n += 6;
          s++;
          datalen--;
        }
      else if (strchr (VALID_URI_CHARS, *s) && !strchr (special, *s))
	{
	  if (buffer)
	    *(unsigned char*)buffer++ = *s;
	  n++;
	}
      else
	{
	  if (buffer)
	    {
	      snprintf (buffer, 4, "%%%02X", *s);
	      buffer += 3;
	    }
	  n += 3;
	}
    }
  return n;
}


static int
insert_escapes (char *buffer, const char *string,
		const char *special)
{
  return escape_data (buffer, string, strlen (string), special);
}


/* Allocate a new string from STRING using standard HTTP escaping as
   well as escaping of characters given in SPECIALS.  A common pattern
   for SPECIALS is "%;?&=". However it depends on the needs, for
   example "+" and "/: often needs to be escaped too.  Returns NULL on
   failure and sets ERRNO.  If SPECIAL is NULL a dedicated forms
   encoding mode is used. */
char *
http_escape_string (const char *string, const char *specials)
{
  int n;
  char *buf;

  n = insert_escapes (NULL, string, specials);
  buf = xtrymalloc (n+1);
  if (buf)
    {
      insert_escapes (buf, string, specials);
      buf[n] = 0;
    }
  return buf;
}

/* Allocate a new string from {DATA,DATALEN} using standard HTTP
   escaping as well as escaping of characters given in SPECIALS.  A
   common pattern for SPECIALS is "%;?&=".  However it depends on the
   needs, for example "+" and "/: often needs to be escaped too.
   Returns NULL on failure and sets ERRNO.  If SPECIAL is NULL a
   dedicated forms encoding mode is used. */
char *
http_escape_data (const void *data, size_t datalen, const char *specials)
{
  int n;
  char *buf;

  n = escape_data (NULL, data, datalen, specials);
  buf = xtrymalloc (n+1);
  if (buf)
    {
      escape_data (buf, data, datalen, specials);
      buf[n] = 0;
    }
  return buf;
}


static uri_tuple_t
parse_tuple (char *string)
{
  char *p = string;
  char *p2;
  int n;
  uri_tuple_t tuple;

  if ((p2 = strchr (p, '=')))
    *p2++ = 0;
  if ((n = remove_escapes (p)) < 0)
    return NULL; /* Bad URI. */
  if (n != strlen (p))
    return NULL; /* Name with a Nul in it. */
  tuple = xtrycalloc (1, sizeof *tuple);
  if (!tuple)
    return NULL; /* Out of core. */
  tuple->name = p;
  if (!p2) /* We have only the name, so we assume an empty value string. */
    {
      tuple->value = p + strlen (p);
      tuple->valuelen = 0;
      tuple->no_value = 1; /* Explicitly mark that we have seen no '='. */
    }
  else /* Name and value. */
    {
      if ((n = remove_escapes (p2)) < 0)
	{
	  xfree (tuple);
	  return NULL; /* Bad URI. */
	}
      tuple->value = p2;
      tuple->valuelen = n;
    }
  return tuple;
}


/* Return true if STRING is likely "hostname:port" or only "hostname".  */
static int
is_hostname_port (const char *string)
{
  int colons = 0;

  if (!string || !*string)
    return 0;
  for (; *string; string++)
    {
      if (*string == ':')
        {
          if (colons)
            return 0;
          if (!string[1])
            return 0;
          colons++;
        }
      else if (!colons && strchr (" \t\f\n\v_@[]/", *string))
        return 0; /* Invalid characters in hostname. */
      else if (colons && !digitp (string))
        return 0; /* Not a digit in the port.  */
    }
  return 1;
}


/*
 * Send a HTTP request to the server
 * Returns 0 if the request was successful
 */
static gpg_error_t
send_request (http_t hd, const char *httphost, const char *auth,
	      const char *proxy, const char *srvtag, strlist_t headers)
{
  gpg_error_t err;
  const char *server;
  char *request, *p;
  unsigned short port;
  const char *http_proxy = NULL;
  char *proxy_authstr = NULL;
  char *authstr = NULL;
  int sock;
  int hnf;

  if (hd->uri->use_tls && !hd->session)
    {
      log_error ("TLS requested but no session object provided\n");
      return gpg_err_make (default_errsource, GPG_ERR_INTERNAL);
    }
#ifdef USE_TLS
  if (hd->uri->use_tls && !hd->session->tls_session)
    {
      log_error ("TLS requested but no GNUTLS context available\n");
      return gpg_err_make (default_errsource, GPG_ERR_INTERNAL);
    }
#endif /*USE_TLS*/

  server = *hd->uri->host ? hd->uri->host : "localhost";
  port = hd->uri->port ? hd->uri->port : 80;

  /* Try to use SNI.  */
#ifdef USE_TLS
  if (hd->uri->use_tls)
    {
# if HTTP_USE_GNUTLS
      int rc;
# endif

      xfree (hd->session->servername);
      hd->session->servername = xtrystrdup (httphost? httphost : server);
      if (!hd->session->servername)
        {
          err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
          return err;
        }

# if HTTP_USE_NTBTLS
      err = ntbtls_set_hostname (hd->session->tls_session,
                                 hd->session->servername);
      if (err)
        {
          log_info ("ntbtls_set_hostname failed: %s\n", gpg_strerror (err));
          return err;
        }
# elif HTTP_USE_GNUTLS
      rc = gnutls_server_name_set (hd->session->tls_session,
                                   GNUTLS_NAME_DNS,
                                   hd->session->servername,
                                   strlen (hd->session->servername));
      if (rc < 0)
        log_info ("gnutls_server_name_set failed: %s\n", gnutls_strerror (rc));
# endif /*HTTP_USE_GNUTLS*/
    }
#endif /*USE_TLS*/

  if ( (proxy && *proxy)
       || ( (hd->flags & HTTP_FLAG_TRY_PROXY)
            && (http_proxy = getenv (HTTP_PROXY_ENV))
            && *http_proxy ))
    {
      parsed_uri_t uri;
      int save_errno;

      if (proxy)
	http_proxy = proxy;

      err = parse_uri (&uri, http_proxy, 1, 0);
      if (gpg_err_code (err) == GPG_ERR_INV_URI
          && is_hostname_port (http_proxy))
        {
          /* Retry assuming a "hostname:port" string.  */
          char *tmpname = strconcat ("http://", http_proxy, NULL);
          if (tmpname && !parse_uri (&uri, tmpname, 0, 0))
            err = 0;
          xfree (tmpname);
        }

      if (err)
        ;
      else if (!strcmp (uri->scheme, "http") || !strcmp (uri->scheme, "socks4"))
        ;
      else if (!strcmp (uri->scheme, "socks5h"))
        err = gpg_err_make (default_errsource, GPG_ERR_NOT_IMPLEMENTED);
      else
        err = gpg_err_make (default_errsource, GPG_ERR_INV_URI);

      if (err)
	{
	  log_error ("invalid HTTP proxy (%s): %s\n",
		     http_proxy, gpg_strerror (err));
	  return gpg_err_make (default_errsource, GPG_ERR_CONFIGURATION);
	}

      if (uri->auth)
        {
          remove_escapes (uri->auth);
          proxy_authstr = make_header_line ("Proxy-Authorization: Basic ",
                                            "\r\n",
                                            uri->auth, strlen(uri->auth));
          if (!proxy_authstr)
            {
              err = gpg_err_make (default_errsource,
                                  gpg_err_code_from_syserror ());
              http_release_parsed_uri (uri);
              return err;
            }
        }

      sock = connect_server (*uri->host ? uri->host : "localhost",
                             uri->port ? uri->port : 80,
                             hd->flags, srvtag, &hnf);
      save_errno = errno;
      http_release_parsed_uri (uri);
      if (sock == -1)
        gpg_err_set_errno (save_errno);
    }
  else
    {
      sock = connect_server (server, port, hd->flags, srvtag, &hnf);
    }

  if (sock == -1)
    {
      xfree (proxy_authstr);
      return gpg_err_make (default_errsource,
                           (hnf? GPG_ERR_UNKNOWN_HOST
                               : gpg_err_code_from_syserror ()));
    }
  hd->sock = my_socket_new (sock);
  if (!hd->sock)
    {
      xfree (proxy_authstr);
      return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
    }



#if HTTP_USE_NTBTLS
  if (hd->uri->use_tls)
    {
      my_socket_ref (hd->sock);

      while ((err = ntbtls_handshake (hd->session->tls_session)))
        {
          switch (err)
            {
            default:
              log_info ("TLS handshake failed: %s <%s>\n",
                        gpg_strerror (err), gpg_strsource (err));
              xfree (proxy_authstr);
              return err;
            }
        }

      hd->session->verify.done = 0;
      if (tls_callback)
        err = tls_callback (hd, hd->session, 0);
      else
        err = http_verify_server_credentials (hd->session);
      if (err)
        {
          log_info ("TLS connection authentication failed: %s <%s>\n",
                    gpg_strerror (err), gpg_strsource (err));
          xfree (proxy_authstr);
          return err;
        }
    }
#elif HTTP_USE_GNUTLS
  if (hd->uri->use_tls)
    {
      int rc;

      my_socket_ref (hd->sock);
      gnutls_transport_set_ptr (hd->session->tls_session, hd->sock);
#ifdef USE_NPTH
      gnutls_transport_set_pull_function (hd->session->tls_session,
                                          my_npth_read);
      gnutls_transport_set_push_function (hd->session->tls_session,
                                          my_npth_write);
#endif

      do
        {
          rc = gnutls_handshake (hd->session->tls_session);
        }
      while (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN);
      if (rc < 0)
        {
          if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED
              || rc == GNUTLS_E_FATAL_ALERT_RECEIVED)
            {
              gnutls_alert_description_t alertno;
              const char *alertstr;

              alertno = gnutls_alert_get (hd->session->tls_session);
              alertstr = gnutls_alert_get_name (alertno);
              log_info ("TLS handshake failed: %s (alert %d)\n",
                        alertstr, (int)alertno);
              if (alertno == GNUTLS_A_UNRECOGNIZED_NAME && server)
                log_info ("  (sent server name '%s')\n", server);
            }
          else
            log_info ("TLS handshake failed: %s\n", gnutls_strerror (rc));
          xfree (proxy_authstr);
          return gpg_err_make (default_errsource, GPG_ERR_NETWORK);
        }

      hd->session->verify.done = 0;
      if (tls_callback)
        err = tls_callback (hd, hd->session, 0);
      else
        err = http_verify_server_credentials (hd->session);
      if (err)
        {
          log_info ("TLS connection authentication failed: %s\n",
                    gpg_strerror (err));
          xfree (proxy_authstr);
          return err;
        }
    }
#endif /*HTTP_USE_GNUTLS*/

  if (auth || hd->uri->auth)
    {
      char *myauth;

      if (auth)
        {
          myauth = xtrystrdup (auth);
          if (!myauth)
            {
              xfree (proxy_authstr);
              return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
            }
          remove_escapes (myauth);
        }
      else
        {
          remove_escapes (hd->uri->auth);
          myauth = hd->uri->auth;
        }

      authstr = make_header_line ("Authorization: Basic ", "\r\n",
                                  myauth, strlen (myauth));
      if (auth)
        xfree (myauth);

      if (!authstr)
        {
          xfree (proxy_authstr);
          return gpg_err_make (default_errsource,
                               gpg_err_code_from_syserror ());
        }
    }

  p = build_rel_path (hd->uri);
  if (!p)
    return gpg_err_make (default_errsource, gpg_err_code_from_syserror ());

  if (http_proxy && *http_proxy)
    {
      request = es_bsprintf
        ("%s %s://%s:%hu%s%s HTTP/1.0\r\n%s%s",
         hd->req_type == HTTP_REQ_GET ? "GET" :
         hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
         hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
         hd->uri->use_tls? "https" : "http",
         httphost? httphost : server,
         port, *p == '/' ? "" : "/", p,
         authstr ? authstr : "",
         proxy_authstr ? proxy_authstr : "");
    }
  else
    {
      char portstr[35];

      if (port == 80)
        *portstr = 0;
      else
        snprintf (portstr, sizeof portstr, ":%u", port);

      request = es_bsprintf
        ("%s %s%s HTTP/1.0\r\nHost: %s%s\r\n%s",
         hd->req_type == HTTP_REQ_GET ? "GET" :
         hd->req_type == HTTP_REQ_HEAD ? "HEAD" :
         hd->req_type == HTTP_REQ_POST ? "POST" : "OOPS",
         *p == '/' ? "" : "/", p,
         httphost? httphost : server,
         portstr,
         authstr? authstr:"");
    }
  xfree (p);
  if (!request)
    {
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
      xfree (authstr);
      xfree (proxy_authstr);
      return err;
    }

  /* log_debug ("request:\n%s\nEND request\n", request); */

  /* First setup estream so that we can write even the first line
     using estream.  This is also required for the sake of gnutls. */
  {
    cookie_t cookie;

    cookie = xtrycalloc (1, sizeof *cookie);
    if (!cookie)
      {
        err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
        goto leave;
      }
    cookie->sock = my_socket_ref (hd->sock);
    hd->write_cookie = cookie;
    cookie->use_tls = hd->uri->use_tls;
    cookie->session = http_session_ref (hd->session);

    hd->fp_write = es_fopencookie (cookie, "w", cookie_functions);
    if (!hd->fp_write)
      {
        err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
        my_socket_unref (cookie->sock, NULL, NULL);
        xfree (cookie);
        hd->write_cookie = NULL;
      }
    else if (es_fputs (request, hd->fp_write) || es_fflush (hd->fp_write))
      err = gpg_err_make (default_errsource, gpg_err_code_from_syserror ());
    else
      err = 0;

  if (!err)
    {
      for (;headers; headers=headers->next)
        {
          if ((es_fputs (headers->d, hd->fp_write) || es_fflush (hd->fp_write))
              || (es_fputs("\r\n",hd->fp_write) || es_fflush(hd->fp_write)))
            {
              err = gpg_err_make (default_errsource,
                                  gpg_err_code_from_syserror ());
              break;
            }
        }
    }
  }

 leave:
  es_free (request);
  xfree (authstr);
  xfree (proxy_authstr);

  return err;
}


/*
 * Build the relative path from the parsed URI.  Minimal
 * implementation.  May return NULL in case of memory failure; errno
 * is then set accordingly.
 */
static char *
build_rel_path (parsed_uri_t uri)
{
  uri_tuple_t r;
  char *rel_path, *p;
  int n;

  /* Count the needed space. */
  n = insert_escapes (NULL, uri->path, "%;?&");
  /* TODO: build params. */
  for (r = uri->query; r; r = r->next)
    {
      n++; /* '?'/'&' */
      n += insert_escapes (NULL, r->name, "%;?&=");
      if (!r->no_value)
	{
	  n++; /* '=' */
	  n += insert_escapes (NULL, r->value, "%;?&=");
	}
    }
  n++;

  /* Now allocate and copy. */
  p = rel_path = xtrymalloc (n);
  if (!p)
    return NULL;
  n = insert_escapes (p, uri->path, "%;?&");
  p += n;
  /* TODO: add params. */
  for (r = uri->query; r; r = r->next)
    {
      *p++ = r == uri->query ? '?' : '&';
      n = insert_escapes (p, r->name, "%;?&=");
      p += n;
      if (!r->no_value)
	{
	  *p++ = '=';
	  /* TODO: Use valuelen. */
	  n = insert_escapes (p, r->value, "%;?&=");
	  p += n;
	}
    }
  *p = 0;
  return rel_path;
}


/* Transform a header name into a standard capitalized format; e.g.
   "Content-Type".  Conversion stops at the colon.  As usual we don't
   use the localized versions of ctype.h. */
static void
capitalize_header_name (char *name)
{
  int first = 1;

  for (; *name && *name != ':'; name++)
    {
      if (*name == '-')
        first = 1;
      else if (first)
        {
          if (*name >= 'a' && *name <= 'z')
            *name = *name - 'a' + 'A';
          first = 0;
        }
      else if (*name >= 'A' && *name <= 'Z')
        *name = *name - 'A' + 'a';
    }
}


/* Store an HTTP header line in LINE away.  Line continuation is
   supported as well as merging of headers with the same name. This
   function may modify LINE. */
static gpg_err_code_t
store_header (http_t hd, char *line)
{
  size_t n;
  char *p, *value;
  header_t h;

  n = strlen (line);
  if (n && line[n-1] == '\n')
    {
      line[--n] = 0;
      if (n && line[n-1] == '\r')
        line[--n] = 0;
    }
  if (!n)  /* we are never called to hit this. */
    return GPG_ERR_BUG;
  if (*line == ' ' || *line == '\t')
    {
      /* Continuation. This won't happen too often as it is not
         recommended.  We use a straightforward implementaion. */
      if (!hd->headers)
        return GPG_ERR_PROTOCOL_VIOLATION;
      n += strlen (hd->headers->value);
      p = xtrymalloc (n+1);
      if (!p)
        return gpg_err_code_from_syserror ();
      strcpy (stpcpy (p, hd->headers->value), line);
      xfree (hd->headers->value);
      hd->headers->value = p;
      return 0;
    }

  capitalize_header_name (line);
  p = strchr (line, ':');
  if (!p)
    return GPG_ERR_PROTOCOL_VIOLATION;
  *p++ = 0;
  while (*p == ' ' || *p == '\t')
    p++;
  value = p;

  for (h=hd->headers; h; h = h->next)
    if ( !strcmp (h->name, line) )
      break;
  if (h)
    {
      /* We have already seen a line with that name.  Thus we assume
         it is a comma separated list and merge them.  */
      p = xtrymalloc (strlen (h->value) + 1 + strlen (value)+ 1);
      if (!p)
        return gpg_err_code_from_syserror ();
      strcpy (stpcpy (stpcpy (p, h->value), ","), value);
      xfree (h->value);
      h->value = p;
      return 0;
    }

  /* Append a new header. */
  h = xtrymalloc (sizeof *h + strlen (line));
  if (!h)
    return gpg_err_code_from_syserror ();
  strcpy (h->name, line);
  h->value = xtrymalloc (strlen (value)+1);
  if (!h->value)
    {
      xfree (h);
      return gpg_err_code_from_syserror ();
    }
  strcpy (h->value, value);
  h->next = hd->headers;
  hd->headers = h;

  return 0;
}


/* Return the header NAME from the last response.  The returned value
   is valid as along as HD has not been closed and no other request
   has been send. If the header was not found, NULL is returned.  NAME
   must be canonicalized, that is the first letter of each dash
   delimited part must be uppercase and all other letters lowercase.  */
const char *
http_get_header (http_t hd, const char *name)
{
  header_t h;

  for (h=hd->headers; h; h = h->next)
    if ( !strcmp (h->name, name) )
      return h->value;
  return NULL;
}


/* Return a newly allocated and NULL terminated array with pointers to
   header names.  The array must be released with xfree() and its
   content is only values as long as no other request has been
   send.  */
const char **
http_get_header_names (http_t hd)
{
  const char **array;
  size_t n;
  header_t h;

  for (n=0, h = hd->headers; h; h = h->next)
    n++;
  array = xtrycalloc (n+1, sizeof *array);
  if (array)
    {
      for (n=0, h = hd->headers; h; h = h->next)
        array[n++] = h->name;
    }

  return array;
}


/*
 * Parse the response from a server.
 * Returns: Errorcode and sets some files in the handle
 */
static gpg_err_code_t
parse_response (http_t hd)
{
  char *line, *p, *p2;
  size_t maxlen, len;
  cookie_t cookie = hd->read_cookie;
  const char *s;

  /* Delete old header lines.  */
  while (hd->headers)
    {
      header_t tmp = hd->headers->next;
      xfree (hd->headers->value);
      xfree (hd->headers);
      hd->headers = tmp;
    }

  /* Wait for the status line. */
  do
    {
      maxlen = MAX_LINELEN;
      len = es_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_err_code_from_syserror (); /* Out of core. */
      if (!maxlen)
	return GPG_ERR_TRUNCATED; /* Line has been truncated. */
      if (!len)
	return GPG_ERR_EOF;

      if ((hd->flags & HTTP_FLAG_LOG_RESP))
        log_info ("RESP: '%.*s'\n",
                  (int)strlen(line)-(*line&&line[1]?2:0),line);
    }
  while (!*line);

  if ((p = strchr (line, '/')))
    *p++ = 0;
  if (!p || strcmp (line, "HTTP"))
    return 0; /* Assume http 0.9. */

  if ((p2 = strpbrk (p, " \t")))
    {
      *p2++ = 0;
      p2 += strspn (p2, " \t");
    }
  if (!p2)
    return 0; /* Also assume http 0.9. */
  p = p2;
  /* TODO: Add HTTP version number check. */
  if ((p2 = strpbrk (p, " \t")))
    *p2++ = 0;
  if (!isdigit ((unsigned int)p[0]) || !isdigit ((unsigned int)p[1])
      || !isdigit ((unsigned int)p[2]) || p[3])
    {
      /* Malformed HTTP status code - assume http 0.9. */
      hd->is_http_0_9 = 1;
      hd->status_code = 200;
      return 0;
    }
  hd->status_code = atoi (p);

  /* Skip all the header lines and wait for the empty line. */
  do
    {
      maxlen = MAX_LINELEN;
      len = es_read_line (hd->fp_read, &hd->buffer, &hd->buffer_size, &maxlen);
      line = hd->buffer;
      if (!line)
	return gpg_err_code_from_syserror (); /* Out of core. */
      /* Note, that we can silently ignore truncated lines. */
      if (!len)
	return GPG_ERR_EOF;
      /* Trim line endings of empty lines. */
      if ((*line == '\r' && line[1] == '\n') || *line == '\n')
	*line = 0;
      if ((hd->flags & HTTP_FLAG_LOG_RESP))
        log_info ("RESP: '%.*s'\n",
                  (int)strlen(line)-(*line&&line[1]?2:0),line);
      if (*line)
        {
          gpg_err_code_t ec = store_header (hd, line);
          if (ec)
            return ec;
        }
    }
  while (len && *line);

  cookie->content_length_valid = 0;
  if (!(hd->flags & HTTP_FLAG_IGNORE_CL))
    {
      s = http_get_header (hd, "Content-Length");
      if (s)
        {
          cookie->content_length_valid = 1;
          cookie->content_length = counter_strtoul (s);
        }
    }

  return 0;
}

#if 0
static int
start_server ()
{
  struct sockaddr_in mya;
  struct sockaddr_in peer;
  int fd, client;
  fd_set rfds;
  int addrlen;
  int i;

  if ((fd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      log_error ("socket() failed: %s\n", strerror (errno));
      return -1;
    }
  i = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (byte *) & i, sizeof (i)))
    log_info ("setsockopt(SO_REUSEADDR) failed: %s\n", strerror (errno));

  mya.sin_family = AF_INET;
  memset (&mya.sin_addr, 0, sizeof (mya.sin_addr));
  mya.sin_port = htons (11371);

  if (bind (fd, (struct sockaddr *) &mya, sizeof (mya)))
    {
      log_error ("bind to port 11371 failed: %s\n", strerror (errno));
      sock_close (fd);
      return -1;
    }

  if (listen (fd, 5))
    {
      log_error ("listen failed: %s\n", strerror (errno));
      sock_close (fd);
      return -1;
    }

  for (;;)
    {
      FD_ZERO (&rfds);
      FD_SET (fd, &rfds);

      if (my_select (fd + 1, &rfds, NULL, NULL, NULL) <= 0)
	continue;		/* ignore any errors */

      if (!FD_ISSET (fd, &rfds))
	continue;

      addrlen = sizeof peer;
      client = my_accept (fd, (struct sockaddr *) &peer, &addrlen);
      if (client == -1)
	continue;		/* oops */

      log_info ("connect from %s\n", inet_ntoa (peer.sin_addr));

      fflush (stdout);
      fflush (stderr);
      if (!fork ())
	{
	  int c;
	  FILE *fp;

	  fp = fdopen (client, "r");
	  while ((c = getc (fp)) != EOF)
	    putchar (c);
	  fclose (fp);
	  exit (0);
	}
      sock_close (client);
    }


  return 0;
}
#endif

/* Actually connect to a server.  Returns the file descriptor or -1 on
   error.  ERRNO is set on error. */
static int
connect_server (const char *server, unsigned short port,
                unsigned int flags, const char *srvtag, int *r_host_not_found)
{
  int sock = -1;
  int srvcount = 0;
  int hostfound = 0;
  int anyhostaddr = 0;
  int srv, connected;
  int last_errno = 0;
  struct srventry *serverlist = NULL;
#ifdef HAVE_W32_SYSTEM
  unsigned long inaddr;
#endif

  *r_host_not_found = 0;
#ifdef HAVE_W32_SYSTEM

#ifndef HTTP_NO_WSASTARTUP
  init_sockets ();
#endif
  /* Win32 gethostbyname doesn't handle IP addresses internally, so we
     try inet_addr first on that platform only. */
  inaddr = inet_addr(server);
  if ( inaddr != INADDR_NONE )
    {
      struct sockaddr_in addr;

      memset(&addr,0,sizeof(addr));

      sock = socket(AF_INET,SOCK_STREAM,0);
      if ( sock==INVALID_SOCKET )
	{
	  log_error("error creating socket: ec=%d\n",(int)WSAGetLastError());
	  return -1;
	}

      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      memcpy (&addr.sin_addr,&inaddr,sizeof(inaddr));

      if (!my_connect (sock,(struct sockaddr *)&addr,sizeof(addr)) )
	return sock;
      sock_close(sock);
      return -1;
    }
#endif /*HAVE_W32_SYSTEM*/

#ifdef USE_DNS_SRV
  /* Do the SRV thing */
  if (srvtag)
    {
      /* We're using SRV, so append the tags. */
      if (1+strlen (srvtag) + 6 + strlen (server) + 1 <= MAXDNAME)
	{
	  char srvname[MAXDNAME];

	  stpcpy (stpcpy (stpcpy (stpcpy (srvname,"_"), srvtag),
                           "._tcp."), server);
	  srvcount = getsrv (srvname, &serverlist);
	}
    }
#else
  (void)flags;
  (void)srvtag;
#endif /*USE_DNS_SRV*/

  if (!serverlist)
    {
      /* Either we're not using SRV, or the SRV lookup failed.  Make
	 up a fake SRV record. */
      serverlist = xtrycalloc (1, sizeof *serverlist);
      if (!serverlist)
        return -1; /* Out of core.  */
      serverlist->port = port;
      strncpy (serverlist->target, server, MAXDNAME);
      serverlist->target[MAXDNAME-1] = '\0';
      srvcount = 1;
    }

#ifdef HAVE_GETADDRINFO
  connected = 0;
  for (srv=0; srv < srvcount && !connected; srv++)
    {
      struct addrinfo hints, *res, *ai;
      char portstr[35];

      snprintf (portstr, sizeof portstr, "%hu", port);
      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_STREAM;
      if (getaddrinfo (serverlist[srv].target, portstr, &hints, &res))
        continue; /* Not found - try next one. */
      hostfound = 1;

      for (ai = res; ai && !connected; ai = ai->ai_next)
        {
          if (ai->ai_family == AF_INET && (flags & HTTP_FLAG_IGNORE_IPv4))
            continue;
          if (ai->ai_family == AF_INET6 && (flags & HTTP_FLAG_IGNORE_IPv6))
            continue;

          if (sock != -1)
            sock_close (sock);
          sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
          if (sock == -1)
            {
              int save_errno = errno;
              log_error ("error creating socket: %s\n", strerror (errno));
              freeaddrinfo (res);
              xfree (serverlist);
              errno = save_errno;
              return -1;
            }

          anyhostaddr = 1;
          if (my_connect (sock, ai->ai_addr, ai->ai_addrlen))
            last_errno = errno;
          else
            connected = 1;
        }
      freeaddrinfo (res);
    }
#else /* !HAVE_GETADDRINFO */
  connected = 0;
  for (srv=0; srv < srvcount && !connected; srv++)
    {
      int i;
      struct hostent *host = NULL;
      struct sockaddr_in addr;

      /* Note: This code is not thread-safe.  */

      memset (&addr, 0, sizeof (addr));
      host = gethostbyname (serverlist[srv].target);
      if (!host)
        continue;
      hostfound = 1;

      if (sock != -1)
        sock_close (sock);
      sock = socket (host->h_addrtype, SOCK_STREAM, 0);
      if (sock == -1)
        {
          log_error ("error creating socket: %s\n", strerror (errno));
          xfree (serverlist);
          return -1;
        }

      addr.sin_family = host->h_addrtype;
      if (addr.sin_family != AF_INET)
	{
	  log_error ("unknown address family for '%s'\n",
                     serverlist[srv].target);
          xfree (serverlist);
	  return -1;
	}
      addr.sin_port = htons (serverlist[srv].port);
      if (host->h_length != 4)
        {
          log_error ("illegal address length for '%s'\n",
                     serverlist[srv].target);
          xfree (serverlist);
          return -1;
        }

      /* Try all A records until one responds. */
      for (i = 0; host->h_addr_list[i] && !connected; i++)
        {
          anyhostaddr = 1;
          memcpy (&addr.sin_addr, host->h_addr_list[i], host->h_length);
          if (my_connect (sock, (struct sockaddr *) &addr, sizeof (addr)))
            last_errno = errno;
          else
            {
              connected = 1;
              break;
            }
        }
    }
#endif /* !HAVE_GETADDRINFO */

  xfree (serverlist);

  if (!connected)
    {
      if (!hostfound)
        log_error ("can't connect to '%s': %s\n",
                   server, "host not found");
      else if (!anyhostaddr)
        log_error ("can't connect to '%s': %s\n",
                   server, "no IP address for host");
      else
        {
#ifdef HAVE_W32_SYSTEM
        log_error ("can't connect to '%s': ec=%d\n",
                   server, (int)WSAGetLastError());
#else
        log_error ("can't connect to '%s': %s\n",
                   server, strerror (last_errno));
#endif
        }
      if (!hostfound || (hostfound && !anyhostaddr))
        *r_host_not_found = 1;
      if (sock != -1)
	sock_close (sock);
      gpg_err_set_errno (last_errno);
      return -1;
    }
  return sock;
}


static gpg_error_t
write_server (int sock, const char *data, size_t length)
{
  int nleft;
  int nwritten;

  nleft = length;
  while (nleft > 0)
    {
#if defined(HAVE_W32_SYSTEM)
# if defined(USE_NPTH)
      npth_unprotect ();
# endif
      nwritten = send (sock, data, nleft, 0);
# if defined(USE_NPTH)
      npth_protect ();
# endif
      if ( nwritten == SOCKET_ERROR )
        {
          log_info ("network write failed: ec=%d\n", (int)WSAGetLastError ());
          return gpg_error (GPG_ERR_NETWORK);
        }
#else /*!HAVE_W32_SYSTEM*/
# ifdef USE_NPTH
      nwritten = npth_write (sock, data, nleft);
# else
      nwritten = write (sock, data, nleft);
# endif
      if (nwritten == -1)
	{
	  if (errno == EINTR)
	    continue;
	  if (errno == EAGAIN)
	    {
	      struct timeval tv;

	      tv.tv_sec = 0;
	      tv.tv_usec = 50000;
	      my_select (0, NULL, NULL, NULL, &tv);
	      continue;
	    }
	  log_info ("network write failed: %s\n", strerror (errno));
	  return gpg_error_from_syserror ();
	}
#endif /*!HAVE_W32_SYSTEM*/
      nleft -= nwritten;
      data += nwritten;
    }

  return 0;
}



/* Read handler for estream.  */
static ssize_t
cookie_read (void *cookie, void *buffer, size_t size)
{
  cookie_t c = cookie;
  int nread;

  if (c->content_length_valid)
    {
      if (!c->content_length)
        return 0; /* EOF */
      if (c->content_length < size)
        size = c->content_length;
    }

#ifdef HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
    again:
      nread = gnutls_record_recv (c->session->tls_session, buffer, size);
      if (nread < 0)
        {
          if (nread == GNUTLS_E_INTERRUPTED)
            goto again;
          if (nread == GNUTLS_E_AGAIN)
            {
              struct timeval tv;

              tv.tv_sec = 0;
              tv.tv_usec = 50000;
              my_select (0, NULL, NULL, NULL, &tv);
              goto again;
            }
          if (nread == GNUTLS_E_REHANDSHAKE)
            goto again; /* A client is allowed to just ignore this request. */
          log_info ("TLS network read failed: %s\n", gnutls_strerror (nread));
          gpg_err_set_errno (EIO);
          return -1;
        }
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      do
        {
#ifdef HAVE_W32_SYSTEM
          /* Under Windows we need to use recv for a socket.  */
# if defined(USE_NPTH)
          npth_unprotect ();
# endif
          nread = recv (c->sock->fd, buffer, size, 0);
# if defined(USE_NPTH)
          npth_protect ();
# endif

#else /*!HAVE_W32_SYSTEM*/

# ifdef USE_NPTH
          nread = npth_read (c->sock->fd, buffer, size);
# else
          nread = read (c->sock->fd, buffer, size);
# endif

#endif /*!HAVE_W32_SYSTEM*/
        }
      while (nread == -1 && errno == EINTR);
    }

  if (c->content_length_valid && nread > 0)
    {
      if (nread < c->content_length)
        c->content_length -= nread;
      else
        c->content_length = 0;
    }

  return nread;
}

/* Write handler for estream.  */
static ssize_t
cookie_write (void *cookie, const void *buffer_arg, size_t size)
{
  const char *buffer = buffer_arg;
  cookie_t c = cookie;
  int nwritten = 0;

#ifdef HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    {
      int nleft = size;
      while (nleft > 0)
        {
          nwritten = gnutls_record_send (c->session->tls_session,
                                         buffer, nleft);
          if (nwritten <= 0)
            {
              if (nwritten == GNUTLS_E_INTERRUPTED)
                continue;
              if (nwritten == GNUTLS_E_AGAIN)
                {
                  struct timeval tv;

                  tv.tv_sec = 0;
                  tv.tv_usec = 50000;
                  my_select (0, NULL, NULL, NULL, &tv);
                  continue;
                }
              log_info ("TLS network write failed: %s\n",
                        gnutls_strerror (nwritten));
              gpg_err_set_errno (EIO);
              return -1;
            }
          nleft -= nwritten;
          buffer += nwritten;
        }
    }
  else
#endif /*HTTP_USE_GNUTLS*/
    {
      if ( write_server (c->sock->fd, buffer, size) )
        {
          gpg_err_set_errno (EIO);
          nwritten = -1;
        }
      else
        nwritten = size;
    }

  return nwritten;
}


#ifdef HTTP_USE_GNUTLS
/* Wrapper for gnutls_bye used by my_socket_unref.  */
static void
send_gnutls_bye (void *opaque)
{
  tls_session_t tls_session = opaque;
  int ret;

 again:
  do
    ret = gnutls_bye (tls_session, GNUTLS_SHUT_RDWR);
  while (ret == GNUTLS_E_INTERRUPTED);
  if (ret == GNUTLS_E_AGAIN)
    {
      struct timeval tv;

      tv.tv_sec = 0;
      tv.tv_usec = 50000;
      my_select (0, NULL, NULL, NULL, &tv);
      goto again;
    }
}
#endif /*HTTP_USE_GNUTLS*/

/* Close handler for estream.  */
static int
cookie_close (void *cookie)
{
  cookie_t c = cookie;

  if (!c)
    return 0;

#ifdef HTTP_USE_GNUTLS
  if (c->use_tls && c->session && c->session->tls_session)
    my_socket_unref (c->sock, send_gnutls_bye, c->session->tls_session);
  else
#endif /*HTTP_USE_GNUTLS*/
    if (c->sock)
      my_socket_unref (c->sock, NULL, NULL);

  if (c->session)
    http_session_unref (c->session);
  xfree (c);
  return 0;
}




/* Verify the credentials of the server.  Returns 0 on success and
   store the result in the session object.  */
gpg_error_t
http_verify_server_credentials (http_session_t sess)
{
#if HTTP_USE_NTBTLS
  (void)sess;
  return 0;  /* FIXME!! */
#elif HTTP_USE_GNUTLS
  static const char const errprefix[] = "TLS verification of peer failed";
  int rc;
  unsigned int status;
  const char *hostname;
  const gnutls_datum_t *certlist;
  unsigned int certlistlen;
  gnutls_x509_crt_t cert;
  gpg_error_t err = 0;

  sess->verify.done = 1;
  sess->verify.status = 0;
  sess->verify.rc = GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_certificate_type_get (sess->tls_session) != GNUTLS_CRT_X509)
    {
      log_error ("%s: %s\n", errprefix, "not an X.509 certificate");
      sess->verify.rc = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
      return gpg_error (GPG_ERR_GENERAL);
    }

  rc = gnutls_certificate_verify_peers2 (sess->tls_session, &status);
  if (rc)
    {
      log_error ("%s: %s\n", errprefix, gnutls_strerror (rc));
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }
  else if (status)
    {
      log_error ("%s: status=0x%04x\n", errprefix, status);
#if GNUTLS_VERSION_NUMBER >= 0x030104
      {
        gnutls_datum_t statusdat;

        if (!gnutls_certificate_verification_status_print
            (status, GNUTLS_CRT_X509, &statusdat, 0))
          {
            log_info ("%s: %s\n", errprefix, statusdat.data);
            gnutls_free (statusdat.data);
          }
      }
#endif /*gnutls >= 3.1.4*/

      sess->verify.status = status;
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  hostname = sess->servername;
  if (!hostname || !strchr (hostname, '.'))
    {
      log_error ("%s: %s\n", errprefix, "hostname missing");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  certlist = gnutls_certificate_get_peers (sess->tls_session, &certlistlen);
  if (!certlistlen)
    {
      log_error ("%s: %s\n", errprefix, "server did not send a certificate");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);

      /* Need to stop here.  */
      if (err)
        return err;
    }

  rc = gnutls_x509_crt_init (&cert);
  if (rc < 0)
    {
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      if (err)
        return err;
    }

  rc = gnutls_x509_crt_import (cert, &certlist[0], GNUTLS_X509_FMT_DER);
  if (rc < 0)
    {
      log_error ("%s: %s: %s\n", errprefix, "error importing certificate",
                 gnutls_strerror (rc));
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  if (!gnutls_x509_crt_check_hostname (cert, hostname))
    {
      log_error ("%s: %s\n", errprefix, "hostname does not match");
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
    }

  gnutls_x509_crt_deinit (cert);

  if (!err)
    sess->verify.rc = 0;

  if (sess->cert_log_cb)
    {
      const void *bufarr[10];
      size_t buflenarr[10];
      size_t n;

      for (n = 0; n < certlistlen && n < DIM (bufarr)-1; n++)
        {
          bufarr[n] = certlist[n].data;
          buflenarr[n] = certlist[n].size;
        }
      bufarr[n] = NULL;
      buflenarr[n] = 0;
      sess->cert_log_cb (sess, err, hostname, bufarr, buflenarr);
    }

  return err;
#else /*!HTTP_USE_GNUTLS*/
  (void)sess;
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
#endif
}

/* Return the first query variable with the specified key.  If there
   is no such variable, return NULL.  */
struct uri_tuple_s *
uri_query_lookup (parsed_uri_t uri, const char *key)
{
  struct uri_tuple_s *t;

  for (t = uri->query; t; t = t->next)
    if (strcmp (t->name, key) == 0)
      return t;

  return NULL;
}
