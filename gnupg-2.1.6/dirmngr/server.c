/* server.c - LDAP and Keyserver access server
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2003, 2004, 2005, 2007, 2008, 2009, 2011, 2015 g10 Code GmbH
 * Copyright (C) 2014 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "dirmngr.h"
#include <assuan.h>

#include "crlcache.h"
#include "crlfetch.h"
#if USE_LDAP
# include "ldapserver.h"
#endif
#include "ocsp.h"
#include "certcache.h"
#include "validate.h"
#include "misc.h"
#if USE_LDAP
# include "ldap-wrapper.h"
#endif
#include "ks-action.h"
#include "ks-engine.h"  /* (ks_hkp_print_hosttable) */
#if USE_LDAP
# include "ldap-parse-uri.h"
#endif
#include "dns-cert.h"
#include "mbox-util.h"

/* To avoid DoS attacks we limit the size of a certificate to
   something reasonable. */
#define MAX_CERT_LENGTH (8*1024)

/* The same goes for OpenPGP keyblocks, but here we need to allow for
   much longer blocks; a 200k keyblock is not too unusual for keys
   with a lot of signatures (e.g. 0x5b0358a2).  */
#define MAX_KEYBLOCK_LENGTH (512*1024)


#define PARM_ERROR(t) assuan_set_error (ctx, \
                                        gpg_error (GPG_ERR_ASS_PARAMETER), (t))
#define set_error(e,t) assuan_set_error (ctx, gpg_error (e), (t))



/* Control structure per connection. */
struct server_local_s
{
  /* Data used to associate an Assuan context with local server data */
  assuan_context_t assuan_ctx;

  /* Per-session LDAP servers.  */
  ldap_server_t ldapservers;

  /* Per-session list of keyservers.  */
  uri_item_t keyservers;

  /* If this flag is set to true this dirmngr process will be
     terminated after the end of this session.  */
  int stopme;
};


/* Cookie definition for assuan data line output.  */
static ssize_t data_line_cookie_write (void *cookie,
                                       const void *buffer, size_t size);
static int data_line_cookie_close (void *cookie);
static es_cookie_io_functions_t data_line_cookie_functions =
  {
    NULL,
    data_line_cookie_write,
    NULL,
    data_line_cookie_close
  };





/* Accessor for the local ldapservers variable. */
ldap_server_t
get_ldapservers_from_ctrl (ctrl_t ctrl)
{
  if (ctrl && ctrl->server_local)
    return ctrl->server_local->ldapservers;
  else
    return NULL;
}


/* Release all configured keyserver info from CTRL.  */
void
release_ctrl_keyservers (ctrl_t ctrl)
{
  if (! ctrl->server_local)
    return;

  while (ctrl->server_local->keyservers)
    {
      uri_item_t tmp = ctrl->server_local->keyservers->next;
      http_release_parsed_uri (ctrl->server_local->keyservers->parsed_uri);
      xfree (ctrl->server_local->keyservers);
      ctrl->server_local->keyservers = tmp;
    }
}



/* Helper to print a message while leaving a command.  */
static gpg_error_t
leave_cmd (assuan_context_t ctx, gpg_error_t err)
{
  if (err)
    {
      const char *name = assuan_get_command_name (ctx);
      if (!name)
        name = "?";
      if (gpg_err_source (err) == GPG_ERR_SOURCE_DEFAULT)
        log_error ("command '%s' failed: %s\n", name,
                   gpg_strerror (err));
      else
        log_error ("command '%s' failed: %s <%s>\n", name,
                   gpg_strerror (err), gpg_strsource (err));
    }
  return err;
}


/* This is a wrapper around assuan_send_data which makes debugging the
   output in verbose mode easier.  */
static gpg_error_t
data_line_write (assuan_context_t ctx, const void *buffer_arg, size_t size)
{
  const char *buffer = buffer_arg;
  gpg_error_t err;

  if (opt.verbose && buffer && size)
    {
      /* Ease reading of output by sending a physical line at each LF.  */
      const char *p;
      size_t n, nbytes;

      nbytes = size;
      do
        {
          p = memchr (buffer, '\n', nbytes);
          n = p ? (p - buffer) + 1 : nbytes;
          err = assuan_send_data (ctx, buffer, n);
          if (err)
            {
              gpg_err_set_errno (EIO);
              return err;
            }
          buffer += n;
          nbytes -= n;
          if (nbytes && (err=assuan_send_data (ctx, NULL, 0))) /* Flush line. */
            {
              gpg_err_set_errno (EIO);
              return err;
            }
        }
      while (nbytes);
    }
  else
    {
      err = assuan_send_data (ctx, buffer, size);
      if (err)
        {
          gpg_err_set_errno (EIO);  /* For use by data_line_cookie_write.  */
          return err;
        }
    }

  return 0;
}


/* A write handler used by es_fopencookie to write assuan data
   lines.  */
static ssize_t
data_line_cookie_write (void *cookie, const void *buffer, size_t size)
{
  assuan_context_t ctx = cookie;

  if (data_line_write (ctx, buffer, size))
    return -1;
  return (ssize_t)size;
}


static int
data_line_cookie_close (void *cookie)
{
  assuan_context_t ctx = cookie;

  if (assuan_send_data (ctx, NULL, 0))
    {
      gpg_err_set_errno (EIO);
      return -1;
    }

  return 0;
}


/* Copy the % and + escaped string S into the buffer D and replace the
   escape sequences.  Note, that it is sufficient to allocate the
   target string D as long as the source string S, i.e.: strlen(s)+1.
   Note further that if S contains an escaped binary Nul the resulting
   string D will contain the 0 as well as all other characters but it
   will be impossible to know whether this is the original EOS or a
   copied Nul. */
static void
strcpy_escaped_plus (char *d, const unsigned char *s)
{
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          *d++ = xtoi_2 ( s);
          s += 2;
        }
      else if (*s == '+')
        *d++ = ' ', s++;
      else
        *d++ = *s++;
    }
  *d = 0;
}


/* Check whether the option NAME appears in LINE */
static int
has_option (const char *line, const char *name)
{
  const char *s;
  int n = strlen (name);

  s = strstr (line, name);
  return (s && (s == line || spacep (s-1)) && (!s[n] || spacep (s+n)));
}

/* Same as has_option but only considers options at the begin of the
   line.  This is useful for commands which allow arbitrary strings on
   the line.  */
static int
has_leading_option (const char *line, const char *name)
{
  const char *s;
  int n;

  if (name[0] != '-' || name[1] != '-' || !name[2] || spacep (name+2))
    return 0;
  n = strlen (name);
  while ( *line == '-' && line[1] == '-' )
    {
      s = line;
      while (*line && !spacep (line))
        line++;
      if (n == (line - s) && !strncmp (s, name, n))
        return 1;
      while (spacep (line))
        line++;
    }
  return 0;
}


/* Same as has_option but does only test for the name of the option
   and ignores an argument, i.e. with NAME being "--hash" it would
   return a pointer for "--hash" as well as for "--hash=foo".  If
   thhere is no such option NULL is returned.  The pointer returned
   points right behind the option name, this may be an equal sign, Nul
   or a space.  */
/* static const char * */
/* has_option_name (const char *line, const char *name) */
/* { */
/*   const char *s; */
/*   int n = strlen (name); */

/*   s = strstr (line, name); */
/*   return (s && (s == line || spacep (s-1)) */
/*           && (!s[n] || spacep (s+n) || s[n] == '=')) ? (s+n) : NULL; */
/* } */


/* Skip over options.  It is assumed that leading spaces have been
   removed (this is the case for lines passed to a handler from
   assuan).  Blanks after the options are also removed. */
static char *
skip_options (char *line)
{
  while ( *line == '-' && line[1] == '-' )
    {
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
    }
  return line;
}


/* Return an error if the assuan context does not belong to the owner
   of the process or to root.  On error FAILTEXT is set as Assuan
   error string.  */
static gpg_error_t
check_owner_permission (assuan_context_t ctx, const char *failtext)
{
#ifdef HAVE_W32_SYSTEM
  /* Under Windows the dirmngr is always run under the control of the
     user.  */
  (void)ctx;
  (void)failtext;
#else
  gpg_err_code_t ec;
  assuan_peercred_t cred;

  ec = gpg_err_code (assuan_get_peercred (ctx, &cred));
  if (!ec && cred->uid && cred->uid != getuid ())
    ec = GPG_ERR_EPERM;
  if (ec)
    return set_error (ec, failtext);
#endif
  return 0;
}



/* Common code for get_cert_local and get_issuer_cert_local. */
static ksba_cert_t
do_get_cert_local (ctrl_t ctrl, const char *name, const char *command)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char *buf;
  ksba_cert_t cert;

  if (name)
    {
      buf = xmalloc ( strlen (command) + 1 + strlen(name) + 1);
      strcpy (stpcpy (stpcpy (buf, command), " "), name);
    }
  else
    buf = xstrdup (command);

  rc = assuan_inquire (ctrl->server_local->assuan_ctx, buf,
                       &value, &valuelen, MAX_CERT_LENGTH);
  xfree (buf);
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"),
                 command, gpg_strerror (rc));
      return NULL;
    }

  if (!valuelen)
    {
      xfree (value);
      return NULL;
    }

  rc = ksba_cert_new (&cert);
  if (!rc)
    {
      rc = ksba_cert_init_from_mem (cert, value, valuelen);
      if (rc)
        {
          ksba_cert_release (cert);
          cert = NULL;
        }
    }
  xfree (value);
  return cert;
}



/* Ask back to return a certificate for name, given as a regular
   gpgsm certificate indentificates (e.g. fingerprint or one of the
   other methods).  Alternatively, NULL may be used for NAME to
   return the current target certificate. Either return the certificate
   in a KSBA object or NULL if it is not available.
*/
ksba_cert_t
get_cert_local (ctrl_t ctrl, const char *name)
{
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_cert_local called w/o context\n");
      return NULL;
    }
  return do_get_cert_local (ctrl, name, "SENDCERT");

}

/* Ask back to return the issuing certificate for name, given as a
   regular gpgsm certificate indentificates (e.g. fingerprint or one
   of the other methods).  Alternatively, NULL may be used for NAME to
   return thecurrent target certificate. Either return the certificate
   in a KSBA object or NULL if it is not available.

*/
ksba_cert_t
get_issuing_cert_local (ctrl_t ctrl, const char *name)
{
  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_issuing_cert_local called w/o context\n");
      return NULL;
    }
  return do_get_cert_local (ctrl, name, "SENDISSUERCERT");
}

/* Ask back to return a certificate with subject NAME and a
   subjectKeyIdentifier of KEYID. */
ksba_cert_t
get_cert_local_ski (ctrl_t ctrl, const char *name, ksba_sexp_t keyid)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char *buf;
  ksba_cert_t cert;
  char *hexkeyid;

  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx)
    {
      if (opt.debug)
        log_debug ("get_cert_local_ski called w/o context\n");
      return NULL;
    }
  if (!name || !keyid)
    {
      log_debug ("get_cert_local_ski called with insufficient arguments\n");
      return NULL;
    }

  hexkeyid = serial_hex (keyid);
  if (!hexkeyid)
    {
      log_debug ("serial_hex() failed\n");
      return NULL;
    }

  buf = xtrymalloc (15 + strlen (hexkeyid) + 2 + strlen(name) + 1);
  if (!buf)
    {

      log_error ("can't allocate enough memory: %s\n", strerror (errno));
      xfree (hexkeyid);
      return NULL;
    }
  strcpy (stpcpy (stpcpy (stpcpy (buf, "SENDCERT_SKI "), hexkeyid)," /"),name);
  xfree (hexkeyid);

  rc = assuan_inquire (ctrl->server_local->assuan_ctx, buf,
                       &value, &valuelen, MAX_CERT_LENGTH);
  xfree (buf);
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"), "SENDCERT_SKI",
                 gpg_strerror (rc));
      return NULL;
    }

  if (!valuelen)
    {
      xfree (value);
      return NULL;
    }

  rc = ksba_cert_new (&cert);
  if (!rc)
    {
      rc = ksba_cert_init_from_mem (cert, value, valuelen);
      if (rc)
        {
          ksba_cert_release (cert);
          cert = NULL;
        }
    }
  xfree (value);
  return cert;
}


/* Ask the client via an inquiry to check the istrusted status of the
   certificate specified by the hexified fingerprint HEXFPR.  Returns
   0 if the certificate is trusted by the client or an error code.  */
gpg_error_t
get_istrusted_from_client (ctrl_t ctrl, const char *hexfpr)
{
  unsigned char *value;
  size_t valuelen;
  int rc;
  char request[100];

  if (!ctrl || !ctrl->server_local || !ctrl->server_local->assuan_ctx
      || !hexfpr)
    return gpg_error (GPG_ERR_INV_ARG);

  snprintf (request, sizeof request, "ISTRUSTED %s", hexfpr);
  rc = assuan_inquire (ctrl->server_local->assuan_ctx, request,
                       &value, &valuelen, 100);
  if (rc)
    {
      log_error (_("assuan_inquire(%s) failed: %s\n"),
                 request, gpg_strerror (rc));
      return rc;
    }
  /* The expected data is: "1" or "1 cruft" (not a C-string).  */
  if (valuelen && *value == '1' && (valuelen == 1 || spacep (value+1)))
    rc = 0;
  else
    rc = gpg_error (GPG_ERR_NOT_TRUSTED);
  xfree (value);
  return rc;
}




/* Ask the client to return the certificate associated with the
   current command. This is sometimes needed because the client usually
   sends us just the cert ID, assuming that the request can be
   satisfied from the cache, where the cert ID is used as key. */
static int
inquire_cert_and_load_crl (assuan_context_t ctx)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char *value = NULL;
  size_t valuelen;
  ksba_cert_t cert = NULL;

  err = assuan_inquire( ctx, "SENDCERT", &value, &valuelen, 0);
  if (err)
    return err;

/*   { */
/*     FILE *fp = fopen ("foo.der", "r"); */
/*     value = xmalloc (2000); */
/*     valuelen = fread (value, 1, 2000, fp); */
/*     fclose (fp); */
/*   } */

  if (!valuelen) /* No data returned; return a comprehensible error. */
    return gpg_error (GPG_ERR_MISSING_CERT);

  err = ksba_cert_new (&cert);
  if (err)
    goto leave;
  err = ksba_cert_init_from_mem (cert, value, valuelen);
  if(err)
    goto leave;
  xfree (value); value = NULL;

  err = crl_cache_reload_crl (ctrl, cert);

 leave:
  ksba_cert_release (cert);
  xfree (value);
  return err;
}


/* Handle OPTION commands. */
static gpg_error_t
option_handler (assuan_context_t ctx, const char *key, const char *value)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;

  if (!strcmp (key, "force-crl-refresh"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->force_crl_refresh = i;
    }
  else if (!strcmp (key, "audit-events"))
    {
      int i = *value? atoi (value) : 0;
      ctrl->audit_events = i;
    }
  else if (!strcmp (key, "http-proxy"))
    {
      xfree (ctrl->http_proxy);
      if (!*value || !strcmp (value, "none"))
        ctrl->http_proxy = NULL;
      else if (!(ctrl->http_proxy = xtrystrdup (value)))
        err = gpg_error_from_syserror ();
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}



static const char hlp_dns_cert[] =
  "DNS_CERT <subtype> <name>\n"
  "DNS_CERT --pka <user_id>\n"
  "\n"
  "Return the CERT record for <name>.  <subtype> is one of\n"
  "  *     Return the first record of any supported subtype\n"
  "  PGP   Return the first record of subtype PGP (3)\n"
  "  IPGP  Return the first record of subtype IPGP (6)\n"
  "If the content of a certifciate is available (PGP) it is returned\n"
  "by data lines.  Fingerprints and URLs are returned via status lines.\n"
  "In --pka mode the fingerprint and if available an URL is returned.";
static gpg_error_t
cmd_dns_cert (assuan_context_t ctx, char *line)
{
  /* ctrl_t ctrl = assuan_get_pointer (ctx); */
  gpg_error_t err = 0;
  int pka_mode;
  char *mbox = NULL;
  char *namebuf = NULL;
  char *encodedhash = NULL;
  const char *name;
  int certtype;
  char *p;
  void *key = NULL;
  size_t keylen;
  unsigned char *fpr = NULL;
  size_t fprlen;
  char *url = NULL;

  pka_mode = has_option (line, "--pka");
  line = skip_options (line);
  if (pka_mode)
    ; /* No need to parse here - we do this later.  */
  else
    {
      p = strchr (line, ' ');
      if (!p)
        {
          err = PARM_ERROR ("missing arguments");
          goto leave;
        }
      *p++ = 0;
      if (!strcmp (line, "*"))
        certtype = DNS_CERTTYPE_ANY;
      else if (!strcmp (line, "IPGP"))
        certtype = DNS_CERTTYPE_IPGP;
      else if (!strcmp (line, "PGP"))
        certtype = DNS_CERTTYPE_PGP;
      else
        {
          err = PARM_ERROR ("unknown subtype");
          goto leave;
        }
      while (spacep (p))
        p++;
      line = p;
      if (!*line)
        {
          err = PARM_ERROR ("name missing");
          goto leave;
        }
    }

  if (pka_mode)
    {
      char *domain;  /* Points to mbox.  */
      char hashbuf[20];

      mbox = mailbox_from_userid (line);
      if (!mbox || !(domain = strchr (mbox, '@')))
        {
          err = set_error (GPG_ERR_INV_USER_ID, "no mailbox in user id");
          goto leave;
        }
      *domain++ = 0;

      gcry_md_hash_buffer (GCRY_MD_SHA1, hashbuf, mbox, strlen (mbox));
      encodedhash = zb32_encode (hashbuf, 8*20);
      if (!encodedhash)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      namebuf = strconcat (encodedhash, "._pka.", domain, NULL);
      if (!namebuf)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      name = namebuf;
      certtype = DNS_CERTTYPE_IPGP;
    }
  else
    name = line;

  err = get_dns_cert (name, certtype, &key, &keylen, &fpr, &fprlen, &url);
  if (err)
    goto leave;

  if (key)
    {
      err = data_line_write (ctx, key, keylen);
      if (err)
        goto leave;
    }

  if (fpr)
    {
      char *tmpstr;

      tmpstr = bin2hex (fpr, fprlen, NULL);
      if (!tmpstr)
        err = gpg_error_from_syserror ();
      else
        {
          err = assuan_write_status (ctx, "FPR", tmpstr);
          xfree (tmpstr);
        }
      if (err)
        goto leave;
    }

  if (url)
    {
      err = assuan_write_status (ctx, "URL", url);
      if (err)
        goto leave;
    }


 leave:
  xfree (key);
  xfree (fpr);
  xfree (url);
  xfree (mbox);
  xfree (namebuf);
  xfree (encodedhash);
  return leave_cmd (ctx, err);
}



static const char hlp_ldapserver[] =
  "LDAPSERVER <data>\n"
  "\n"
  "Add a new LDAP server to the list of configured LDAP servers.\n"
  "DATA is in the same format as expected in the configure file.";
static gpg_error_t
cmd_ldapserver (assuan_context_t ctx, char *line)
{
#if USE_LDAP
  ctrl_t ctrl = assuan_get_pointer (ctx);
  ldap_server_t server;
  ldap_server_t *last_next_p;

  while (spacep (line))
    line++;
  if (*line == '\0')
    return leave_cmd (ctx, PARM_ERROR (_("ldapserver missing")));

  server = ldapserver_parse_one (line, "", 0);
  if (! server)
    return leave_cmd (ctx, gpg_error (GPG_ERR_INV_ARG));

  last_next_p = &ctrl->server_local->ldapservers;
  while (*last_next_p)
    last_next_p = &(*last_next_p)->next;
  *last_next_p = server;
  return leave_cmd (ctx, 0);
#else
  (void)line;
  return leave_cmd (ctx, gpg_error (GPG_ERR_NOT_IMPLEMENTED));
#endif
}


static const char hlp_isvalid[] =
  "ISVALID [--only-ocsp] [--force-default-responder]"
  " <certificate_id>|<certificate_fpr>\n"
  "\n"
  "This command checks whether the certificate identified by the\n"
  "certificate_id is valid.  This is done by consulting CRLs or\n"
  "whatever has been configured.  Note, that the returned error codes\n"
  "are from gpg-error.h.  The command may callback using the inquire\n"
  "function.  See the manual for details.\n"
  "\n"
  "The CERTIFICATE_ID is a hex encoded string consisting of two parts,\n"
  "delimited by a single dot.  The first part is the SHA-1 hash of the\n"
  "issuer name and the second part the serial number.\n"
  "\n"
  "Alternatively the certificate's fingerprint may be given in which\n"
  "case an OCSP request is done before consulting the CRL.\n"
  "\n"
  "If the option --only-ocsp is given, no fallback to a CRL check will\n"
  "be used.\n"
  "\n"
  "If the option --force-default-responder is given, only the default\n"
  "OCSP responder will be used and any other methods of obtaining an\n"
  "OCSP responder URL won't be used.";
static gpg_error_t
cmd_isvalid (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  char *issuerhash, *serialno;
  gpg_error_t err;
  int did_inquire = 0;
  int ocsp_mode = 0;
  int only_ocsp;
  int force_default_responder;

  only_ocsp = has_option (line, "--only-ocsp");
  force_default_responder = has_option (line, "--force-default-responder");
  line = skip_options (line);

  issuerhash = xstrdup (line); /* We need to work on a copy of the
                                  line because that same Assuan
                                  context may be used for an inquiry.
                                  That is because Assuan reuses its
                                  line buffer.
                                   */

  serialno = strchr (issuerhash, '.');
  if (serialno)
    *serialno++ = 0;
  else
    {
      char *endp = strchr (issuerhash, ' ');
      if (endp)
        *endp = 0;
      if (strlen (issuerhash) != 40)
        {
          xfree (issuerhash);
          return leave_cmd (ctx, PARM_ERROR (_("serialno missing in cert ID")));
        }
      ocsp_mode = 1;
    }


 again:
  if (ocsp_mode)
    {
      /* Note, that we ignore the given issuer hash and instead rely
         on the current certificate semantics used with this
         command. */
      if (!opt.allow_ocsp)
        err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      else
        err = ocsp_isvalid (ctrl, NULL, NULL, force_default_responder);
      /* Fixme: If we got no ocsp response and --only-ocsp is not used
         we should fall back to CRL mode.  Thus we need to clear
         OCSP_MODE, get the issuerhash and the serialno from the
         current certificate and jump to again. */
    }
  else if (only_ocsp)
    err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
  else
    {
      switch (crl_cache_isvalid (ctrl,
                                 issuerhash, serialno,
                                 ctrl->force_crl_refresh))
        {
        case CRL_CACHE_VALID:
          err = 0;
          break;
        case CRL_CACHE_INVALID:
          err = gpg_error (GPG_ERR_CERT_REVOKED);
          break;
        case CRL_CACHE_DONTKNOW:
          if (did_inquire)
            err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
          else if (!(err = inquire_cert_and_load_crl (ctx)))
            {
              did_inquire = 1;
              goto again;
            }
          break;
        case CRL_CACHE_CANTUSE:
          err = gpg_error (GPG_ERR_NO_CRL_KNOWN);
          break;
        default:
          log_fatal ("crl_cache_isvalid returned invalid code\n");
        }
    }

  xfree (issuerhash);
  return leave_cmd (ctx, err);
}


/* If the line contains a SHA-1 fingerprint as the first argument,
   return the FPR vuffer on success.  The function checks that the
   fingerprint consists of valid characters and prints and error
   message if it does not and returns NULL.  Fingerprints are
   considered optional and thus no explicit error is returned. NULL is
   also returned if there is no fingerprint at all available.
   FPR must be a caller provided buffer of at least 20 bytes.

   Note that colons within the fingerprint are allowed to separate 2
   hex digits; this allows for easier cutting and pasting using the
   usual fingerprint rendering.
*/
static unsigned char *
get_fingerprint_from_line (const char *line, unsigned char *fpr)
{
  const char *s;
  int i;

  for (s=line, i=0; *s && *s != ' '; s++ )
    {
      if ( hexdigitp (s) && hexdigitp (s+1) )
        {
          if ( i >= 20 )
            return NULL;  /* Fingerprint too long.  */
          fpr[i++] = xtoi_2 (s);
          s++;
        }
      else if ( *s != ':' )
        return NULL; /* Invalid.  */
    }
  if ( i != 20 )
    return NULL; /* Fingerprint to short.  */
  return fpr;
}



static const char hlp_checkcrl[] =
  "CHECKCRL [<fingerprint>]\n"
  "\n"
  "Check whether the certificate with FINGERPRINT (SHA-1 hash of the\n"
  "entire X.509 certificate blob) is valid or not by consulting the\n"
  "CRL responsible for this certificate.  If the fingerprint has not\n"
  "been given or the certificate is not known, the function \n"
  "inquires the certificate using an\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request (which should match FINGERPRINT) as a binary blob.\n"
  "Processing then takes place without further interaction; in\n"
  "particular dirmngr tries to locate other required certificate by\n"
  "its own mechanism which includes a local certificate store as well\n"
  "as a list of trusted root certificates.\n"
  "\n"
  "The return value is the usual gpg-error code or 0 for ducesss;\n"
  "i.e. the certificate validity has been confirmed by a valid CRL.";
static gpg_error_t
cmd_checkcrl (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char fprbuffer[20], *fpr;
  ksba_cert_t cert;

  fpr = get_fingerprint_from_line (line, fprbuffer);
  cert = fpr? get_cert_byfpr (fpr) : NULL;

  if (!cert)
    {
      /* We do not have this certificate yet or the fingerprint has
         not been given.  Inquire it from the client.  */
      unsigned char *value = NULL;
      size_t valuelen;

      err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                           &value, &valuelen, MAX_CERT_LENGTH);
      if (err)
        {
          log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      if (!valuelen) /* No data returned; return a comprehensible error. */
        err = gpg_error (GPG_ERR_MISSING_CERT);
      else
        {
          err = ksba_cert_new (&cert);
          if (!err)
            err = ksba_cert_init_from_mem (cert, value, valuelen);
        }
      xfree (value);
      if(err)
        goto leave;
    }

  assert (cert);

  err = crl_cache_cert_isvalid (ctrl, cert, ctrl->force_crl_refresh);
  if (gpg_err_code (err) == GPG_ERR_NO_CRL_KNOWN)
    {
      err = crl_cache_reload_crl (ctrl, cert);
      if (!err)
        err = crl_cache_cert_isvalid (ctrl, cert, 0);
    }

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}


static const char hlp_checkocsp[] =
  "CHECKOCSP [--force-default-responder] [<fingerprint>]\n"
  "\n"
  "Check whether the certificate with FINGERPRINT (SHA-1 hash of the\n"
  "entire X.509 certificate blob) is valid or not by asking an OCSP\n"
  "responder responsible for this certificate.  The optional\n"
  "fingerprint may be used for a quick check in case an OCSP check has\n"
  "been done for this certificate recently (we always cache OCSP\n"
  "responses for a couple of minutes). If the fingerprint has not been\n"
  "given or there is no cached result, the function inquires the\n"
  "certificate using an\n"
  "\n"
  "   INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request (which should match FINGERPRINT) as a binary blob.\n"
  "Processing then takes place without further interaction; in\n"
  "particular dirmngr tries to locate other required certificates by\n"
  "its own mechanism which includes a local certificate store as well\n"
  "as a list of trusted root certifciates.\n"
  "\n"
  "If the option --force-default-responder is given, only the default\n"
  "OCSP responder will be used and any other methods of obtaining an\n"
  "OCSP responder URL won't be used.\n"
  "\n"
  "The return value is the usual gpg-error code or 0 for ducesss;\n"
  "i.e. the certificate validity has been confirmed by a valid CRL.";
static gpg_error_t
cmd_checkocsp (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char fprbuffer[20], *fpr;
  ksba_cert_t cert;
  int force_default_responder;

  force_default_responder = has_option (line, "--force-default-responder");
  line = skip_options (line);

  fpr = get_fingerprint_from_line (line, fprbuffer);
  cert = fpr? get_cert_byfpr (fpr) : NULL;

  if (!cert)
    {
      /* We do not have this certificate yet or the fingerprint has
         not been given.  Inquire it from the client.  */
      unsigned char *value = NULL;
      size_t valuelen;

      err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                           &value, &valuelen, MAX_CERT_LENGTH);
      if (err)
        {
          log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      if (!valuelen) /* No data returned; return a comprehensible error. */
        err = gpg_error (GPG_ERR_MISSING_CERT);
      else
        {
          err = ksba_cert_new (&cert);
          if (!err)
            err = ksba_cert_init_from_mem (cert, value, valuelen);
        }
      xfree (value);
      if(err)
        goto leave;
    }

  assert (cert);

  if (!opt.allow_ocsp)
    err = gpg_error (GPG_ERR_NOT_SUPPORTED);
  else
    err = ocsp_isvalid (ctrl, cert, NULL, force_default_responder);

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}



static int
lookup_cert_by_url (assuan_context_t ctx, const char *url)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  unsigned char *value = NULL;
  size_t valuelen;

  /* Fetch single certificate given it's URL.  */
  err = fetch_cert_by_url (ctrl, url, &value, &valuelen);
  if (err)
    {
      log_error (_("fetch_cert_by_url failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Send the data, flush the buffer and then send an END. */
  err = assuan_send_data (ctx, value, valuelen);
  if (!err)
    err = assuan_send_data (ctx, NULL, 0);
  if (!err)
    err = assuan_write_line (ctx, "END");
  if (err)
    {
      log_error (_("error sending data: %s\n"), gpg_strerror (err));
      goto leave;
    }

 leave:

  return err;
}


/* Send the certificate, flush the buffer and then send an END. */
static gpg_error_t
return_one_cert (void *opaque, ksba_cert_t cert)
{
  assuan_context_t ctx = opaque;
  gpg_error_t err;
  const unsigned char *der;
  size_t derlen;

  der = ksba_cert_get_image (cert, &derlen);
  if (!der)
    err = gpg_error (GPG_ERR_INV_CERT_OBJ);
  else
    {
      err = assuan_send_data (ctx, der, derlen);
      if (!err)
        err = assuan_send_data (ctx, NULL, 0);
      if (!err)
        err = assuan_write_line (ctx, "END");
    }
  if (err)
    log_error (_("error sending data: %s\n"), gpg_strerror (err));
  return err;
}


/* Lookup certificates from the internal cache or using the ldap
   servers. */
static int
lookup_cert_by_pattern (assuan_context_t ctx, char *line,
                        int single, int cache_only)
{
  gpg_error_t err = 0;
  char *p;
  strlist_t sl, list = NULL;
  int truncated = 0, truncation_forced = 0;
  int count = 0;
  int local_count = 0;
#if USE_LDAP
  ctrl_t ctrl = assuan_get_pointer (ctx);
  unsigned char *value = NULL;
  size_t valuelen;
  struct ldapserver_iter ldapserver_iter;
  cert_fetch_context_t fetch_context;
#endif /*USE_LDAP*/
  int any_no_data = 0;

  /* Break the line down into an STRLIST */
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;

      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_errno (errno);
              goto leave;
            }
          memset (sl, 0, sizeof *sl);
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  /* First look through the internal cache.  The certifcates retruned
     here are not counted towards the truncation limit.  */
  if (single && !cache_only)
    ; /* Do not read from the local cache in this case.  */
  else
    {
      for (sl=list; sl; sl = sl->next)
        {
          err = get_certs_bypattern (sl->d, return_one_cert, ctx);
          if (!err)
            local_count++;
          if (!err && single)
            goto ready;

          if (gpg_err_code (err) == GPG_ERR_NO_DATA)
            {
              err = 0;
              if (cache_only)
                any_no_data = 1;
            }
          else if (gpg_err_code (err) == GPG_ERR_INV_NAME && !cache_only)
            {
              /* No real fault because the internal pattern lookup
                 can't yet cope with all types of pattern.  */
              err = 0;
            }
          if (err)
            goto ready;
        }
    }

  /* Loop over all configured servers unless we want only the
     certificates from the cache.  */
#if USE_LDAP
  for (ldapserver_iter_begin (&ldapserver_iter, ctrl);
       !cache_only && !ldapserver_iter_end_p (&ldapserver_iter)
	 && ldapserver_iter.server->host && !truncation_forced;
       ldapserver_iter_next (&ldapserver_iter))
    {
      ldap_server_t ldapserver = ldapserver_iter.server;

      if (DBG_LOOKUP)
        log_debug ("cmd_lookup: trying %s:%d base=%s\n",
                   ldapserver->host, ldapserver->port,
                   ldapserver->base?ldapserver->base : "[default]");

      /* Fetch certificates matching pattern */
      err = start_cert_fetch (ctrl, &fetch_context, list, ldapserver);
      if ( gpg_err_code (err) == GPG_ERR_NO_DATA )
        {
          if (DBG_LOOKUP)
            log_debug ("cmd_lookup: no data\n");
          err = 0;
          any_no_data = 1;
          continue;
        }
      if (err)
        {
          log_error (_("start_cert_fetch failed: %s\n"), gpg_strerror (err));
          goto leave;
        }

      /* Fetch the certificates for this query. */
      while (!truncation_forced)
        {
          xfree (value); value = NULL;
          err = fetch_next_cert (fetch_context, &value, &valuelen);
          if (gpg_err_code (err) == GPG_ERR_NO_DATA )
            {
              err = 0;
              any_no_data = 1;
              break; /* Ready. */
            }
          if (gpg_err_code (err) == GPG_ERR_TRUNCATED)
            {
              truncated = 1;
              err = 0;
              break;  /* Ready.  */
            }
          if (gpg_err_code (err) == GPG_ERR_EOF)
            {
              err = 0;
              break; /* Ready. */
            }
          if (!err && !value)
            {
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          if (err)
            {
              log_error (_("fetch_next_cert failed: %s\n"),
                         gpg_strerror (err));
              end_cert_fetch (fetch_context);
              goto leave;
            }

          if (DBG_LOOKUP)
            log_debug ("cmd_lookup: returning one cert%s\n",
                       truncated? " (truncated)":"");

          /* Send the data, flush the buffer and then send an END line
             as a certificate delimiter. */
          err = assuan_send_data (ctx, value, valuelen);
          if (!err)
            err = assuan_send_data (ctx, NULL, 0);
          if (!err)
            err = assuan_write_line (ctx, "END");
          if (err)
            {
              log_error (_("error sending data: %s\n"), gpg_strerror (err));
              end_cert_fetch (fetch_context);
              goto leave;
            }

          if (++count >= opt.max_replies )
            {
              truncation_forced = 1;
              log_info (_("max_replies %d exceeded\n"), opt.max_replies );
            }
          if (single)
            break;
        }

      end_cert_fetch (fetch_context);
    }
#endif /*USE_LDAP*/

 ready:
  if (truncated || truncation_forced)
    {
      char str[50];

      sprintf (str, "%d", count);
      assuan_write_status (ctx, "TRUNCATED", str);
    }

  if (!err && !count && !local_count && any_no_data)
    err = gpg_error (GPG_ERR_NO_DATA);

 leave:
  free_strlist (list);
  return err;
}


static const char hlp_lookup[] =
  "LOOKUP [--url] [--single] [--cache-only] <pattern>\n"
  "\n"
  "Lookup certificates matching PATTERN. With --url the pattern is\n"
  "expected to be one URL.\n"
  "\n"
  "If --url is not given:  To allow for multiple patterns (which are ORed)\n"
  "quoting is required: Spaces are translated to \"+\" or \"%20\";\n"
  "obviously this requires that the usual escape quoting rules are applied.\n"
  "\n"
  "If --url is given no special escaping is required because URLs are\n"
  "already escaped this way.\n"
  "\n"
  "If --single is given the first and only the first match will be\n"
  "returned.  If --cache-only is _not_ given, no local query will be\n"
  "done.\n"
  "\n"
  "If --cache-only is given no external lookup is done so that only\n"
  "certificates from the cache may get returned.";
static gpg_error_t
cmd_lookup (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  int lookup_url, single, cache_only;

  lookup_url = has_leading_option (line, "--url");
  single = has_leading_option (line, "--single");
  cache_only = has_leading_option (line, "--cache-only");
  line = skip_options (line);

  if (lookup_url && cache_only)
    err = gpg_error (GPG_ERR_NOT_FOUND);
  else if (lookup_url && single)
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  else if (lookup_url)
    err = lookup_cert_by_url (ctx, line);
  else
    err = lookup_cert_by_pattern (ctx, line, single, cache_only);

  return leave_cmd (ctx, err);
}


static const char hlp_loadcrl[] =
  "LOADCRL [--url] <filename|url>\n"
  "\n"
  "Load the CRL in the file with name FILENAME into our cache.  Note\n"
  "that FILENAME should be given with an absolute path because\n"
  "Dirmngrs cwd is not known.  With --url the CRL is directly loaded\n"
  "from the given URL.\n"
  "\n"
  "This command is usually used by gpgsm using the invocation \"gpgsm\n"
  "--call-dirmngr loadcrl <filename>\".  A direct invocation of Dirmngr\n"
  "is not useful because gpgsm might need to callback gpgsm to ask for\n"
  "the CA's certificate.";
static gpg_error_t
cmd_loadcrl (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int use_url = has_leading_option (line, "--url");

  line = skip_options (line);

  if (use_url)
    {
      ksba_reader_t reader;

      err = crl_fetch (ctrl, line, &reader);
      if (err)
        log_error (_("fetching CRL from '%s' failed: %s\n"),
                   line, gpg_strerror (err));
      else
        {
          err = crl_cache_insert (ctrl, line, reader);
          if (err)
            log_error (_("processing CRL from '%s' failed: %s\n"),
                       line, gpg_strerror (err));
          crl_close_reader (reader);
        }
    }
  else
    {
      char *buf;

      buf = xtrymalloc (strlen (line)+1);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          strcpy_escaped_plus (buf, line);
          err = crl_cache_load (ctrl, buf);
          xfree (buf);
        }
    }

  return leave_cmd (ctx, err);
}


static const char hlp_listcrls[] =
  "LISTCRLS\n"
  "\n"
  "List the content of all CRLs in a readable format.  This command is\n"
  "usually used by gpgsm using the invocation \"gpgsm --call-dirmngr\n"
  "listcrls\".  It may also be used directly using \"dirmngr\n"
  "--list-crls\".";
static gpg_error_t
cmd_listcrls (assuan_context_t ctx, char *line)
{
  gpg_error_t err;
  estream_t fp;

  (void)line;

  fp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!fp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = crl_cache_list (fp);
      es_fclose (fp);
    }
  return leave_cmd (ctx, err);
}


static const char hlp_cachecert[] =
  "CACHECERT\n"
  "\n"
  "Put a certificate into the internal cache.  This command might be\n"
  "useful if a client knows in advance certificates required for a\n"
  "test and wants to make sure they get added to the internal cache.\n"
  "It is also helpful for debugging.  To get the actual certificate,\n"
  "this command immediately inquires it using\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request as a binary blob.";
static gpg_error_t
cmd_cachecert (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  ksba_cert_t cert = NULL;
  unsigned char *value = NULL;
  size_t valuelen;

  (void)line;

  err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                       &value, &valuelen, MAX_CERT_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    err = gpg_error (GPG_ERR_MISSING_CERT);
  else
    {
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_init_from_mem (cert, value, valuelen);
    }
  xfree (value);
  if(err)
    goto leave;

  err = cache_cert (cert);

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}


static const char hlp_validate[] =
  "VALIDATE\n"
  "\n"
  "Validate a certificate using the certificate validation function\n"
  "used internally by dirmngr.  This command is only useful for\n"
  "debugging.  To get the actual certificate, this command immediately\n"
  "inquires it using\n"
  "\n"
  "  INQUIRE TARGETCERT\n"
  "\n"
  "and the caller is expected to return the certificate for the\n"
  "request as a binary blob.";
static gpg_error_t
cmd_validate (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  ksba_cert_t cert = NULL;
  unsigned char *value = NULL;
  size_t valuelen;

  (void)line;

  err = assuan_inquire (ctrl->server_local->assuan_ctx, "TARGETCERT",
                       &value, &valuelen, MAX_CERT_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    err = gpg_error (GPG_ERR_MISSING_CERT);
  else
    {
      err = ksba_cert_new (&cert);
      if (!err)
        err = ksba_cert_init_from_mem (cert, value, valuelen);
    }
  xfree (value);
  if(err)
    goto leave;

  /* If we have this certificate already in our cache, use the cached
     version for validation because this will take care of any cached
     results. */
  {
    unsigned char fpr[20];
    ksba_cert_t tmpcert;

    cert_compute_fpr (cert, fpr);
    tmpcert = get_cert_byfpr (fpr);
    if (tmpcert)
      {
        ksba_cert_release (cert);
        cert = tmpcert;
      }
  }

  err = validate_cert_chain (ctrl, cert, NULL, VALIDATE_MODE_CERT, NULL);

 leave:
  ksba_cert_release (cert);
  return leave_cmd (ctx, err);
}


static const char hlp_keyserver[] =
  "KEYSERVER [<options>] [<uri>|<host>]\n"
  "Options are:\n"
  "  --help\n"
  "  --clear      Remove all configured keyservers\n"
  "  --resolve    Resolve HKP host names and rotate\n"
  "  --hosttable  Print table of known hosts and pools\n"
  "  --dead       Mark <host> as dead\n"
  "  --alive      Mark <host> as alive\n"
  "\n"
  "If called without arguments list all configured keyserver URLs.\n"
  "If called with an URI add this as keyserver.  Note that keyservers\n"
  "are configured on a per-session base.  A default keyserver may already be\n"
  "present, thus the \"--clear\" option must be used to get full control.\n"
  "If \"--clear\" and an URI are used together the clear command is\n"
  "obviously executed first.  A RESET command does not change the list\n"
  "of configured keyservers.";
static gpg_error_t
cmd_keyserver (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err = 0;
  int clear_flag, add_flag, help_flag, host_flag, resolve_flag;
  int dead_flag, alive_flag;
  uri_item_t item = NULL; /* gcc 4.4.5 is not able to detect that it
                             is always initialized.  */

  clear_flag = has_option (line, "--clear");
  help_flag = has_option (line, "--help");
  resolve_flag = has_option (line, "--resolve");
  host_flag = has_option (line, "--hosttable");
  dead_flag = has_option (line, "--dead");
  alive_flag = has_option (line, "--alive");
  line = skip_options (line);
  add_flag = !!*line;

  if (help_flag)
    {
      err = ks_action_help (ctrl, line);
      goto leave;
    }

  if (resolve_flag)
    {
      err = ks_action_resolve (ctrl, ctrl->server_local->keyservers);
      if (err)
        goto leave;
    }

  if (alive_flag && dead_flag)
    {
      err = set_error (GPG_ERR_ASS_PARAMETER, "no support for zombies");
      goto leave;
    }
  if (dead_flag)
    {
      err = check_owner_permission (ctx, "no permission to use --dead");
      if (err)
        goto leave;
    }
  if (alive_flag || dead_flag)
    {
      if (!*line)
        {
          err = set_error (GPG_ERR_ASS_PARAMETER, "name of host missing");
          goto leave;
        }

      err = ks_hkp_mark_host (ctrl, line, alive_flag);
      if (err)
        goto leave;
    }

  if (host_flag)
    {
      err = ks_hkp_print_hosttable (ctrl);
      if (err)
        goto leave;
    }
  if (resolve_flag || host_flag || alive_flag || dead_flag)
    goto leave;

  if (add_flag)
    {
      item = xtrymalloc (sizeof *item + strlen (line));
      if (!item)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      item->next = NULL;
      item->parsed_uri = NULL;
      strcpy (item->uri, line);

#if USE_LDAP
      if (ldap_uri_p (item->uri))
	err = ldap_parse_uri (&item->parsed_uri, line);
      else
#endif
	{
	  err = http_parse_uri (&item->parsed_uri, line, 1);
	}
      if (err)
        {
          xfree (item);
          goto leave;
        }
    }
  if (clear_flag)
    release_ctrl_keyservers (ctrl);
  if (add_flag)
    {
      item->next = ctrl->server_local->keyservers;
      ctrl->server_local->keyservers = item;
    }

  if (!add_flag && !clear_flag && !help_flag) /* List configured keyservers.  */
    {
      uri_item_t u;

      for (u=ctrl->server_local->keyservers; u; u = u->next)
        dirmngr_status (ctrl, "KEYSERVER", u->uri, NULL);
    }
  err = 0;

 leave:
  return leave_cmd (ctx, err);
}



static const char hlp_ks_search[] =
  "KS_SEARCH {<pattern>}\n"
  "\n"
  "Search the configured OpenPGP keyservers (see command KEYSERVER)\n"
  "for keys matching PATTERN";
static gpg_error_t
cmd_ks_search (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  strlist_t list, sl;
  char *p;
  estream_t outfp;

  /* No options for now.  */
  line = skip_options (line);

  /* Break the line down into an strlist.  Each pattern is
     percent-plus escaped. */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  /* Setup an output stream and perform the search.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = ks_action_search (ctrl, ctrl->server_local->keyservers,
			      list, outfp);
      es_fclose (outfp);
    }

 leave:
  free_strlist (list);
  return leave_cmd (ctx, err);
}



static const char hlp_ks_get[] =
  "KS_GET {<pattern>}\n"
  "\n"
  "Get the keys matching PATTERN from the configured OpenPGP keyservers\n"
  "(see command KEYSERVER).  Each pattern should be a keyid, a fingerprint,\n"
  "or an exact name indicated by the '=' prefix.";
static gpg_error_t
cmd_ks_get (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  strlist_t list, sl;
  char *p;
  estream_t outfp;

  /* No options for now.  */
  line = skip_options (line);

  /* Break the line into a strlist.  Each pattern is by
     definition percent-plus escaped.  However we only support keyids
     and fingerprints and thus the client has no need to apply the
     escaping.  */
  list = NULL;
  for (p=line; *p; line = p)
    {
      while (*p && *p != ' ')
        p++;
      if (*p)
        *p++ = 0;
      if (*line)
        {
          sl = xtrymalloc (sizeof *sl + strlen (line));
          if (!sl)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          sl->flags = 0;
          strcpy_escaped_plus (sl->d, line);
          sl->next = list;
          list = sl;
        }
    }

  /* Setup an output stream and perform the get.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = ks_action_get (ctrl, ctrl->server_local->keyservers, list, outfp);
      es_fclose (outfp);
    }

 leave:
  free_strlist (list);
  return leave_cmd (ctx, err);
}


static const char hlp_ks_fetch[] =
  "KS_FETCH <URL>\n"
  "\n"
  "Get the key(s) from URL.";
static gpg_error_t
cmd_ks_fetch (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  estream_t outfp;

  /* No options for now.  */
  line = skip_options (line);

  /* Setup an output stream and perform the get.  */
  outfp = es_fopencookie (ctx, "w", data_line_cookie_functions);
  if (!outfp)
    err = set_error (GPG_ERR_ASS_GENERAL, "error setting up a data stream");
  else
    {
      err = ks_action_fetch (ctrl, line, outfp);
      es_fclose (outfp);
    }

  return leave_cmd (ctx, err);
}



static const char hlp_ks_put[] =
  "KS_PUT\n"
  "\n"
  "Send a key to the configured OpenPGP keyservers.  The actual key material\n"
  "is then requested by Dirmngr using\n"
  "\n"
  "  INQUIRE KEYBLOCK\n"
  "\n"
  "The client shall respond with a binary version of the keyblock (e.g.,\n"
  "the output of `gpg --export KEYID').  For LDAP\n"
  "keyservers Dirmngr may ask for meta information of the provided keyblock\n"
  "using:\n"
  "\n"
  "  INQUIRE KEYBLOCK_INFO\n"
  "\n"
  "The client shall respond with a colon delimited info lines (the output\n"
  "of 'for x in keys sigs; do gpg --list-$x --with-colons KEYID; done').\n";
static gpg_error_t
cmd_ks_put (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;
  unsigned char *value = NULL;
  size_t valuelen;
  unsigned char *info = NULL;
  size_t infolen;

  /* No options for now.  */
  line = skip_options (line);

  /* Ask for the key material.  */
  err = assuan_inquire (ctx, "KEYBLOCK",
                        &value, &valuelen, MAX_KEYBLOCK_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  if (!valuelen) /* No data returned; return a comprehensible error. */
    {
      err = gpg_error (GPG_ERR_MISSING_CERT);
      goto leave;
    }

  /* Ask for the key meta data. Not actually needed for HKP servers
     but we do it anyway to test the client implementaion.  */
  err = assuan_inquire (ctx, "KEYBLOCK_INFO",
                        &info, &infolen, MAX_KEYBLOCK_LENGTH);
  if (err)
    {
      log_error (_("assuan_inquire failed: %s\n"), gpg_strerror (err));
      goto leave;
    }

  /* Send the key.  */
  err = ks_action_put (ctrl, ctrl->server_local->keyservers,
		       value, valuelen, info, infolen);

 leave:
  xfree (info);
  xfree (value);
  return leave_cmd (ctx, err);
}




static const char hlp_getinfo[] =
  "GETINFO <what>\n"
  "\n"
  "Multi purpose command to return certain information.  \n"
  "Supported values of WHAT are:\n"
  "\n"
  "version     - Return the version of the program.\n"
  "pid         - Return the process id of the server.\n"
  "\n"
  "socket_name - Return the name of the socket.\n";
static gpg_error_t
cmd_getinfo (assuan_context_t ctx, char *line)
{
  gpg_error_t err;

  if (!strcmp (line, "version"))
    {
      const char *s = VERSION;
      err = assuan_send_data (ctx, s, strlen (s));
    }
  else if (!strcmp (line, "pid"))
    {
      char numbuf[50];

      snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
      err = assuan_send_data (ctx, numbuf, strlen (numbuf));
    }
  else if (!strcmp (line, "socket_name"))
    {
      const char *s = dirmngr_user_socket_name ();

      if (!s)
        s = dirmngr_sys_socket_name ();

      if (s)
        err = assuan_send_data (ctx, s, strlen (s));
      else
        err = gpg_error (GPG_ERR_NO_DATA);
    }
  else
    err = set_error (GPG_ERR_ASS_PARAMETER, "unknown value for WHAT");

  return leave_cmd (ctx, err);
}



static const char hlp_killdirmngr[] =
  "KILLDIRMNGR\n"
  "\n"
  "This command allows a user - given sufficient permissions -\n"
  "to kill this dirmngr process.\n";
static gpg_error_t
cmd_killdirmngr (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  gpg_error_t err;

  (void)line;

  if (opt.system_daemon)
    {
      if (opt.system_service)
        err = set_error (GPG_ERR_NOT_SUPPORTED,
                         "can't do that whilst running as system service");
      else
        err = check_owner_permission (ctx,
                                      "no permission to kill this process");
    }
  else
    err = 0;

  if (!err)
    {
      ctrl->server_local->stopme = 1;
      err = gpg_error (GPG_ERR_EOF);
    }
  return err;
}


static const char hlp_reloaddirmngr[] =
  "RELOADDIRMNGR\n"
  "\n"
  "This command is an alternative to SIGHUP\n"
  "to reload the configuration.";
static gpg_error_t
cmd_reloaddirmngr (assuan_context_t ctx, char *line)
{
  (void)ctx;
  (void)line;

 if (opt.system_daemon)
    {
#ifndef HAVE_W32_SYSTEM
      {
        gpg_err_code_t ec;
        assuan_peercred_t cred;

        ec = gpg_err_code (assuan_get_peercred (ctx, &cred));
        if (!ec && cred->uid)
          ec = GPG_ERR_EPERM; /* Only root may terminate.  */
        if (ec)
          return set_error (ec, "no permission to reload this process");
      }
#endif
    }

  dirmngr_sighup_action ();
  return 0;
}




/* Tell the assuan library about our commands. */
static int
register_commands (assuan_context_t ctx)
{
  static struct {
    const char *name;
    assuan_handler_t handler;
    const char * const help;
  } table[] = {
    { "DNS_CERT",   cmd_dns_cert,   hlp_dns_cert },
    { "LDAPSERVER", cmd_ldapserver, hlp_ldapserver },
    { "ISVALID",    cmd_isvalid,    hlp_isvalid },
    { "CHECKCRL",   cmd_checkcrl,   hlp_checkcrl },
    { "CHECKOCSP",  cmd_checkocsp,  hlp_checkocsp },
    { "LOOKUP",     cmd_lookup,     hlp_lookup },
    { "LOADCRL",    cmd_loadcrl,    hlp_loadcrl },
    { "LISTCRLS",   cmd_listcrls,   hlp_listcrls },
    { "CACHECERT",  cmd_cachecert,  hlp_cachecert },
    { "VALIDATE",   cmd_validate,   hlp_validate },
    { "KEYSERVER",  cmd_keyserver,  hlp_keyserver },
    { "KS_SEARCH",  cmd_ks_search,  hlp_ks_search },
    { "KS_GET",     cmd_ks_get,     hlp_ks_get },
    { "KS_FETCH",   cmd_ks_fetch,   hlp_ks_fetch },
    { "KS_PUT",     cmd_ks_put,     hlp_ks_put },
    { "GETINFO",    cmd_getinfo,    hlp_getinfo },
    { "KILLDIRMNGR",cmd_killdirmngr,hlp_killdirmngr },
    { "RELOADDIRMNGR",cmd_reloaddirmngr,hlp_reloaddirmngr },
    { NULL, NULL }
  };
  int i, j, rc;

  for (i=j=0; table[i].name; i++)
    {
      rc = assuan_register_command (ctx, table[i].name, table[i].handler,
                                    table[i].help);
      if (rc)
        return rc;
    }
  return 0;
}


/* Note that we do not reset the list of configured keyservers.  */
static gpg_error_t
reset_notify (assuan_context_t ctx, char *line)
{
  ctrl_t ctrl = assuan_get_pointer (ctx);
  (void)line;

#if USE_LDAP
  ldapserver_list_free (ctrl->server_local->ldapservers);
#endif /*USE_LDAP*/
  ctrl->server_local->ldapservers = NULL;
  return 0;
}


/* Startup the server and run the main command loop.  With FD = -1,
   use stdin/stdout. */
void
start_command_handler (assuan_fd_t fd)
{
  static const char hello[] = "Dirmngr " VERSION " at your service";
  static char *hello_line;
  int rc;
  assuan_context_t ctx;
  ctrl_t ctrl;

  ctrl = xtrycalloc (1, sizeof *ctrl);
  if (ctrl)
    ctrl->server_local = xtrycalloc (1, sizeof *ctrl->server_local);
  if (!ctrl || !ctrl->server_local)
    {
      log_error (_("can't allocate control structure: %s\n"),
                 strerror (errno));
      xfree (ctrl);
      return;
    }

  dirmngr_init_default_ctrl (ctrl);

  rc = assuan_new (&ctx);
  if (rc)
    {
      log_error (_("failed to allocate assuan context: %s\n"),
		 gpg_strerror (rc));
      dirmngr_exit (2);
    }

  if (fd == ASSUAN_INVALID_FD)
    {
      assuan_fd_t filedes[2];

      filedes[0] = assuan_fdopen (0);
      filedes[1] = assuan_fdopen (1);
      rc = assuan_init_pipe_server (ctx, filedes);
    }
  else
    {
      rc = assuan_init_socket_server (ctx, fd, ASSUAN_SOCKET_SERVER_ACCEPTED);
    }

  if (rc)
    {
      assuan_release (ctx);
      log_error (_("failed to initialize the server: %s\n"),
                 gpg_strerror(rc));
      dirmngr_exit (2);
    }

  rc = register_commands (ctx);
  if (rc)
    {
      log_error (_("failed to the register commands with Assuan: %s\n"),
                 gpg_strerror(rc));
      dirmngr_exit (2);
    }


  if (!hello_line)
    {
      size_t n;
      const char *cfgname;

      cfgname = opt.config_filename? opt.config_filename : "[none]";

      n = (30 + strlen (opt.homedir) + strlen (cfgname)
           + strlen (hello) + 1);
      hello_line = xmalloc (n+1);
      snprintf (hello_line, n,
                "Home: %s\n"
                "Config: %s\n"
                "%s",
                opt.homedir,
                cfgname,
                hello);
      hello_line[n] = 0;
    }

  ctrl->server_local->assuan_ctx = ctx;
  assuan_set_pointer (ctx, ctrl);

  assuan_set_hello_line (ctx, hello_line);
  assuan_register_option_handler (ctx, option_handler);
  assuan_register_reset_notify (ctx, reset_notify);

  for (;;)
    {
      rc = assuan_accept (ctx);
      if (rc == -1)
        break;
      if (rc)
        {
          log_info (_("Assuan accept problem: %s\n"), gpg_strerror (rc));
          break;
        }

#ifndef HAVE_W32_SYSTEM
      if (opt.verbose)
        {
	  assuan_peercred_t peercred;

          if (!assuan_get_peercred (ctx, &peercred))
            log_info ("connection from process %ld (%ld:%ld)\n",
                      (long)peercred->pid, (long)peercred->uid,
		      (long)peercred->gid);
        }
#endif

      rc = assuan_process (ctx);
      if (rc)
        {
          log_info (_("Assuan processing failed: %s\n"), gpg_strerror (rc));
          continue;
        }
    }

#if USE_LDAP
  ldap_wrapper_connection_cleanup (ctrl);

  ldapserver_list_free (ctrl->server_local->ldapservers);
#endif /*USE_LDAP*/
  ctrl->server_local->ldapservers = NULL;

  ctrl->server_local->assuan_ctx = NULL;
  assuan_release (ctx);

  if (ctrl->server_local->stopme)
    dirmngr_exit (0);

  if (ctrl->refcount)
    log_error ("oops: connection control structure still referenced (%d)\n",
               ctrl->refcount);
  else
    {
      release_ctrl_ocsp_certs (ctrl);
      xfree (ctrl->server_local);
      dirmngr_deinit_default_ctrl (ctrl);
      xfree (ctrl);
    }
}


/* Send a status line back to the client.  KEYWORD is the status
   keyword, the optional string arguments are blank separated added to
   the line, the last argument must be a NULL. */
gpg_error_t
dirmngr_status (ctrl_t ctrl, const char *keyword, ...)
{
  gpg_error_t err = 0;
  va_list arg_ptr;
  const char *text;

  va_start (arg_ptr, keyword);

  if (ctrl->server_local)
    {
      assuan_context_t ctx = ctrl->server_local->assuan_ctx;
      char buf[950], *p;
      size_t n;

      p = buf;
      n = 0;
      while ( (text = va_arg (arg_ptr, const char *)) )
        {
          if (n)
            {
              *p++ = ' ';
              n++;
            }
          for ( ; *text && n < DIM (buf)-2; n++)
            *p++ = *text++;
        }
      *p = 0;
      err = assuan_write_status (ctx, keyword, buf);
    }

  va_end (arg_ptr);
  return err;
}


/* Print a help status line.  TEXTLEN gives the length of the text
   from TEXT to be printed.  The function splits text at LFs.  */
gpg_error_t
dirmngr_status_help (ctrl_t ctrl, const char *text)
{
  gpg_error_t err = 0;

  if (ctrl->server_local)
    {
      assuan_context_t ctx = ctrl->server_local->assuan_ctx;
      char buf[950], *p;
      size_t n;

      do
        {
          p = buf;
          n = 0;
          for ( ; *text && *text != '\n' && n < DIM (buf)-2; n++)
            *p++ = *text++;
          if (*text == '\n')
            text++;
          *p = 0;
          err = assuan_write_status (ctx, "#", buf);
        }
      while (!err && *text);
    }

  return err;
}

/* Send a tick progress indicator back.  Fixme: This is only done for
   the currently active channel.  */
gpg_error_t
dirmngr_tick (ctrl_t ctrl)
{
  static time_t next_tick = 0;
  gpg_error_t err = 0;
  time_t now = time (NULL);

  if (!next_tick)
    {
      next_tick = now + 1;
    }
  else if ( now > next_tick )
    {
      if (ctrl)
        {
          err = dirmngr_status (ctrl, "PROGRESS", "tick", "? 0 0", NULL);
          if (err)
            {
              /* Take this as in indication for a cancel request.  */
              err = gpg_error (GPG_ERR_CANCELED);
            }
          now = time (NULL);
        }

      next_tick = now + 1;
    }
  return err;
}
