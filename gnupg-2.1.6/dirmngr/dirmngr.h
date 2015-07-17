/* dirmngr.h - Common definitions for the dirmngr
 * Copyright (C) 2002 Klarälvdalens Datakonsult AB
 * Copyright (C) 2004, 2015 g10 Code GmbH
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

#ifndef DIRMNGR_H
#define DIRMNGR_H

#include "./dirmngr-err.h"
#define map_assuan_err(a) \
        map_assuan_err_with_source (GPG_ERR_SOURCE_DEFAULT, (a))
#include <errno.h>
#include <gcrypt.h>
#include <ksba.h>

#include "../common/util.h"
#include "../common/membuf.h"
#include "../common/sysutils.h" /* (gnupg_fd_t) */
#include "../common/i18n.h"
#include "../common/http.h"     /* (parsed_uri_t) */

/* This objects keeps information about a particular LDAP server and
   is used as item of a single linked list of servers. */
struct ldap_server_s
{
  struct ldap_server_s* next;

  char *host;
  int   port;
  char *user;
  char *pass;
  char *base;
};
typedef struct ldap_server_s *ldap_server_t;


/* This objects is used to build a list of URI consisting of the
   original and the parsed URI.  */
struct uri_item_s
{
  struct uri_item_s *next;
  parsed_uri_t parsed_uri;  /* The broken down URI.  */
  char uri[1];              /* The original URI.  */
};
typedef struct uri_item_s *uri_item_t;


/* A list of fingerprints.  */
struct fingerprint_list_s;
typedef struct fingerprint_list_s *fingerprint_list_t;
struct fingerprint_list_s
{
  fingerprint_list_t next;
  char hexfpr[20+20+1];
};


/* A large struct named "opt" to keep global flags.  */
struct
{
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int verbose;        /* verbosity level */
  int quiet;          /* be as quiet as possible */
  int dry_run;        /* don't change any persistent data */
  int batch;          /* batch mode */
  const char *homedir;      /* Configuration directory name */
  const char *homedir_cache; /* Ditto for cache files (/var/cache/dirmngr).  */

  char *config_filename;     /* Name of a config file, which will be
                                reread on a HUP if it is not NULL. */

  char *ldap_wrapper_program; /* Override value for the LDAP wrapper
                                 program.  */
  char *http_wrapper_program; /* Override value for the HTTP wrapper
                                 program.  */

  int system_service;   /* We are running as W32 service (implies daemon).  */
  int system_daemon;    /* We are running in system daemon mode.  */
  int running_detached; /* We are running in detached mode.  */

  int force;          /* Force loading outdated CRLs. */

  int disable_http;       /* Do not use HTTP at all.  */
  int disable_ldap;       /* Do not use LDAP at all.  */
  int honor_http_proxy;   /* Honor the http_proxy env variable. */
  const char *http_proxy; /* The default HTTP proxy.  */
  const char *ldap_proxy; /* Use given LDAP proxy.  */
  int only_ldap_proxy;    /* Only use the LDAP proxy; no fallback.  */
  int ignore_http_dp;     /* Ignore HTTP CRL distribution points.  */
  int ignore_ldap_dp;     /* Ignore LDAP CRL distribution points.  */
  int ignore_ocsp_service_url; /* Ignore OCSP service URLs as given in
                                  the certificate.  */

  /* A list of certificate extension OIDs which are ignored so that
     one can claim that a critical extension has been handled.  One
     OID per string.  */
  strlist_t ignored_cert_extensions;

  int allow_ocsp;     /* Allow using OCSP. */

  int max_replies;
  unsigned int ldaptimeout;

  ldap_server_t ldapservers;
  int add_new_ldapservers;

  const char *ocsp_responder;     /* Standard OCSP responder's URL. */
  fingerprint_list_t ocsp_signer; /* The list of fingerprints with allowed
                                     standard OCSP signer certificates.  */

  unsigned int ocsp_max_clock_skew; /* Allowed seconds of clocks skew. */
  unsigned int ocsp_max_period;     /* Seconds a response is at maximum
                                       considered valid after thisUpdate. */
  unsigned int ocsp_current_period; /* Seconds a response is considered
                                       current after nextUpdate. */
} opt;


#define DBG_X509_VALUE    1	/* debug x.509 parsing */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_IPC_VALUE     1024  /* debug assuan communication */
#define DBG_LOOKUP_VALUE  8192  /* debug lookup details */

#define DBG_X509    (opt.debug & DBG_X509_VALUE)
#define DBG_CRYPTO  (opt.debug & DBG_CRYPTO_VALUE)
#define DBG_MEMORY  (opt.debug & DBG_MEMORY_VALUE)
#define DBG_CACHE   (opt.debug & DBG_CACHE_VALUE)
#define DBG_HASHING (opt.debug & DBG_HASHING_VALUE)
#define DBG_IPC     (opt.debug & DBG_IPC_VALUE)
#define DBG_LOOKUP  (opt.debug & DBG_LOOKUP_VALUE)

/* A simple list of certificate references. */
struct cert_ref_s
{
  struct cert_ref_s *next;
  unsigned char fpr[20];
};
typedef struct cert_ref_s *cert_ref_t;

/* Forward references; access only through server.c.  */
struct server_local_s;

/* Connection control structure.  */
struct server_control_s
{
  int refcount;      /* Count additional references to this object.  */
  int no_server;     /* We are not running under server control. */
  int status_fd;     /* Only for non-server mode. */
  struct server_local_s *server_local;
  int force_crl_refresh; /* Always load a fresh CRL. */

  int check_revocations_nest_level; /* Internal to check_revovations.  */
  cert_ref_t ocsp_certs; /* Certificates from the current OCSP
                            response. */

  int audit_events;  /* Send audit events to client.  */
  char *http_proxy;  /* The used http_proxy or NULL.  */
};


/*-- dirmngr.c --*/
void dirmngr_exit( int );  /* Wrapper for exit() */
void dirmngr_init_default_ctrl (ctrl_t ctrl);
void dirmngr_deinit_default_ctrl (ctrl_t ctrl);
void dirmngr_sighup_action (void);


/*-- Various housekeeping functions.  --*/
void ks_hkp_housekeeping (time_t curtime);


/*-- server.c --*/
ldap_server_t get_ldapservers_from_ctrl (ctrl_t ctrl);
ksba_cert_t get_cert_local (ctrl_t ctrl, const char *issuer);
ksba_cert_t get_issuing_cert_local (ctrl_t ctrl, const char *issuer);
ksba_cert_t get_cert_local_ski (ctrl_t ctrl,
                                const char *name, ksba_sexp_t keyid);
gpg_error_t get_istrusted_from_client (ctrl_t ctrl, const char *hexfpr);
void start_command_handler (gnupg_fd_t fd);
gpg_error_t dirmngr_status (ctrl_t ctrl, const char *keyword, ...);
gpg_error_t dirmngr_status_help (ctrl_t ctrl, const char *text);
gpg_error_t dirmngr_tick (ctrl_t ctrl);



#endif /*DIRMNGR_H*/
