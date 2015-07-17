/* gpgv.c - The GnuPG signature verify utility
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2005, 2006,
 *               2008, 2009, 2012 Free Software Foundation, Inc.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_DOSISH_SYSTEM
#include <fcntl.h> /* for setmode() */
#endif
#ifdef HAVE_LIBREADLINE
#define GNUPG_LIBREADLINE_H_INCLUDED
#include <readline/readline.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"
#include "util.h"
#include "packet.h"
#include "iobuf.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"
#include "sysutils.h"
#include "status.h"
#include "call-agent.h"
#include "../common/init.h"


enum cmd_and_opt_values {
  aNull = 0,
  oQuiet	  = 'q',
  oVerbose	  = 'v',
  oBatch	  = 500,
  oKeyring,
  oIgnoreTimeConflict,
  oStatusFD,
  oLoggerFD,
  oHomedir,
  aTest
};


static ARGPARSE_OPTS opts[] = {
  ARGPARSE_group (300, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,   "quiet",   N_("be somewhat more quiet")),
  ARGPARSE_s_s (oKeyring, "keyring",
                N_("|FILE|take the keys from the keyring FILE")),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict",
                N_("make timestamp conflicts only a warning")),
  ARGPARSE_s_i (oStatusFD, "status-fd",
                N_("|FD|write status info to this FD")),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),

  ARGPARSE_end ()
};



int g10_errors_seen = 0;


static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  const char *s;
  char *result;

  s = getfnc (NULL);
  result = xmalloc (strlen (libname) + 1 + strlen (s) + 1);
  strcpy (stpcpy (stpcpy (result, libname), " "), s);
  return result;
}

static const char *
my_strusage( int level )
{
  static char *ver_gcry;
  const char *p;

  switch (level)
    {
    case 11: p = "@GPG@v (GnuPG)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 1:
    case 40: p = _("Usage: gpgv [options] [files] (-h for help)");
      break;
    case 41: p = _("Syntax: gpgv [options] [files]\n"
                   "Check signatures against known trusted keys\n");
	break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;


    default: p = NULL;
    }
  return p;
}



int
main( int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int rc=0;
  strlist_t sl;
  strlist_t nrings = NULL;
  unsigned configlineno;
  ctrl_t ctrl;

  early_system_init ();
  set_strusage (my_strusage);
  log_set_prefix ("gpgv", 1);

  /* Make sure that our subsystems are ready.  */
  i18n_init();
  init_common_subsystems (&argc, &argv);

  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal ( _("%s is too old (need %s, have %s)\n"), "libgcrypt",
                  NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

  gnupg_init_signals (0, NULL);

  opt.command_fd = -1; /* no command fd */
  opt.keyserver_options.options |= KEYSERVER_AUTO_KEY_RETRIEVE;
  opt.trust_model = TM_ALWAYS;
  opt.batch = 1;

  opt.homedir = default_homedir ();

  tty_no_terminal(1);
  tty_batchmode(1);
  dotlock_disable ();
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
  while (optfile_parse( NULL, NULL, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case oQuiet: opt.quiet = 1; break;
        case oVerbose:
          opt.verbose++;
          opt.list_sigs=1;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;
        case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
        case oStatusFD: set_status_fd( pargs.r.ret_int ); break;
        case oLoggerFD:
          log_set_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
          break;
        case oHomedir: opt.homedir = pargs.r.ret_str; break;
        case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
        default : pargs.err = ARGPARSE_PRINT_ERROR; break;
	}
    }

  if (log_get_errorcount (0))
    g10_exit(2);

  if (opt.verbose > 1)
    set_packet_list_mode(1);

  /* Note: We open all keyrings in read-only mode.  */
  if (!nrings)  /* No keyring given: use default one. */
    keydb_add_resource ("trustedkeys" EXTSEP_S GPGEXT_GPG,
                        KEYDB_RESOURCE_FLAG_READONLY);
  for (sl = nrings; sl; sl = sl->next)
    keydb_add_resource (sl->d, KEYDB_RESOURCE_FLAG_READONLY);

  FREE_STRLIST (nrings);

  ctrl = xcalloc (1, sizeof *ctrl);

  if ((rc = verify_signatures (ctrl, argc, argv)))
    log_error("verify signatures failed: %s\n", gpg_strerror (rc) );

  xfree (ctrl);

  /* cleanup */
  g10_exit (0);
  return 8; /*NOTREACHED*/
}


void
g10_exit( int rc )
{
  rc = rc? rc : log_get_errorcount(0)? 2 : g10_errors_seen? 1 : 0;
  exit(rc );
}


/* Stub:
 * We have to override the trustcheck from pkclist.c becuase
 * this utility assumes that all keys in the keyring are trustworthy
 */
int
check_signatures_trust( PKT_signature *sig )
{
  (void)sig;
  return 0;
}

void
read_trust_options(byte *trust_model, ulong *created, ulong *nextcheck,
		   byte *marginals, byte *completes, byte *cert_depth,
		   byte *min_cert_level)
{
  (void)trust_model;
  (void)created;
  (void)nextcheck;
  (void)marginals;
  (void)completes;
  (void)cert_depth;
  (void)min_cert_level;
}

/* Stub:
 * We don't have the trustdb , so we have to provide some stub functions
 * instead
 */

int
cache_disabled_value(PKT_public_key *pk)
{
  (void)pk;
  return 0;
}

void
check_trustdb_stale(void)
{
}

int
get_validity_info (PKT_public_key *pk, PKT_user_id *uid)
{
  (void)pk;
  (void)uid;
  return '?';
}

unsigned int
get_validity (PKT_public_key *pk, PKT_user_id *uid)
{
  (void)pk;
  (void)uid;
  return 0;
}

const char *
trust_value_to_string (unsigned int value)
{
  (void)value;
  return "err";
}

const char *
uid_trust_string_fixed (PKT_public_key *key, PKT_user_id *uid)
{
  (void)key;
  (void)uid;
  return "err";
}

int
get_ownertrust_info (PKT_public_key *pk)
{
  (void)pk;
  return '?';
}

unsigned int
get_ownertrust (PKT_public_key *pk)
{
  (void)pk;
  return TRUST_UNKNOWN;
}


/* Stubs:
 * Because we only work with trusted keys, it does not make sense to
 * get them from a keyserver
 */

struct keyserver_spec *
keyserver_match (struct keyserver_spec *spec)
{
  (void)spec;
  return NULL;
}

int
keyserver_import_keyid (u32 *keyid, void *dummy)
{
  (void)keyid;
  (void)dummy;
  return -1;
}

int
keyserver_import_cert (const char *name)
{
  (void)name;
  return -1;
}

int
keyserver_import_pka (const char *name,unsigned char *fpr)
{
  (void)name;
  (void)fpr;
  return -1;
}

int
keyserver_import_name (const char *name,struct keyserver_spec *spec)
{
  (void)name;
  (void)spec;
  return -1;
}

int
keyserver_import_ldap (const char *name)
{
  (void)name;
  return -1;
}

/* Stub:
 * No encryption here but mainproc links to these functions.
 */
gpg_error_t
get_session_key (PKT_pubkey_enc *k, DEK *dek)
{
  (void)k;
  (void)dek;
  return GPG_ERR_GENERAL;
}

/* Stub: */
gpg_error_t
get_override_session_key (DEK *dek, const char *string)
{
  (void)dek;
  (void)string;
  return GPG_ERR_GENERAL;
}

/* Stub: */
int
decrypt_data (ctrl_t ctrl, void *procctx, PKT_encrypted *ed, DEK *dek)
{
  (void)ctrl;
  (void)procctx;
  (void)ed;
  (void)dek;
  return GPG_ERR_GENERAL;
}


/* Stub:
 * No interactive commands, so we don't need the helptexts
 */
void
display_online_help (const char *keyword)
{
  (void)keyword;
}

/* Stub:
 * We don't use secret keys, but getkey.c links to this
 */
int
check_secret_key (PKT_public_key *pk, int n)
{
  (void)pk;
  (void)n;
  return GPG_ERR_GENERAL;
}

/* Stub:
 * No secret key, so no passphrase needed
 */
DEK *
passphrase_to_dek (u32 *keyid, int pubkey_algo,
                   int cipher_algo, STRING2KEY *s2k, int mode,
                   const char *tmp, int *canceled)
{
  (void)keyid;
  (void)pubkey_algo;
  (void)cipher_algo;
  (void)s2k;
  (void)mode;
  (void)tmp;

  if (canceled)
    *canceled = 0;
  return NULL;
}

void
passphrase_clear_cache (u32 *keyid, const char *cacheid, int algo)
{
  (void)keyid;
  (void)cacheid;
  (void)algo;
}

struct keyserver_spec *
parse_preferred_keyserver(PKT_signature *sig)
{
  (void)sig;
  return NULL;
}

struct keyserver_spec *
parse_keyserver_uri (const char *uri, int require_scheme,
                     const char *configname, unsigned int configlineno)
{
  (void)uri;
  (void)require_scheme;
  (void)configname;
  (void)configlineno;
  return NULL;
}

void
free_keyserver_spec (struct keyserver_spec *keyserver)
{
  (void)keyserver;
}

/* Stubs to avoid linking to photoid.c */
void
show_photos (const struct user_attribute *attrs, int count, PKT_public_key *pk)
{
  (void)attrs;
  (void)count;
  (void)pk;
}

int
parse_image_header (const struct user_attribute *attr, byte *type, u32 *len)
{
  (void)attr;
  (void)type;
  (void)len;
  return 0;
}

char *
image_type_to_string (byte type, int string)
{
  (void)type;
  (void)string;
  return NULL;
}

#ifdef ENABLE_CARD_SUPPORT
int
agent_scd_getattr (const char *name, struct agent_card_info_s *info)
{
  (void)name;
  (void)info;
  return 0;
}
#endif /* ENABLE_CARD_SUPPORT */

/* We do not do any locking, so use these stubs here */
void
dotlock_disable (void)
{
}

dotlock_t
dotlock_create (const char *file_to_lock, unsigned int flags)
{
  (void)file_to_lock;
  (void)flags;
  return NULL;
}

void
dotlock_destroy (dotlock_t h)
{
  (void)h;
}

int
dotlock_take (dotlock_t h, long timeout)
{
  (void)h;
  (void)timeout;
  return 0;
}

int
dotlock_release (dotlock_t h)
{
  (void)h;
  return 0;
}

void
dotlock_remove_lockfiles (void)
{
}

gpg_error_t
agent_probe_secret_key (ctrl_t ctrl, PKT_public_key *pk)
{
  (void)ctrl;
  (void)pk;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
agent_probe_any_secret_key (ctrl_t ctrl, kbnode_t keyblock)
{
  (void)ctrl;
  (void)keyblock;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
agent_get_keyinfo (ctrl_t ctrl, const char *hexkeygrip, char **r_serialno)
{
  (void)ctrl;
  (void)hexkeygrip;
  *r_serialno = NULL;
  return gpg_error (GPG_ERR_NO_SECKEY);
}

gpg_error_t
gpg_dirmngr_get_pka (ctrl_t ctrl, const char *userid,
                     unsigned char **r_fpr, size_t *r_fprlen,
                     char **r_url)
{
  (void)ctrl;
  (void)userid;
  if (r_fpr)
    *r_fpr = NULL;
  if (r_fprlen)
    *r_fprlen = 0;
  if (r_url)
    *r_url = NULL;
  return gpg_error (GPG_ERR_NOT_FOUND);
}
