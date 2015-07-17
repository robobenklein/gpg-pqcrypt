/* import.c - import a key into our key storage.
 * Copyright (C) 1998-2007, 2010-2011 Free Software Foundation, Inc.
 * Copyright (C) 2014  Werner Koch
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
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpg.h"
#include "options.h"
#include "packet.h"
#include "status.h"
#include "keydb.h"
#include "util.h"
#include "trustdb.h"
#include "main.h"
#include "i18n.h"
#include "ttyio.h"
#include "status.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "../common/membuf.h"

struct stats_s
{
  ulong count;
  ulong no_user_id;
  ulong imported;
  ulong n_uids;
  ulong n_sigs;
  ulong n_subk;
  ulong unchanged;
  ulong n_revoc;
  ulong secret_read;
  ulong secret_imported;
  ulong secret_dups;
  ulong skipped_new_keys;
  ulong not_imported;
  ulong n_sigs_cleaned;
  ulong n_uids_cleaned;
  ulong v3keys;   /* Number of V3 keys seen.  */
};


static int import (ctrl_t ctrl,
                   IOBUF inp, const char* fname, struct stats_s *stats,
		   unsigned char **fpr, size_t *fpr_len, unsigned int options,
		   import_screener_t screener, void *screener_arg);
static int read_block (IOBUF a, PACKET **pending_pkt, kbnode_t *ret_root,
                       int *r_v3keys);
static void revocation_present (ctrl_t ctrl, kbnode_t keyblock);
static int import_one (ctrl_t ctrl,
                       const char *fname, kbnode_t keyblock,struct stats_s *stats,
                       unsigned char **fpr, size_t *fpr_len,
                       unsigned int options, int from_sk, int silent,
                       import_screener_t screener, void *screener_arg);
static int import_secret_one (ctrl_t ctrl, const char *fname, kbnode_t keyblock,
                              struct stats_s *stats, int batch,
                              unsigned int options, int for_migration,
                              import_screener_t screener, void *screener_arg);
static int import_revoke_cert( const char *fname, kbnode_t node,
                               struct stats_s *stats);
static int chk_self_sigs (const char *fname, kbnode_t keyblock,
			  PKT_public_key *pk, u32 *keyid, int *non_self );
static int delete_inv_parts (const char *fname, kbnode_t keyblock,
			     u32 *keyid, unsigned int options );
static int merge_blocks (const char *fname, kbnode_t keyblock_orig,
			 kbnode_t keyblock, u32 *keyid,
			 int *n_uids, int *n_sigs, int *n_subk );
static int append_uid (kbnode_t keyblock, kbnode_t node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int append_key (kbnode_t keyblock, kbnode_t node, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_sigs (kbnode_t dst, kbnode_t src, int *n_sigs,
			     const char *fname, u32 *keyid );
static int merge_keysigs (kbnode_t dst, kbnode_t src, int *n_sigs,
			     const char *fname, u32 *keyid );

int
parse_import_options(char *str,unsigned int *options,int noisy)
{
  struct parse_options import_opts[]=
    {
      {"import-local-sigs",IMPORT_LOCAL_SIGS,NULL,
       N_("import signatures that are marked as local-only")},

      {"repair-pks-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,
       N_("repair damage from the pks keyserver during import")},

      {"keep-ownertrust", IMPORT_KEEP_OWNERTTRUST, NULL,
       N_("do not clear the ownertrust values during import")},

      {"fast-import",IMPORT_FAST,NULL,
       N_("do not update the trustdb after import")},

      {"merge-only",IMPORT_MERGE_ONLY,NULL,
       N_("only accept updates to existing keys")},

      {"import-clean",IMPORT_CLEAN,NULL,
       N_("remove unusable parts from key after import")},

      {"import-minimal",IMPORT_MINIMAL|IMPORT_CLEAN,NULL,
       N_("remove as much as possible from key after import")},

      /* Aliases for backward compatibility */
      {"allow-local-sigs",IMPORT_LOCAL_SIGS,NULL,NULL},
      {"repair-hkp-subkey-bug",IMPORT_REPAIR_PKS_SUBKEY_BUG,NULL,NULL},
      /* dummy */
      {"import-unusable-sigs",0,NULL,NULL},
      {"import-clean-sigs",0,NULL,NULL},
      {"import-clean-uids",0,NULL,NULL},
      {"convert-sk-to-pk",0, NULL,NULL}, /* Not anymore needed due to
                                            the new design.  */
      {NULL,0,NULL,NULL}
    };

  return parse_options(str,options,import_opts,noisy);
}


void *
import_new_stats_handle (void)
{
  return xmalloc_clear ( sizeof (struct stats_s) );
}


void
import_release_stats_handle (void *p)
{
  xfree (p);
}


/*
 * Import the public keys from the given filename. Input may be armored.
 * This function rejects all keys which are not validly self signed on at
 * least one userid. Only user ids which are self signed will be imported.
 * Other signatures are not checked.
 *
 * Actually this function does a merge. It works like this:
 *
 *  - get the keyblock
 *  - check self-signatures and remove all userids and their signatures
 *    without/invalid self-signatures.
 *  - reject the keyblock, if we have no valid userid.
 *  - See whether we have this key already in one of our pubrings.
 *    If not, simply add it to the default keyring.
 *  - Compare the key and the self-signatures of the new and the one in
 *    our keyring.  If they are different something weird is going on;
 *    ask what to do.
 *  - See whether we have only non-self-signature on one user id; if not
 *    ask the user what to do.
 *  - compare the signatures: If we already have this signature, check
 *    that they compare okay; if not, issue a warning and ask the user.
 *    (consider looking at the timestamp and use the newest?)
 *  - Simply add the signature.  Can't verify here because we may not have
 *    the signature's public key yet; verification is done when putting it
 *    into the trustdb, which is done automagically as soon as this pubkey
 *    is used.
 *  - Proceed with next signature.
 *
 *  Key revocation certificates have special handling.
 */
static int
import_keys_internal (ctrl_t ctrl, iobuf_t inp, char **fnames, int nnames,
		      void *stats_handle, unsigned char **fpr, size_t *fpr_len,
		      unsigned int options,
                      import_screener_t screener, void *screener_arg)
{
  int i;
  int rc = 0;
  struct stats_s *stats = stats_handle;

  if (!stats)
    stats = import_new_stats_handle ();

  if (inp)
    {
      rc = import (ctrl, inp, "[stream]", stats, fpr, fpr_len, options,
                   screener, screener_arg);
    }
  else
    {
      if (!fnames && !nnames)
        nnames = 1;  /* Ohh what a ugly hack to jump into the loop */

      for (i=0; i < nnames; i++)
        {
          const char *fname = fnames? fnames[i] : NULL;
          IOBUF inp2 = iobuf_open(fname);

          if (!fname)
            fname = "[stdin]";
          if (inp2 && is_secured_file (iobuf_get_fd (inp2)))
            {
              iobuf_close (inp2);
              inp2 = NULL;
              gpg_err_set_errno (EPERM);
            }
          if (!inp2)
            log_error (_("can't open '%s': %s\n"), fname, strerror (errno));
          else
            {
              rc = import (ctrl, inp2, fname, stats, fpr, fpr_len, options,
                           screener, screener_arg);
              iobuf_close (inp2);
              /* Must invalidate that ugly cache to actually close it. */
              iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);
              if (rc)
                log_error ("import from '%s' failed: %s\n",
                           fname, gpg_strerror (rc) );
            }
          if (!fname)
            break;
	}
    }

  if (!stats_handle)
    {
      import_print_stats (stats);
      import_release_stats_handle (stats);
    }

  /* If no fast import and the trustdb is dirty (i.e. we added a key
     or userID that had something other than a selfsig, a signature
     that was other than a selfsig, or any revocation), then
     update/check the trustdb if the user specified by setting
     interactive or by not setting no-auto-check-trustdb */

  if (!(options & IMPORT_FAST))
    check_or_update_trustdb ();

  return rc;
}


void
import_keys (ctrl_t ctrl, char **fnames, int nnames,
	     void *stats_handle, unsigned int options )
{
  import_keys_internal (ctrl, NULL, fnames, nnames, stats_handle,
                        NULL, NULL, options, NULL, NULL);
}

int
import_keys_stream (ctrl_t ctrl, IOBUF inp, void *stats_handle,
		    unsigned char **fpr, size_t *fpr_len, unsigned int options)
{
  return import_keys_internal (ctrl, inp, NULL, 0, stats_handle,
                               fpr, fpr_len, options, NULL, NULL);
}


/* Variant of import_keys_stream reading from an estream_t.  */
int
import_keys_es_stream (ctrl_t ctrl, estream_t fp, void *stats_handle,
                       unsigned char **fpr, size_t *fpr_len,
                       unsigned int options,
                       import_screener_t screener, void *screener_arg)
{
  int rc;
  iobuf_t inp;

  inp = iobuf_esopen (fp, "r", 1);
  if (!inp)
    {
      rc = gpg_error_from_syserror ();
      log_error ("iobuf_esopen failed: %s\n", gpg_strerror (rc));
      return rc;
    }

  rc = import_keys_internal (ctrl, inp, NULL, 0, stats_handle,
                             fpr, fpr_len, options,
                             screener, screener_arg);

  iobuf_close (inp);
  return rc;
}


static int
import (ctrl_t ctrl, IOBUF inp, const char* fname,struct stats_s *stats,
	unsigned char **fpr,size_t *fpr_len, unsigned int options,
	import_screener_t screener, void *screener_arg)
{
  PACKET *pending_pkt = NULL;
  kbnode_t keyblock = NULL;  /* Need to initialize because gcc can't
                                grasp the return semantics of
                                read_block. */
  int rc = 0;
  int v3keys;

  getkey_disable_caches ();

  if (!opt.no_armor) /* Armored reading is not disabled.  */
    {
      armor_filter_context_t *afx;

      afx = new_armor_context ();
      afx->only_keyblocks = 1;
      push_armor_filter (afx, inp);
      release_armor_context (afx);
    }

  while (!(rc = read_block (inp, &pending_pkt, &keyblock, &v3keys)))
    {
      stats->v3keys += v3keys;
      if (keyblock->pkt->pkttype == PKT_PUBLIC_KEY)
        rc = import_one (ctrl, fname, keyblock,
                         stats, fpr, fpr_len, options, 0, 0,
                         screener, screener_arg);
      else if (keyblock->pkt->pkttype == PKT_SECRET_KEY)
        rc = import_secret_one (ctrl, fname, keyblock, stats,
                                opt.batch, options, 0,
                                screener, screener_arg);
      else if (keyblock->pkt->pkttype == PKT_SIGNATURE
               && keyblock->pkt->pkt.signature->sig_class == 0x20 )
        rc = import_revoke_cert( fname, keyblock, stats );
      else
        {
          log_info (_("skipping block of type %d\n"), keyblock->pkt->pkttype);
	}
      release_kbnode (keyblock);

      /* fixme: we should increment the not imported counter but
         this does only make sense if we keep on going despite of
         errors.  For now we do this only if the imported key is too
         large. */
      if (gpg_err_code (rc) == GPG_ERR_TOO_LARGE
            && gpg_err_source (rc) == GPG_ERR_SOURCE_KEYBOX)
        {
          stats->not_imported++;
          rc = 0;
        }
      else if (rc)
        break;

      if (!(++stats->count % 100) && !opt.quiet)
        log_info (_("%lu keys processed so far\n"), stats->count );
    }
  stats->v3keys += v3keys;
  if (rc == -1)
    rc = 0;
  else if (rc && gpg_err_code (rc) != GPG_ERR_INV_KEYRING)
    log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (rc));

  return rc;
}


/* Helper to migrate secring.gpg to GnuPG 2.1.  */
gpg_error_t
import_old_secring (ctrl_t ctrl, const char *fname)
{
  gpg_error_t err;
  iobuf_t inp;
  PACKET *pending_pkt = NULL;
  kbnode_t keyblock = NULL;  /* Need to initialize because gcc can't
                                grasp the return semantics of
                                read_block. */
  struct stats_s *stats;
  int v3keys;

  inp = iobuf_open (fname);
  if (inp && is_secured_file (iobuf_get_fd (inp)))
    {
      iobuf_close (inp);
      inp = NULL;
      gpg_err_set_errno (EPERM);
    }
  if (!inp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("can't open '%s': %s\n"), fname, gpg_strerror (err));
      return err;
    }

  getkey_disable_caches();
  stats = import_new_stats_handle ();
  while (!(err = read_block (inp, &pending_pkt, &keyblock, &v3keys)))
    {
      if (keyblock->pkt->pkttype == PKT_SECRET_KEY)
        err = import_secret_one (ctrl, fname, keyblock, stats, 1, 0, 1,
                                 NULL, NULL);
      release_kbnode (keyblock);
      if (err)
        break;
    }
  import_release_stats_handle (stats);
  if (err == -1)
    err = 0;
  else if (err && gpg_err_code (err) != GPG_ERR_INV_KEYRING)
    log_error (_("error reading '%s': %s\n"), fname, gpg_strerror (err));
  else if (err)
    log_error ("import from '%s' failed: %s\n", fname, gpg_strerror (err));

  iobuf_close (inp);
  iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);

  return err;
}


void
import_print_stats (void *hd)
{
  struct stats_s *stats = hd;

  if (!opt.quiet)
    {
      log_info(_("Total number processed: %lu\n"),
               stats->count + stats->v3keys);
      if (stats->v3keys)
        log_info(_("    skipped PGP-2 keys: %lu\n"), stats->v3keys);
      if (stats->skipped_new_keys )
        log_info(_("      skipped new keys: %lu\n"),
                 stats->skipped_new_keys );
      if (stats->no_user_id )
        log_info(_("          w/o user IDs: %lu\n"), stats->no_user_id );
      if (stats->imported)
        {
          log_info(_("              imported: %lu"), stats->imported );
          log_printf ("\n");
        }
      if (stats->unchanged )
        log_info(_("             unchanged: %lu\n"), stats->unchanged );
      if (stats->n_uids )
        log_info(_("          new user IDs: %lu\n"), stats->n_uids );
      if (stats->n_subk )
        log_info(_("           new subkeys: %lu\n"), stats->n_subk );
      if (stats->n_sigs )
        log_info(_("        new signatures: %lu\n"), stats->n_sigs );
      if (stats->n_revoc )
        log_info(_("   new key revocations: %lu\n"), stats->n_revoc );
      if (stats->secret_read )
        log_info(_("      secret keys read: %lu\n"), stats->secret_read );
      if (stats->secret_imported )
        log_info(_("  secret keys imported: %lu\n"), stats->secret_imported );
      if (stats->secret_dups )
        log_info(_(" secret keys unchanged: %lu\n"), stats->secret_dups );
      if (stats->not_imported )
        log_info(_("          not imported: %lu\n"), stats->not_imported );
      if (stats->n_sigs_cleaned)
        log_info(_("    signatures cleaned: %lu\n"),stats->n_sigs_cleaned);
      if (stats->n_uids_cleaned)
        log_info(_("      user IDs cleaned: %lu\n"),stats->n_uids_cleaned);
    }

  if (is_status_enabled ())
    {
      char buf[15*20];

      snprintf (buf, sizeof buf,
                "%lu %lu %lu 0 %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		stats->count + stats->v3keys,
		stats->no_user_id,
		stats->imported,
		stats->unchanged,
		stats->n_uids,
		stats->n_subk,
		stats->n_sigs,
		stats->n_revoc,
		stats->secret_read,
		stats->secret_imported,
		stats->secret_dups,
		stats->skipped_new_keys,
                stats->not_imported,
                stats->v3keys );
      write_status_text (STATUS_IMPORT_RES, buf);
    }
}


/* Return true if PKTTYPE is valid in a keyblock.  */
static int
valid_keyblock_packet (int pkttype)
{
  switch (pkttype)
    {
    case PKT_PUBLIC_KEY:
    case PKT_PUBLIC_SUBKEY:
    case PKT_SECRET_KEY:
    case PKT_SECRET_SUBKEY:
    case PKT_SIGNATURE:
    case PKT_USER_ID:
    case PKT_ATTRIBUTE:
    case PKT_RING_TRUST:
      return 1;
    default:
      return 0;
    }
}


/****************
 * Read the next keyblock from stream A.
 * PENDING_PKT should be initialzed to NULL
 * and not changed by the caller.
 * Return: 0 = okay, -1 no more blocks or another errorcode.
 *         The int at at R_V3KEY counts the number of unsupported v3
 *         keyblocks.
 */
static int
read_block( IOBUF a, PACKET **pending_pkt, kbnode_t *ret_root, int *r_v3keys)
{
  int rc;
  PACKET *pkt;
  kbnode_t root = NULL;
  int in_cert, in_v3key;

  *r_v3keys = 0;

  if (*pending_pkt)
    {
      root = new_kbnode( *pending_pkt );
      *pending_pkt = NULL;
      in_cert = 1;
    }
  else
    in_cert = 0;

  pkt = xmalloc (sizeof *pkt);
  init_packet (pkt);
  in_v3key = 0;
  while ((rc=parse_packet(a, pkt)) != -1)
    {
      if (rc && (gpg_err_code (rc) == GPG_ERR_LEGACY_KEY
                 && (pkt->pkttype == PKT_PUBLIC_KEY
                     || pkt->pkttype == PKT_SECRET_KEY)))
        {
          in_v3key = 1;
          ++*r_v3keys;
          free_packet (pkt);
          init_packet (pkt);
          continue;
        }
      else if (rc ) /* (ignore errors) */
        {
          if (gpg_err_code (rc) == GPG_ERR_UNKNOWN_PACKET)
            ; /* Do not show a diagnostic.  */
          else
            {
              log_error("read_block: read error: %s\n", gpg_strerror (rc) );
              rc = GPG_ERR_INV_KEYRING;
              goto ready;
            }
          free_packet( pkt );
          init_packet(pkt);
          continue;
	}

        if (in_v3key && !(pkt->pkttype == PKT_PUBLIC_KEY
                          || pkt->pkttype == PKT_SECRET_KEY))
          {
	    free_packet( pkt );
	    init_packet(pkt);
	    continue;
          }
        in_v3key = 0;

	if (!root && pkt->pkttype == PKT_SIGNATURE
		  && pkt->pkt.signature->sig_class == 0x20 )
          {
	    /* This is a revocation certificate which is handled in a
	     * special way.  */
	    root = new_kbnode( pkt );
	    pkt = NULL;
	    goto ready;
          }

	/* Make a linked list of all packets.  */
	switch (pkt->pkttype)
          {
	  case PKT_COMPRESSED:
	    if (check_compress_algo (pkt->pkt.compressed->algorithm))
	      {
		rc = GPG_ERR_COMPR_ALGO;
		goto ready;
	      }
	    else
	      {
		compress_filter_context_t *cfx = xmalloc_clear( sizeof *cfx );
		pkt->pkt.compressed->buf = NULL;
		push_compress_filter2(a,cfx,pkt->pkt.compressed->algorithm,1);
	      }
	    free_packet( pkt );
	    init_packet(pkt);
	    break;

          case PKT_RING_TRUST:
            /* Skip those packets.  */
	    free_packet( pkt );
	    init_packet(pkt);
            break;

	  case PKT_PUBLIC_KEY:
	  case PKT_SECRET_KEY:
	    if (in_cert ) /* Store this packet.  */
              {
		*pending_pkt = pkt;
		pkt = NULL;
		goto ready;
              }
	    in_cert = 1;
	  default:
	    if (in_cert && valid_keyblock_packet (pkt->pkttype))
              {
		if (!root )
                  root = new_kbnode (pkt);
		else
                  add_kbnode (root, new_kbnode (pkt));
		pkt = xmalloc (sizeof *pkt);
              }
	    init_packet(pkt);
	    break;
          }
    }

 ready:
  if (rc == -1 && root )
    rc = 0;

  if (rc )
    release_kbnode( root );
  else
    *ret_root = root;
  free_packet( pkt );
  xfree( pkt );
  return rc;
}


/* Walk through the subkeys on a pk to find if we have the PKS
   disease: multiple subkeys with their binding sigs stripped, and the
   sig for the first subkey placed after the last subkey.  That is,
   instead of "pk uid sig sub1 bind1 sub2 bind2 sub3 bind3" we have
   "pk uid sig sub1 sub2 sub3 bind1".  We can't do anything about sub2
   and sub3, as they are already lost, but we can try and rescue sub1
   by reordering the keyblock so that it reads "pk uid sig sub1 bind1
   sub2 sub3".  Returns TRUE if the keyblock was modified. */
static int
fix_pks_corruption (kbnode_t keyblock)
{
  int changed = 0;
  int keycount = 0;
  kbnode_t node;
  kbnode_t last = NULL;
  kbnode_t sknode=NULL;

  /* First determine if we have the problem at all.  Look for 2 or
     more subkeys in a row, followed by a single binding sig. */
  for (node=keyblock; node; last=node, node=node->next)
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  keycount++;
	  if(!sknode)
	    sknode=node;
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && node->pkt->pkt.signature->sig_class == 0x18
               && keycount >= 2
               && !node->next)
	{
	  /* We might have the problem, as this key has two subkeys in
	     a row without any intervening packets. */

	  /* Sanity check */
	  if (!last)
	    break;

	  /* Temporarily attach node to sknode. */
	  node->next = sknode->next;
	  sknode->next = node;
	  last->next = NULL;

	  /* Note we aren't checking whether this binding sig is a
	     selfsig.  This is not necessary here as the subkey and
	     binding sig will be rejected later if that is the
	     case. */
	  if (check_key_signature (keyblock,node,NULL))
	    {
	      /* Not a match, so undo the changes. */
	      sknode->next = node->next;
	      last->next = node;
	      node->next = NULL;
	      break;
	    }
	  else
	    {
	      sknode->flag |= 1; /* Mark it good so we don't need to
                                    check it again */
	      changed = 1;
	      break;
	    }
	}
      else
	keycount = 0;
    }

  return changed;
}


/* Versions of GnuPG before 1.4.11 and 2.0.16 allowed to import bogus
   direct key signatures.  A side effect of this was that a later
   import of the same good direct key signatures was not possible
   because the cmp_signature check in merge_blocks considered them
   equal.  Although direct key signatures are now checked during
   import, there might still be bogus signatures sitting in a keyring.
   We need to detect and delete them before doing a merge.  This
   function returns the number of removed sigs.  */
static int
fix_bad_direct_key_sigs (kbnode_t keyblock, u32 *keyid)
{
  gpg_error_t err;
  kbnode_t node;
  int count = 0;

  for (node = keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        break;
      if (node->pkt->pkttype == PKT_SIGNATURE
          && IS_KEY_SIG (node->pkt->pkt.signature))
        {
          err = check_key_signature (keyblock, node, NULL);
          if (err && gpg_err_code (err) != GPG_ERR_PUBKEY_ALGO )
            {
              /* If we don't know the error, we can't decide; this is
                 not a problem because cmp_signature can't compare the
                 signature either.  */
              log_info ("key %s: invalid direct key signature removed\n",
                        keystr (keyid));
              delete_kbnode (node);
              count++;
            }
        }
    }

  return count;
}


static void
print_import_ok (PKT_public_key *pk, unsigned int reason)
{
  byte array[MAX_FINGERPRINT_LEN], *s;
  char buf[MAX_FINGERPRINT_LEN*2+30], *p;
  size_t i, n;

  snprintf (buf, sizeof buf, "%u ", reason);
  p = buf + strlen (buf);

  fingerprint_from_pk (pk, array, &n);
  s = array;
  for (i=0; i < n ; i++, s++, p += 2)
    sprintf (p, "%02X", *s);

  write_status_text (STATUS_IMPORT_OK, buf);
}


static void
print_import_check (PKT_public_key * pk, PKT_user_id * id)
{
  char * buf;
  byte fpr[24];
  u32 keyid[2];
  size_t i, n;
  size_t pos = 0;

  buf = xmalloc (17+41+id->len+32);
  keyid_from_pk (pk, keyid);
  sprintf (buf, "%08X%08X ", keyid[0], keyid[1]);
  pos = 17;
  fingerprint_from_pk (pk, fpr, &n);
  for (i = 0; i < n; i++, pos += 2)
    sprintf (buf+pos, "%02X", fpr[i]);
  strcat (buf, " ");
  pos += 1;
  strcat (buf, id->name);
  write_status_text (STATUS_IMPORT_CHECK, buf);
  xfree (buf);
}


static void
check_prefs_warning(PKT_public_key *pk)
{
  log_info(_("WARNING: key %s contains preferences for unavailable\n"
             "algorithms on these user IDs:\n"), keystr_from_pk(pk));
}


static void
check_prefs (ctrl_t ctrl, kbnode_t keyblock)
{
  kbnode_t node;
  PKT_public_key *pk;
  int problem=0;

  merge_keys_and_selfsig(keyblock);
  pk=keyblock->pkt->pkt.public_key;

  for(node=keyblock;node;node=node->next)
    {
      if(node->pkt->pkttype==PKT_USER_ID
	 && node->pkt->pkt.user_id->created
	 && node->pkt->pkt.user_id->prefs)
	{
	  PKT_user_id *uid = node->pkt->pkt.user_id;
	  prefitem_t *prefs = uid->prefs;
	  char *user = utf8_to_native(uid->name,strlen(uid->name),0);

	  for(;prefs->type;prefs++)
	    {
	      char num[10]; /* prefs->value is a byte, so we're over
			       safe here */

	      sprintf(num,"%u",prefs->value);

	      if(prefs->type==PREFTYPE_SYM)
		{
		  if (openpgp_cipher_test_algo (prefs->value))
		    {
		      const char *algo =
                        (openpgp_cipher_test_algo (prefs->value)
                         ? num
                         : openpgp_cipher_algo_name (prefs->value));
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for cipher"
				 " algorithm %s\n"), user, algo);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_HASH)
		{
		  if(openpgp_md_test_algo(prefs->value))
		    {
		      const char *algo =
                        (gcry_md_test_algo (prefs->value)
                         ? num
                         : gcry_md_algo_name (prefs->value));
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for digest"
				 " algorithm %s\n"), user, algo);
		      problem=1;
		    }
		}
	      else if(prefs->type==PREFTYPE_ZIP)
		{
		  if(check_compress_algo (prefs->value))
		    {
		      const char *algo=compress_algo_to_string(prefs->value);
		      if(!problem)
			check_prefs_warning(pk);
		      log_info(_("         \"%s\": preference for compression"
				 " algorithm %s\n"),user,algo?algo:num);
		      problem=1;
		    }
		}
	    }

	  xfree(user);
	}
    }

  if(problem)
    {
      log_info(_("it is strongly suggested that you update"
		 " your preferences and\n"));
      log_info(_("re-distribute this key to avoid potential algorithm"
		 " mismatch problems\n"));

      if(!opt.batch)
	{
	  strlist_t sl = NULL;
          strlist_t locusr = NULL;
	  size_t fprlen=0;
	  byte fpr[MAX_FINGERPRINT_LEN], *p;
	  char username[(MAX_FINGERPRINT_LEN*2)+1];
	  unsigned int i;

	  p = fingerprint_from_pk (pk,fpr,&fprlen);
	  for(i=0;i<fprlen;i++,p++)
	    sprintf(username+2*i,"%02X",*p);
	  add_to_strlist(&locusr,username);

	  append_to_strlist(&sl,"updpref");
	  append_to_strlist(&sl,"save");

	  keyedit_menu (ctrl, username, locusr, sl, 1, 1 );
	  free_strlist(sl);
	  free_strlist(locusr);
	}
      else if(!opt.quiet)
	log_info(_("you can update your preferences with:"
		   " gpg --edit-key %s updpref save\n"),keystr_from_pk(pk));
    }
}


/*
 * Try to import one keyblock. Return an error only in serious cases,
 * but never for an invalid keyblock.  It uses log_error to increase
 * the internal errorcount, so that invalid input can be detected by
 * programs which called gpg.  If SILENT is no messages are printed -
 * even most error messages are suppressed.
 */
static int
import_one (ctrl_t ctrl,
            const char *fname, kbnode_t keyblock, struct stats_s *stats,
	    unsigned char **fpr, size_t *fpr_len, unsigned int options,
	    int from_sk, int silent,
            import_screener_t screener, void *screener_arg)
{
  PKT_public_key *pk;
  PKT_public_key *pk_orig;
  kbnode_t node, uidnode;
  kbnode_t keyblock_orig = NULL;
  byte fpr2[MAX_FINGERPRINT_LEN];
  size_t fpr2len;
  u32 keyid[2];
  int rc = 0;
  int new_key = 0;
  int mod_key = 0;
  int same_key = 0;
  int non_self = 0;
  size_t an;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  /* Get the key and print some info about it. */
  node = find_kbnode( keyblock, PKT_PUBLIC_KEY );
  if (!node )
    BUG();

  pk = node->pkt->pkt.public_key;

  fingerprint_from_pk (pk, fpr2, &fpr2len);
  for (an = fpr2len; an < MAX_FINGERPRINT_LEN; an++)
    fpr2[an] = 0;
  keyid_from_pk( pk, keyid );
  uidnode = find_next_kbnode( keyblock, PKT_USER_ID );

  if (opt.verbose && !opt.interactive && !silent)
    {
      log_info( "pub  %s/%s %s  ",
                pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                keystr_from_pk(pk), datestr_from_pk(pk) );
      if (uidnode)
        print_utf8_buffer (log_get_stream (),
                           uidnode->pkt->pkt.user_id->name,
                           uidnode->pkt->pkt.user_id->len );
      log_printf ("\n");
    }


  if (!uidnode )
    {
      if (!silent)
        log_error( _("key %s: no user ID\n"), keystr_from_pk(pk));
      return 0;
    }

  if (screener && screener (keyblock, screener_arg))
    {
      log_error (_("key %s: %s\n"), keystr_from_pk (pk),
                 _("rejected by import screener"));
      return 0;
    }

  if (opt.interactive && !silent)
    {
      if (is_status_enabled())
        print_import_check (pk, uidnode->pkt->pkt.user_id);
      merge_keys_and_selfsig (keyblock);
      tty_printf ("\n");
      show_basic_key_info (keyblock);
      tty_printf ("\n");
      if (!cpr_get_answer_is_yes ("import.okay",
                                  "Do you want to import this key? (y/N) "))
        return 0;
    }

  collapse_uids(&keyblock);

  /* Clean the key that we're about to import, to cut down on things
     that we have to clean later.  This has no practical impact on the
     end result, but does result in less logging which might confuse
     the user. */
  if (options&IMPORT_CLEAN)
    clean_key (keyblock,opt.verbose,options&IMPORT_MINIMAL,NULL,NULL);

  clear_kbnode_flags( keyblock );

  if ((options&IMPORT_REPAIR_PKS_SUBKEY_BUG) && fix_pks_corruption(keyblock)
      && opt.verbose)
    log_info (_("key %s: PKS subkey corruption repaired\n"),
              keystr_from_pk(pk));

  rc = chk_self_sigs( fname, keyblock , pk, keyid, &non_self );
  if (rc )
    return rc== -1? 0:rc;

  /* If we allow such a thing, mark unsigned uids as valid */
  if (opt.allow_non_selfsigned_uid)
    {
      for (node=keyblock; node; node = node->next )
        if (node->pkt->pkttype == PKT_USER_ID && !(node->flag & 1) )
          {
            char *user=utf8_to_native(node->pkt->pkt.user_id->name,
                                      node->pkt->pkt.user_id->len,0);
            node->flag |= 1;
            log_info( _("key %s: accepted non self-signed user ID \"%s\"\n"),
                      keystr_from_pk(pk),user);
            xfree(user);
	  }
    }

  if (!delete_inv_parts( fname, keyblock, keyid, options ) )
    {
      if (!silent)
        {
          log_error( _("key %s: no valid user IDs\n"), keystr_from_pk(pk));
          if (!opt.quiet )
            log_info(_("this may be caused by a missing self-signature\n"));
        }
      stats->no_user_id++;
      return 0;
    }

  /* Do we have this key already in one of our pubrings ? */
  pk_orig = xmalloc_clear( sizeof *pk_orig );
  rc = get_pubkey_byfprint_fast (pk_orig, fpr2, fpr2len);
  if (rc && gpg_err_code (rc) != GPG_ERR_NO_PUBKEY
      && gpg_err_code (rc) != GPG_ERR_UNUSABLE_PUBKEY )
    {
      if (!silent)
        log_error (_("key %s: public key not found: %s\n"),
                   keystr(keyid), gpg_strerror (rc));
    }
  else if ( rc && (opt.import_options&IMPORT_MERGE_ONLY) )
    {
      if (opt.verbose && !silent )
        log_info( _("key %s: new key - skipped\n"), keystr(keyid));
      rc = 0;
      stats->skipped_new_keys++;
    }
  else if (rc )  /* Insert this key. */
    {
      KEYDB_HANDLE hd = keydb_new ();

      rc = keydb_locate_writable (hd, NULL);
      if (rc)
        {
          log_error (_("no writable keyring found: %s\n"), gpg_strerror (rc));
          keydb_release (hd);
          return GPG_ERR_GENERAL;
	}
      if (opt.verbose > 1 )
        log_info (_("writing to '%s'\n"), keydb_get_resource_name (hd) );

      rc = keydb_insert_keyblock (hd, keyblock );
      if (rc)
        log_error (_("error writing keyring '%s': %s\n"),
                   keydb_get_resource_name (hd), gpg_strerror (rc));
      else if (!(opt.import_options & IMPORT_KEEP_OWNERTTRUST))
        {
          /* This should not be possible since we delete the
             ownertrust when a key is deleted, but it can happen if
             the keyring and trustdb are out of sync.  It can also
             be made to happen with the trusted-key command and by
             importing and locally exported key. */

          clear_ownertrusts (pk);
          if (non_self)
            revalidation_mark ();
        }
      keydb_release (hd);

      /* We are ready.  */
      if (!opt.quiet && !silent)
        {
          char *p = get_user_id_byfpr_native (fpr2);
          log_info (_("key %s: public key \"%s\" imported\n"),
                    keystr(keyid), p);
          xfree(p);
        }
      if (is_status_enabled())
        {
          char *us = get_long_user_id_string( keyid );
          write_status_text( STATUS_IMPORTED, us );
          xfree(us);
          print_import_ok (pk, 1);
        }
      stats->imported++;
      new_key = 1;
    }
  else /* merge */
    {
      KEYDB_HANDLE hd;
      int n_uids, n_sigs, n_subk, n_sigs_cleaned, n_uids_cleaned;

      /* Compare the original against the new key; just to be sure nothing
       * weird is going on */
      if (cmp_public_keys( pk_orig, pk ) )
        {
          if (!silent)
            log_error( _("key %s: doesn't match our copy\n"),keystr(keyid));
          goto leave;
        }

      /* Now read the original keyblock again so that we can use
         that handle for updating the keyblock.  */
      hd = keydb_new ();
      keydb_disable_caching (hd);
      rc = keydb_search_fpr (hd, fpr2);
      if (rc )
        {
          log_error (_("key %s: can't locate original keyblock: %s\n"),
                     keystr(keyid), gpg_strerror (rc));
          keydb_release (hd);
          goto leave;
        }
      rc = keydb_get_keyblock (hd, &keyblock_orig);
      if (rc)
        {
          log_error (_("key %s: can't read original keyblock: %s\n"),
                     keystr(keyid), gpg_strerror (rc));
          keydb_release (hd);
          goto leave;
        }

      /* Make sure the original direct key sigs are all sane.  */
      n_sigs_cleaned = fix_bad_direct_key_sigs (keyblock_orig, keyid);
      if (n_sigs_cleaned)
        commit_kbnode (&keyblock_orig);

      /* and try to merge the block */
      clear_kbnode_flags( keyblock_orig );
      clear_kbnode_flags( keyblock );
      n_uids = n_sigs = n_subk = n_uids_cleaned = 0;
      rc = merge_blocks( fname, keyblock_orig, keyblock,
                         keyid, &n_uids, &n_sigs, &n_subk );
      if (rc )
        {
          keydb_release (hd);
          goto leave;
        }

      if ((options & IMPORT_CLEAN))
        clean_key (keyblock_orig,opt.verbose,options&IMPORT_MINIMAL,
                   &n_uids_cleaned,&n_sigs_cleaned);

      if (n_uids || n_sigs || n_subk || n_sigs_cleaned || n_uids_cleaned)
        {
          mod_key = 1;
          /* KEYBLOCK_ORIG has been updated; write */
          rc = keydb_update_keyblock (hd, keyblock_orig);
          if (rc)
            log_error (_("error writing keyring '%s': %s\n"),
                       keydb_get_resource_name (hd), gpg_strerror (rc) );
          else if (non_self)
            revalidation_mark ();

          /* We are ready.  */
          if (!opt.quiet && !silent)
            {
              char *p = get_user_id_byfpr_native (fpr2);
              if (n_uids == 1 )
                log_info( _("key %s: \"%s\" 1 new user ID\n"),
                          keystr(keyid),p);
              else if (n_uids )
                log_info( _("key %s: \"%s\" %d new user IDs\n"),
                          keystr(keyid),p,n_uids);
              if (n_sigs == 1 )
                log_info( _("key %s: \"%s\" 1 new signature\n"),
                          keystr(keyid), p);
              else if (n_sigs )
                log_info( _("key %s: \"%s\" %d new signatures\n"),
                          keystr(keyid), p, n_sigs );
              if (n_subk == 1 )
                log_info( _("key %s: \"%s\" 1 new subkey\n"),
                          keystr(keyid), p);
              else if (n_subk )
                log_info( _("key %s: \"%s\" %d new subkeys\n"),
                          keystr(keyid), p, n_subk );
              if (n_sigs_cleaned==1)
                log_info(_("key %s: \"%s\" %d signature cleaned\n"),
                         keystr(keyid),p,n_sigs_cleaned);
              else if (n_sigs_cleaned)
                log_info(_("key %s: \"%s\" %d signatures cleaned\n"),
                         keystr(keyid),p,n_sigs_cleaned);
              if (n_uids_cleaned==1)
                log_info(_("key %s: \"%s\" %d user ID cleaned\n"),
                         keystr(keyid),p,n_uids_cleaned);
              else if (n_uids_cleaned)
                log_info(_("key %s: \"%s\" %d user IDs cleaned\n"),
                         keystr(keyid),p,n_uids_cleaned);
              xfree(p);
            }

          stats->n_uids +=n_uids;
          stats->n_sigs +=n_sigs;
          stats->n_subk +=n_subk;
          stats->n_sigs_cleaned +=n_sigs_cleaned;
          stats->n_uids_cleaned +=n_uids_cleaned;

          if (is_status_enabled () && !silent)
            print_import_ok (pk, ((n_uids?2:0)|(n_sigs?4:0)|(n_subk?8:0)));
	}
      else
        {
          same_key = 1;
          if (is_status_enabled ())
            print_import_ok (pk, 0);

          if (!opt.quiet && !silent)
            {
              char *p = get_user_id_byfpr_native (fpr2);
              log_info( _("key %s: \"%s\" not changed\n"),keystr(keyid),p);
              xfree(p);
            }

          stats->unchanged++;
        }

      keydb_release (hd); hd = NULL;
    }

  leave:
  if (mod_key || new_key || same_key)
    {
      /* A little explanation for this: we fill in the fingerprint
         when importing keys as it can be useful to know the
         fingerprint in certain keyserver-related cases (a keyserver
         asked for a particular name, but the key doesn't have that
         name).  However, in cases where we're importing more than
         one key at a time, we cannot know which key to fingerprint.
         In these cases, rather than guessing, we do not
         fingerprinting at all, and we must hope the user ID on the
         keys are useful.  Note that we need to do this for new
         keys, merged keys and even for unchanged keys.  This is
         required because for example the --auto-key-locate feature
         may import an already imported key and needs to know the
         fingerprint of the key in all cases.  */
      if (fpr)
        {
          xfree (*fpr);
          /* Note that we need to compare against 0 here because
             COUNT gets only incremented after returning form this
             function.  */
          if (!stats->count)
            *fpr = fingerprint_from_pk (pk, NULL, fpr_len);
          else
            *fpr = NULL;
        }
    }

  /* Now that the key is definitely incorporated into the keydb, we
     need to check if a designated revocation is present or if the
     prefs are not rational so we can warn the user. */

  if (mod_key)
    {
      revocation_present (ctrl, keyblock_orig);
      if (!from_sk && have_secret_key_with_kid (keyid))
        check_prefs (ctrl, keyblock_orig);
    }
  else if (new_key)
    {
      revocation_present (ctrl, keyblock);
      if (!from_sk && have_secret_key_with_kid (keyid))
        check_prefs (ctrl, keyblock);
    }

  release_kbnode( keyblock_orig );
  free_public_key( pk_orig );

  return rc;
}


/* Transfer all the secret keys in SEC_KEYBLOCK to the gpg-agent.  The
   function prints diagnostics and returns an error code.  If BATCH is
   true the secret keys are stored by gpg-agent in the transfer format
   (i.e. no re-protection and aksing for passphrases). */
static gpg_error_t
transfer_secret_keys (ctrl_t ctrl, struct stats_s *stats, kbnode_t sec_keyblock,
                      int batch)
{
  gpg_error_t err = 0;
  void *kek = NULL;
  size_t keklen;
  kbnode_t ctx = NULL;
  kbnode_t node;
  PKT_public_key *main_pk, *pk;
  struct seckey_info *ski;
  int nskey;
  membuf_t mbuf;
  int i, j;
  void *format_args[2*PUBKEY_MAX_NSKEY];
  gcry_sexp_t skey, prot, tmpsexp;
  gcry_sexp_t curve = NULL;
  unsigned char *transferkey = NULL;
  size_t transferkeylen;
  gcry_cipher_hd_t cipherhd = NULL;
  unsigned char *wrappedkey = NULL;
  size_t wrappedkeylen;
  char *cache_nonce = NULL;

  /* Get the current KEK.  */
  err = agent_keywrap_key (ctrl, 0, &kek, &keklen);
  if (err)
    {
      log_error ("error getting the KEK: %s\n", gpg_strerror (err));
      goto leave;
    }

  /* Prepare a cipher context.  */
  err = gcry_cipher_open (&cipherhd, GCRY_CIPHER_AES128,
                          GCRY_CIPHER_MODE_AESWRAP, 0);
  if (!err)
    err = gcry_cipher_setkey (cipherhd, kek, keklen);
  if (err)
    goto leave;
  xfree (kek);
  kek = NULL;

  main_pk = NULL;
  while ((node = walk_kbnode (sec_keyblock, &ctx, 0)))
    {
      if (node->pkt->pkttype != PKT_SECRET_KEY
          && node->pkt->pkttype != PKT_SECRET_SUBKEY)
        continue;
      pk = node->pkt->pkt.public_key;
      if (!main_pk)
        main_pk = pk;

      /* Make sure the keyids are available.  */
      keyid_from_pk (pk, NULL);
      if (node->pkt->pkttype == PKT_SECRET_KEY)
        {
          pk->main_keyid[0] = pk->keyid[0];
          pk->main_keyid[1] = pk->keyid[1];
        }
      else
        {
          pk->main_keyid[0] = main_pk->keyid[0];
          pk->main_keyid[1] = main_pk->keyid[1];
        }


      ski = pk->seckey_info;
      if (!ski)
        BUG ();

      stats->count++;
      stats->secret_read++;

      /* We ignore stub keys.  The way we handle them in other parts
         of the code is by asking the agent whether any secret key is
         available for a given keyblock and then concluding that we
         have a secret key; all secret (sub)keys of the keyblock the
         agent does not know of are then stub keys.  This works also
         for card stub keys.  The learn command or the card-status
         command may be used to check with the agent whether a card
         has been inserted and a stub key is in turn generated by the
         agent.  */
      if (ski->s2k.mode == 1001 || ski->s2k.mode == 1002)
        continue;

      /* Convert our internal secret key object into an S-expression.  */
      nskey = pubkey_get_nskey (pk->pubkey_algo);
      if (!nskey || nskey > PUBKEY_MAX_NSKEY)
        {
          err = gpg_error (GPG_ERR_BAD_SECKEY);
          log_error ("internal error: %s\n", gpg_strerror (err));
          goto leave;
        }

      init_membuf (&mbuf, 50);
      put_membuf_str (&mbuf, "(skey");
      if (pk->pubkey_algo == PUBKEY_ALGO_ECDSA
          || pk->pubkey_algo == PUBKEY_ALGO_EDDSA
          || pk->pubkey_algo == PUBKEY_ALGO_ECDH)
        {
          /* The ECC case.  */
          char *curvestr = openpgp_oid_to_str (pk->pkey[0]);
          if (!curvestr)
            err = gpg_error_from_syserror ();
          else
            {
              err = gcry_sexp_build (&curve, NULL, "(curve %s)", curvestr);
              xfree (curvestr);
              if (!err)
                {
                  j = 0;
                  /* Append the public key element Q.  */
                  put_membuf_str (&mbuf, " _ %m");
                  format_args[j++] = pk->pkey + 1;

                  /* Append the secret key element D.  For ECDH we
                     skip PKEY[2] because this holds the KEK which is
                     not needed by gpg-agent.  */
                  i = pk->pubkey_algo == PUBKEY_ALGO_ECDH? 3 : 2;
                  if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_USER1))
                    put_membuf_str (&mbuf, " e %m");
                  else
                    put_membuf_str (&mbuf, " _ %m");
                  format_args[j++] = pk->pkey + i;
                }
            }
        }
      else
        {
          /* Standard case for the old (non-ECC) algorithms.  */
          for (i=j=0; i < nskey; i++)
            {
              if (!pk->pkey[i])
                continue; /* Protected keys only have NPKEY+1 elements.  */

              if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_USER1))
                put_membuf_str (&mbuf, " e %m");
              else
                put_membuf_str (&mbuf, " _ %m");
              format_args[j++] = pk->pkey + i;
            }
        }
      put_membuf_str (&mbuf, ")");
      put_membuf (&mbuf, "", 1);
      if (err)
        xfree (get_membuf (&mbuf, NULL));
      else
        {
          char *format = get_membuf (&mbuf, NULL);
          if (!format)
            err = gpg_error_from_syserror ();
          else
            err = gcry_sexp_build_array (&skey, NULL, format, format_args);
          xfree (format);
        }
      if (err)
        {
          log_error ("error building skey array: %s\n", gpg_strerror (err));
          goto leave;
        }

      if (ski->is_protected)
        {
          char countbuf[35];

          /* Note that the IVLEN may be zero if we are working on a
             dummy key.  We can't express that in an S-expression and
             thus we send dummy data for the IV.  */
          snprintf (countbuf, sizeof countbuf, "%lu",
                    (unsigned long)ski->s2k.count);
          err = gcry_sexp_build
            (&prot, NULL,
             " (protection %s %s %b %d %s %b %s)\n",
             ski->sha1chk? "sha1":"sum",
             openpgp_cipher_algo_name (ski->algo),
             ski->ivlen? (int)ski->ivlen:1,
             ski->ivlen? ski->iv: (const unsigned char*)"X",
             ski->s2k.mode,
             openpgp_md_algo_name (ski->s2k.hash_algo),
             (int)sizeof (ski->s2k.salt), ski->s2k.salt,
             countbuf);
        }
      else
        err = gcry_sexp_build (&prot, NULL, " (protection none)\n");

      tmpsexp = NULL;
      xfree (transferkey);
      transferkey = NULL;
      if (!err)
        err = gcry_sexp_build (&tmpsexp, NULL,
                               "(openpgp-private-key\n"
                               " (version %d)\n"
                               " (algo %s)\n"
                               " %S%S\n"
                               " (csum %d)\n"
                               " %S)\n",
                               pk->version,
                               openpgp_pk_algo_name (pk->pubkey_algo),
                               curve, skey,
                               (int)(unsigned long)ski->csum, prot);
      gcry_sexp_release (skey);
      gcry_sexp_release (prot);
      if (!err)
        err = make_canon_sexp_pad (tmpsexp, 1, &transferkey, &transferkeylen);
      gcry_sexp_release (tmpsexp);
      if (err)
        {
          log_error ("error building transfer key: %s\n", gpg_strerror (err));
          goto leave;
        }

      /* Wrap the key.  */
      wrappedkeylen = transferkeylen + 8;
      xfree (wrappedkey);
      wrappedkey = xtrymalloc (wrappedkeylen);
      if (!wrappedkey)
        err = gpg_error_from_syserror ();
      else
        err = gcry_cipher_encrypt (cipherhd, wrappedkey, wrappedkeylen,
                                   transferkey, transferkeylen);
      if (err)
        goto leave;
      xfree (transferkey);
      transferkey = NULL;

      /* Send the wrapped key to the agent.  */
      {
        char *desc = gpg_format_keydesc (pk, FORMAT_KEYDESC_IMPORT, 1);
        err = agent_import_key (ctrl, desc, &cache_nonce,
                                wrappedkey, wrappedkeylen, batch);
        xfree (desc);
      }
      if (!err)
        {
          if (opt.verbose)
            log_info (_("key %s: secret key imported\n"),
                      keystr_from_pk_with_sub (main_pk, pk));
          stats->secret_imported++;
        }
      else if ( gpg_err_code (err) == GPG_ERR_EEXIST )
        {
          if (opt.verbose)
            log_info (_("key %s: secret key already exists\n"),
                      keystr_from_pk_with_sub (main_pk, pk));
          err = 0;
          stats->secret_dups++;
        }
      else
        {
          log_error (_("key %s: error sending to agent: %s\n"),
                     keystr_from_pk_with_sub (main_pk, pk),
                     gpg_strerror (err));
          if (gpg_err_code (err) == GPG_ERR_CANCELED
              || gpg_err_code (err) == GPG_ERR_FULLY_CANCELED)
            break; /* Don't try the other subkeys.  */
        }
    }

 leave:
  gcry_sexp_release (curve);
  xfree (cache_nonce);
  xfree (wrappedkey);
  xfree (transferkey);
  gcry_cipher_close (cipherhd);
  xfree (kek);
  return err;
}


/* Walk a secret keyblock and produce a public keyblock out of it.
   Returns a new node or NULL on error. */
static kbnode_t
sec_to_pub_keyblock (kbnode_t sec_keyblock)
{
  kbnode_t pub_keyblock = NULL;
  kbnode_t ctx = NULL;
  kbnode_t secnode, pubnode;

  while ((secnode = walk_kbnode (sec_keyblock, &ctx, 0)))
    {
      if (secnode->pkt->pkttype == PKT_SECRET_KEY
          || secnode->pkt->pkttype == PKT_SECRET_SUBKEY)
	{
	  /* Make a public key.  */
	  PACKET *pkt;
          PKT_public_key *pk;

	  pkt = xtrycalloc (1, sizeof *pkt);
          pk = pkt? copy_public_key (NULL, secnode->pkt->pkt.public_key): NULL;
          if (!pk)
            {
              xfree (pkt);
	      release_kbnode (pub_keyblock);
              return NULL;
            }
	  if (secnode->pkt->pkttype == PKT_SECRET_KEY)
	    pkt->pkttype = PKT_PUBLIC_KEY;
	  else
	    pkt->pkttype = PKT_PUBLIC_SUBKEY;
	  pkt->pkt.public_key = pk;

	  pubnode = new_kbnode (pkt);
	}
      else
	{
	  pubnode = clone_kbnode (secnode);
	}

      if (!pub_keyblock)
	pub_keyblock = pubnode;
      else
	add_kbnode (pub_keyblock, pubnode);
    }

  return pub_keyblock;
}

/****************
 * Ditto for secret keys.  Handling is simpler than for public keys.
 * We allow secret key importing only when allow is true, this is so
 * that a secret key can not be imported accidently and thereby tampering
 * with the trust calculation.
 */
static int
import_secret_one (ctrl_t ctrl, const char *fname, kbnode_t keyblock,
                   struct stats_s *stats, int batch, unsigned int options,
                   int for_migration,
                   import_screener_t screener, void *screener_arg)
{
  PKT_public_key *pk;
  struct seckey_info *ski;
  kbnode_t node, uidnode;
  u32 keyid[2];
  int rc = 0;
  int nr_prev;
  kbnode_t pub_keyblock;
  char pkstrbuf[PUBKEY_STRING_SIZE];

  /* Get the key and print some info about it */
  node = find_kbnode (keyblock, PKT_SECRET_KEY);
  if (!node)
    BUG ();

  pk = node->pkt->pkt.public_key;

  keyid_from_pk (pk, keyid);
  uidnode = find_next_kbnode (keyblock, PKT_USER_ID);

  if (screener && screener (keyblock, screener_arg))
    {
      log_error (_("secret key %s: %s\n"), keystr_from_pk (pk),
                 _("rejected by import screener"));
      return 0;
  }

  if (opt.verbose && !for_migration)
    {
      log_info ("sec  %s/%s %s   ",
                pubkey_string (pk, pkstrbuf, sizeof pkstrbuf),
                keystr_from_pk (pk), datestr_from_pk (pk));
      if (uidnode)
        print_utf8_buffer (log_get_stream (), uidnode->pkt->pkt.user_id->name,
                           uidnode->pkt->pkt.user_id->len);
      log_printf ("\n");
    }
  stats->secret_read++;

  if ((options & IMPORT_NO_SECKEY))
    {
      if (!for_migration)
        log_error (_("importing secret keys not allowed\n"));
      return 0;
    }

  if (!uidnode)
    {
      if (!for_migration)
        log_error( _("key %s: no user ID\n"), keystr_from_pk (pk));
      return 0;
    }

  ski = pk->seckey_info;
  if (!ski)
    {
      /* Actually an internal error.  */
      log_error ("key %s: secret key info missing\n", keystr_from_pk (pk));
      return 0;
    }

  /* A quick check to not import keys with an invalid protection
     cipher algorithm (only checks the primary key, though).  */
  if (ski->algo > 110)
    {
      if (!for_migration)
        log_error (_("key %s: secret key with invalid cipher %d"
                     " - skipped\n"), keystr_from_pk (pk), ski->algo);
      return 0;
    }

#ifdef ENABLE_SELINUX_HACKS
  if (1)
    {
      /* We don't allow to import secret keys because that may be used
         to put a secret key into the keyring and the user might later
         be tricked into signing stuff with that key.  */
      log_error (_("importing secret keys not allowed\n"));
      return 0;
    }
#endif

  clear_kbnode_flags (keyblock);

  nr_prev = stats->skipped_new_keys;

  /* Make a public key out of the key. */
  pub_keyblock = sec_to_pub_keyblock (keyblock);
  if (!pub_keyblock)
    log_error ("key %s: failed to create public key from secret key\n",
                   keystr_from_pk (pk));
  else
    {
      /* Note that this outputs an IMPORT_OK status message for the
	 public key block, and below we will output another one for
	 the secret keys.  FIXME?  */
      import_one (ctrl, fname, pub_keyblock, stats,
		  NULL, NULL, options, 1, for_migration,
                  screener, screener_arg);

      /* Fixme: We should check for an invalid keyblock and
	 cancel the secret key import in this case.  */
      release_kbnode (pub_keyblock);

      /* At least we cancel the secret key import when the public key
	 import was skipped due to MERGE_ONLY option and a new
	 key.  */
      if (stats->skipped_new_keys <= nr_prev)
	{
          /* Read the keyblock again to get the effects of a merge.  */
          /* Fixme: we should do this based on the fingerprint or
             even better let import_one return the merged
             keyblock.  */
          node = get_pubkeyblock (keyid);
          if (!node)
            log_error ("key %s: failed to re-lookup public key\n",
                       keystr_from_pk (pk));
          else
            {
	      nr_prev = stats->secret_imported;
              if (!transfer_secret_keys (ctrl, stats, keyblock, batch))
                {
		  int status = 16;
                  if (!opt.quiet)
                    log_info (_("key %s: secret key imported\n"),
                              keystr_from_pk (pk));
		  if (stats->secret_imported > nr_prev)
		    status |= 1;
                  if (is_status_enabled ())
                    print_import_ok (pk, status);
                  check_prefs (ctrl, node);
                }
              release_kbnode (node);
            }
        }
    }

  return rc;
}


/****************
 * Import a revocation certificate; this is a single signature packet.
 */
static int
import_revoke_cert( const char *fname, kbnode_t node, struct stats_s *stats )
{
  PKT_public_key *pk = NULL;
  kbnode_t onode;
  kbnode_t keyblock = NULL;
  KEYDB_HANDLE hd = NULL;
  u32 keyid[2];
  int rc = 0;

  (void)fname;

  assert( !node->next );
  assert( node->pkt->pkttype == PKT_SIGNATURE );
  assert( node->pkt->pkt.signature->sig_class == 0x20 );

  keyid[0] = node->pkt->pkt.signature->keyid[0];
  keyid[1] = node->pkt->pkt.signature->keyid[1];

  pk = xmalloc_clear( sizeof *pk );
  rc = get_pubkey( pk, keyid );
  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY )
    {
      log_error(_("key %s: no public key -"
                  " can't apply revocation certificate\n"), keystr(keyid));
      rc = 0;
      goto leave;
    }
  else if (rc )
    {
      log_error(_("key %s: public key not found: %s\n"),
                keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* Read the original keyblock. */
  hd = keydb_new ();
  {
    byte afp[MAX_FINGERPRINT_LEN];
    size_t an;

    fingerprint_from_pk (pk, afp, &an);
    while (an < MAX_FINGERPRINT_LEN)
      afp[an++] = 0;
    rc = keydb_search_fpr (hd, afp);
  }
  if (rc)
    {
      log_error (_("key %s: can't locate original keyblock: %s\n"),
                 keystr(keyid), gpg_strerror (rc));
      goto leave;
    }
  rc = keydb_get_keyblock (hd, &keyblock );
  if (rc)
    {
      log_error (_("key %s: can't read original keyblock: %s\n"),
                 keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* it is okay, that node is not in keyblock because
   * check_key_signature works fine for sig_class 0x20 in this
   * special case. */
  rc = check_key_signature( keyblock, node, NULL);
  if (rc )
    {
      log_error( _("key %s: invalid revocation certificate"
                   ": %s - rejected\n"), keystr(keyid), gpg_strerror (rc));
      goto leave;
    }

  /* check whether we already have this */
  for(onode=keyblock->next; onode; onode=onode->next ) {
    if (onode->pkt->pkttype == PKT_USER_ID )
      break;
    else if (onode->pkt->pkttype == PKT_SIGNATURE
             && !cmp_signatures(node->pkt->pkt.signature,
                                onode->pkt->pkt.signature))
      {
        rc = 0;
        goto leave; /* yes, we already know about it */
      }
  }

  /* insert it */
  insert_kbnode( keyblock, clone_kbnode(node), 0 );

  /* and write the keyblock back */
  rc = keydb_update_keyblock (hd, keyblock );
  if (rc)
    log_error (_("error writing keyring '%s': %s\n"),
               keydb_get_resource_name (hd), gpg_strerror (rc) );
  keydb_release (hd);
  hd = NULL;

  /* we are ready */
  if (!opt.quiet )
    {
      char *p=get_user_id_native (keyid);
      log_info( _("key %s: \"%s\" revocation certificate imported\n"),
                keystr(keyid),p);
      xfree(p);
    }
  stats->n_revoc++;

  /* If the key we just revoked was ultimately trusted, remove its
     ultimate trust.  This doesn't stop the user from putting the
     ultimate trust back, but is a reasonable solution for now. */
  if(get_ownertrust(pk)==TRUST_ULTIMATE)
    clear_ownertrusts(pk);

  revalidation_mark ();

 leave:
  keydb_release (hd);
  release_kbnode( keyblock );
  free_public_key( pk );
  return rc;
}


/*
 * Loop over the keyblock and check all self signatures.
 * Mark all user-ids with a self-signature by setting flag bit 0.
 * Mark all user-ids with an invalid self-signature by setting bit 1.
 * This works also for subkeys, here the subkey is marked.  Invalid or
 * extra subkey sigs (binding or revocation) are marked for deletion.
 * non_self is set to true if there are any sigs other than self-sigs
 * in this keyblock.
 */
static int
chk_self_sigs (const char *fname, kbnode_t keyblock,
	       PKT_public_key *pk, u32 *keyid, int *non_self )
{
  kbnode_t n, knode = NULL;
  PKT_signature *sig;
  int rc;
  u32 bsdate=0, rsdate=0;
  kbnode_t bsnode = NULL, rsnode = NULL;

  (void)fname;
  (void)pk;

  for (n=keyblock; (n = find_next_kbnode (n, 0)); )
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY)
	{
	  knode = n;
	  bsdate = 0;
	  rsdate = 0;
	  bsnode = NULL;
	  rsnode = NULL;
	  continue;
	}

      if ( n->pkt->pkttype != PKT_SIGNATURE )
        continue;

      sig = n->pkt->pkt.signature;
      if ( keyid[0] != sig->keyid[0] || keyid[1] != sig->keyid[1] )
        {
          *non_self = 1;
          continue;
        }

      /* This just caches the sigs for later use.  That way we
         import a fully-cached key which speeds things up. */
      if (!opt.no_sig_cache)
        check_key_signature (keyblock, n, NULL);

      if ( IS_UID_SIG(sig) || IS_UID_REV(sig) )
        {
          kbnode_t unode = find_prev_kbnode( keyblock, n, PKT_USER_ID );
          if ( !unode )
            {
              log_error( _("key %s: no user ID for signature\n"),
                         keystr(keyid));
              return -1;  /* The complete keyblock is invalid.  */
            }

          /* If it hasn't been marked valid yet, keep trying.  */
          if (!(unode->flag&1))
            {
              rc = check_key_signature (keyblock, n, NULL);
              if ( rc )
                {
                  if ( opt.verbose )
                    {
                      char *p = utf8_to_native
                        (unode->pkt->pkt.user_id->name,
                         strlen (unode->pkt->pkt.user_id->name),0);
                      log_info (gpg_err_code(rc) == GPG_ERR_PUBKEY_ALGO ?
                                _("key %s: unsupported public key "
                                  "algorithm on user ID \"%s\"\n"):
                                _("key %s: invalid self-signature "
                                  "on user ID \"%s\"\n"),
                                keystr (keyid),p);
                      xfree (p);
                    }
                }
              else
                unode->flag |= 1; /* Mark that signature checked. */
            }
        }
      else if (IS_KEY_SIG (sig))
        {
          rc = check_key_signature (keyblock, n, NULL);
          if ( rc )
            {
              if (opt.verbose)
                log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                          _("key %s: unsupported public key algorithm\n"):
                          _("key %s: invalid direct key signature\n"),
                          keystr (keyid));
              n->flag |= 4;
            }
        }
      else if ( IS_SUBKEY_SIG (sig) )
        {
          /* Note that this works based solely on the timestamps like
             the rest of gpg.  If the standard gets revocation
             targets, this may need to be revised.  */

          if ( !knode )
            {
              if (opt.verbose)
                log_info (_("key %s: no subkey for key binding\n"),
                          keystr (keyid));
              n->flag |= 4; /* delete this */
            }
          else
            {
              rc = check_key_signature (keyblock, n, NULL);
              if ( rc )
                {
                  if (opt.verbose)
                    log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                              _("key %s: unsupported public key"
                                " algorithm\n"):
                              _("key %s: invalid subkey binding\n"),
                              keystr (keyid));
                  n->flag |= 4;
                }
              else
                {
                  /* It's valid, so is it newer? */
                  if (sig->timestamp >= bsdate)
                    {
                      knode->flag |= 1;  /* The subkey is valid.  */
                      if (bsnode)
                        {
                          /* Delete the last binding sig since this
                             one is newer */
                          bsnode->flag |= 4;
                          if (opt.verbose)
                            log_info (_("key %s: removed multiple subkey"
                                        " binding\n"),keystr(keyid));
                        }

                      bsnode = n;
                      bsdate = sig->timestamp;
                    }
                  else
                    n->flag |= 4; /* older */
                }
            }
        }
      else if ( IS_SUBKEY_REV (sig) )
        {
          /* We don't actually mark the subkey as revoked right now,
             so just check that the revocation sig is the most recent
             valid one.  Note that we don't care if the binding sig is
             newer than the revocation sig.  See the comment in
             getkey.c:merge_selfsigs_subkey for more.  */
          if ( !knode )
            {
              if (opt.verbose)
                log_info (_("key %s: no subkey for key revocation\n"),
                          keystr(keyid));
              n->flag |= 4; /* delete this */
            }
          else
            {
              rc = check_key_signature (keyblock, n, NULL);
              if ( rc )
                {
                  if(opt.verbose)
                    log_info (gpg_err_code (rc) == GPG_ERR_PUBKEY_ALGO ?
                              _("key %s: unsupported public"
                                " key algorithm\n"):
                              _("key %s: invalid subkey revocation\n"),
                              keystr(keyid));
                  n->flag |= 4;
                }
              else
                {
                  /* It's valid, so is it newer? */
                  if (sig->timestamp >= rsdate)
                    {
                      if (rsnode)
                        {
                          /* Delete the last revocation sig since
                             this one is newer.  */
                          rsnode->flag |= 4;
                          if (opt.verbose)
                            log_info (_("key %s: removed multiple subkey"
                                        " revocation\n"),keystr(keyid));
                        }

                      rsnode = n;
                      rsdate = sig->timestamp;
                    }
                  else
                    n->flag |= 4; /* older */
                }
            }
        }
    }

  return 0;
}


/****************
 * delete all parts which are invalid and those signatures whose
 * public key algorithm is not available in this implemenation;
 * but consider RSA as valid, because parse/build_packets knows
 * about it.
 * returns: true if at least one valid user-id is left over.
 */
static int
delete_inv_parts( const char *fname, kbnode_t keyblock,
		  u32 *keyid, unsigned int options)
{
  kbnode_t node;
  int nvalid=0, uid_seen=0, subkey_seen=0;

  (void)fname;

  for (node=keyblock->next; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          uid_seen = 1;
          if ((node->flag & 2) || !(node->flag & 1) )
            {
              if (opt.verbose )
                {
                  char *p=utf8_to_native(node->pkt->pkt.user_id->name,
                                         node->pkt->pkt.user_id->len,0);
                  log_info( _("key %s: skipped user ID \"%s\"\n"),
                            keystr(keyid),p);
                  xfree(p);
                }
              delete_kbnode( node ); /* the user-id */
              /* and all following packets up to the next user-id */
              while (node->next
                     && node->next->pkt->pkttype != PKT_USER_ID
                     && node->next->pkt->pkttype != PKT_PUBLIC_SUBKEY
                     && node->next->pkt->pkttype != PKT_SECRET_SUBKEY ){
                delete_kbnode( node->next );
                node = node->next;
              }
	    }
          else
            nvalid++;
	}
      else if (   node->pkt->pkttype == PKT_PUBLIC_SUBKEY
               || node->pkt->pkttype == PKT_SECRET_SUBKEY )
        {
          if ((node->flag & 2) || !(node->flag & 1) )
            {
              if (opt.verbose )
                log_info( _("key %s: skipped subkey\n"),keystr(keyid));

              delete_kbnode( node ); /* the subkey */
              /* and all following signature packets */
              while (node->next
                     && node->next->pkt->pkttype == PKT_SIGNATURE ) {
                delete_kbnode( node->next );
                node = node->next;
              }
	    }
          else
            subkey_seen = 1;
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && openpgp_pk_test_algo (node->pkt->pkt.signature->pubkey_algo)
               && node->pkt->pkt.signature->pubkey_algo != PUBKEY_ALGO_RSA )
        {
          delete_kbnode( node ); /* build_packet() can't handle this */
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && !node->pkt->pkt.signature->flags.exportable
               && !(options&IMPORT_LOCAL_SIGS)
               && !have_secret_key_with_kid (node->pkt->pkt.signature->keyid))
        {
          /* here we violate the rfc a bit by still allowing
           * to import non-exportable signature when we have the
           * the secret key used to create this signature - it
           * seems that this makes sense */
          if(opt.verbose)
            log_info( _("key %s: non exportable signature"
                        " (class 0x%02X) - skipped\n"),
                      keystr(keyid), node->pkt->pkt.signature->sig_class );
          delete_kbnode( node );
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && node->pkt->pkt.signature->sig_class == 0x20)
        {
          if (uid_seen )
            {
              if(opt.verbose)
                log_info( _("key %s: revocation certificate"
                            " at wrong place - skipped\n"),keystr(keyid));
              delete_kbnode( node );
            }
          else
            {
	      /* If the revocation cert is from a different key than
                 the one we're working on don't check it - it's
                 probably from a revocation key and won't be
                 verifiable with this key anyway. */

	      if(node->pkt->pkt.signature->keyid[0]==keyid[0]
                 && node->pkt->pkt.signature->keyid[1]==keyid[1])
		{
		  int rc = check_key_signature( keyblock, node, NULL);
		  if (rc )
		    {
		      if(opt.verbose)
			log_info( _("key %s: invalid revocation"
				    " certificate: %s - skipped\n"),
				  keystr(keyid), gpg_strerror (rc));
		      delete_kbnode( node );
		    }
		}
	    }
	}
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && (node->pkt->pkt.signature->sig_class == 0x18
                   || node->pkt->pkt.signature->sig_class == 0x28)
               && !subkey_seen )
        {
          if(opt.verbose)
            log_info( _("key %s: subkey signature"
                        " in wrong place - skipped\n"), keystr(keyid));
          delete_kbnode( node );
        }
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && !IS_CERT(node->pkt->pkt.signature))
        {
          if(opt.verbose)
            log_info(_("key %s: unexpected signature class (0x%02X) -"
                       " skipped\n"),keystr(keyid),
                     node->pkt->pkt.signature->sig_class);
          delete_kbnode(node);
	  }
      else if ((node->flag & 4) ) /* marked for deletion */
        delete_kbnode( node );
    }

  /* note: because keyblock is the public key, it is never marked
   * for deletion and so keyblock cannot change */
  commit_kbnode( &keyblock );
  return nvalid;
}


/****************
 * It may happen that the imported keyblock has duplicated user IDs.
 * We check this here and collapse those user IDs together with their
 * sigs into one.
 * Returns: True if the keyblock has changed.
 */
int
collapse_uids( kbnode_t *keyblock )
{
  kbnode_t uid1;
  int any=0;

  for(uid1=*keyblock;uid1;uid1=uid1->next)
    {
      kbnode_t uid2;

      if(is_deleted_kbnode(uid1))
	continue;

      if(uid1->pkt->pkttype!=PKT_USER_ID)
	continue;

      for(uid2=uid1->next;uid2;uid2=uid2->next)
	{
	  if(is_deleted_kbnode(uid2))
	    continue;

	  if(uid2->pkt->pkttype!=PKT_USER_ID)
	    continue;

	  if(cmp_user_ids(uid1->pkt->pkt.user_id,
			  uid2->pkt->pkt.user_id)==0)
	    {
	      /* We have a duplicated uid */
	      kbnode_t sig1,last;

	      any=1;

	      /* Now take uid2's signatures, and attach them to
		 uid1 */
	      for(last=uid2;last->next;last=last->next)
		{
		  if(is_deleted_kbnode(last))
		    continue;

		  if(last->next->pkt->pkttype==PKT_USER_ID
		     || last->next->pkt->pkttype==PKT_PUBLIC_SUBKEY
		     || last->next->pkt->pkttype==PKT_SECRET_SUBKEY)
		    break;
		}

	      /* Snip out uid2 */
	      (find_prev_kbnode(*keyblock,uid2,0))->next=last->next;

	      /* Now put uid2 in place as part of uid1 */
	      last->next=uid1->next;
	      uid1->next=uid2;
	      delete_kbnode(uid2);

	      /* Now dedupe uid1 */
	      for(sig1=uid1->next;sig1;sig1=sig1->next)
		{
		  kbnode_t sig2;

		  if(is_deleted_kbnode(sig1))
		    continue;

		  if(sig1->pkt->pkttype==PKT_USER_ID
		     || sig1->pkt->pkttype==PKT_PUBLIC_SUBKEY
		     || sig1->pkt->pkttype==PKT_SECRET_SUBKEY)
		    break;

		  if(sig1->pkt->pkttype!=PKT_SIGNATURE)
		    continue;

		  for(sig2=sig1->next,last=sig1;sig2;last=sig2,sig2=sig2->next)
		    {
		      if(is_deleted_kbnode(sig2))
			continue;

		      if(sig2->pkt->pkttype==PKT_USER_ID
			 || sig2->pkt->pkttype==PKT_PUBLIC_SUBKEY
			 || sig2->pkt->pkttype==PKT_SECRET_SUBKEY)
			break;

		      if(sig2->pkt->pkttype!=PKT_SIGNATURE)
			continue;

		      if(cmp_signatures(sig1->pkt->pkt.signature,
					sig2->pkt->pkt.signature)==0)
			{
			  /* We have a match, so delete the second
			     signature */
			  delete_kbnode(sig2);
			  sig2=last;
			}
		    }
		}
	    }
	}
    }

  commit_kbnode(keyblock);

  if(any && !opt.quiet)
    {
      const char *key="???";

      if ((uid1 = find_kbnode (*keyblock, PKT_PUBLIC_KEY)) )
	key = keystr_from_pk (uid1->pkt->pkt.public_key);
      else if ((uid1 = find_kbnode( *keyblock, PKT_SECRET_KEY)) )
	key = keystr_from_pk (uid1->pkt->pkt.public_key);

      log_info (_("key %s: duplicated user ID detected - merged\n"), key);
    }

  return any;
}


/* Check for a 0x20 revocation from a revocation key that is not
   present.  This may be called without the benefit of merge_xxxx so
   you can't rely on pk->revkey and friends. */
static void
revocation_present (ctrl_t ctrl, kbnode_t keyblock)
{
  kbnode_t onode, inode;
  PKT_public_key *pk = keyblock->pkt->pkt.public_key;

  for(onode=keyblock->next;onode;onode=onode->next)
    {
      /* If we reach user IDs, we're done. */
      if(onode->pkt->pkttype==PKT_USER_ID)
	break;

      if(onode->pkt->pkttype==PKT_SIGNATURE &&
	 onode->pkt->pkt.signature->sig_class==0x1F &&
	 onode->pkt->pkt.signature->revkey)
	{
	  int idx;
	  PKT_signature *sig=onode->pkt->pkt.signature;

	  for(idx=0;idx<sig->numrevkeys;idx++)
	    {
	      u32 keyid[2];

	      keyid_from_fingerprint(sig->revkey[idx]->fpr,
				     MAX_FINGERPRINT_LEN,keyid);

	      for(inode=keyblock->next;inode;inode=inode->next)
		{
		  /* If we reach user IDs, we're done. */
		  if(inode->pkt->pkttype==PKT_USER_ID)
		    break;

		  if(inode->pkt->pkttype==PKT_SIGNATURE &&
		     inode->pkt->pkt.signature->sig_class==0x20 &&
		     inode->pkt->pkt.signature->keyid[0]==keyid[0] &&
		     inode->pkt->pkt.signature->keyid[1]==keyid[1])
		    {
		      /* Okay, we have a revocation key, and a
                         revocation issued by it.  Do we have the key
                         itself? */
		      int rc;

		      rc=get_pubkey_byfprint_fast (NULL,sig->revkey[idx]->fpr,
                                                   MAX_FINGERPRINT_LEN);
		      if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
                          || gpg_err_code (rc) == GPG_ERR_UNUSABLE_PUBKEY)
			{
			  char *tempkeystr=xstrdup(keystr_from_pk(pk));

			  /* No, so try and get it */
			  if(opt.keyserver
			     && (opt.keyserver_options.options
				 & KEYSERVER_AUTO_KEY_RETRIEVE))
			    {
			      log_info(_("WARNING: key %s may be revoked:"
					 " fetching revocation key %s\n"),
				       tempkeystr,keystr(keyid));
			      keyserver_import_fprint (ctrl,
                                                       sig->revkey[idx]->fpr,
                                                       MAX_FINGERPRINT_LEN,
                                                       opt.keyserver);

			      /* Do we have it now? */
			      rc=get_pubkey_byfprint_fast (NULL,
						     sig->revkey[idx]->fpr,
						     MAX_FINGERPRINT_LEN);
			    }

			  if (gpg_err_code (rc) == GPG_ERR_NO_PUBKEY
                              || gpg_err_code (rc) == GPG_ERR_UNUSABLE_PUBKEY)
			    log_info(_("WARNING: key %s may be revoked:"
				       " revocation key %s not present.\n"),
				     tempkeystr,keystr(keyid));

			  xfree(tempkeystr);
			}
		    }
		}
	    }
	}
    }
}


/*
 * compare and merge the blocks
 *
 * o compare the signatures: If we already have this signature, check
 *   that they compare okay; if not, issue a warning and ask the user.
 * o Simply add the signature.	Can't verify here because we may not have
 *   the signature's public key yet; verification is done when putting it
 *   into the trustdb, which is done automagically as soon as this pubkey
 *   is used.
 * Note: We indicate newly inserted packets with flag bit 0
 */
static int
merge_blocks (const char *fname, kbnode_t keyblock_orig, kbnode_t keyblock,
	      u32 *keyid, int *n_uids, int *n_sigs, int *n_subk )
{
  kbnode_t onode, node;
  int rc, found;

  /* 1st: handle revocation certificates */
  for (node=keyblock->next; node; node=node->next )
    {
      if (node->pkt->pkttype == PKT_USER_ID )
        break;
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && node->pkt->pkt.signature->sig_class == 0x20)
        {
          /* check whether we already have this */
          found = 0;
          for (onode=keyblock_orig->next; onode; onode=onode->next)
            {
              if (onode->pkt->pkttype == PKT_USER_ID )
                break;
              else if (onode->pkt->pkttype == PKT_SIGNATURE
                       && onode->pkt->pkt.signature->sig_class == 0x20
                       && !cmp_signatures(onode->pkt->pkt.signature,
                                          node->pkt->pkt.signature))
                {
                  found = 1;
                  break;
                }
	    }
          if (!found)
            {
              kbnode_t n2 = clone_kbnode(node);
              insert_kbnode( keyblock_orig, n2, 0 );
              n2->flag |= 1;
              ++*n_sigs;
              if(!opt.quiet)
                {
                  char *p=get_user_id_native (keyid);
                  log_info(_("key %s: \"%s\" revocation"
                             " certificate added\n"), keystr(keyid),p);
                  xfree(p);
                }
	    }
	}
    }

  /* 2nd: merge in any direct key (0x1F) sigs */
  for(node=keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID )
        break;
      else if (node->pkt->pkttype == PKT_SIGNATURE
               && node->pkt->pkt.signature->sig_class == 0x1F)
        {
          /* check whether we already have this */
          found = 0;
          for (onode=keyblock_orig->next; onode; onode=onode->next)
            {
              if (onode->pkt->pkttype == PKT_USER_ID)
                break;
              else if (onode->pkt->pkttype == PKT_SIGNATURE
                       && onode->pkt->pkt.signature->sig_class == 0x1F
                       && !cmp_signatures(onode->pkt->pkt.signature,
                                          node->pkt->pkt.signature))
                {
                  found = 1;
                  break;
		}
	    }
          if (!found )
            {
              kbnode_t n2 = clone_kbnode(node);
              insert_kbnode( keyblock_orig, n2, 0 );
              n2->flag |= 1;
              ++*n_sigs;
              if(!opt.quiet)
                log_info( _("key %s: direct key signature added\n"),
                          keystr(keyid));
            }
	}
    }

  /* 3rd: try to merge new certificates in */
  for (onode=keyblock_orig->next; onode; onode=onode->next)
    {
      if (!(onode->flag & 1) && onode->pkt->pkttype == PKT_USER_ID)
        {
          /* find the user id in the imported keyblock */
          for (node=keyblock->next; node; node=node->next)
            if (node->pkt->pkttype == PKT_USER_ID
                && !cmp_user_ids( onode->pkt->pkt.user_id,
                                  node->pkt->pkt.user_id ) )
              break;
          if (node ) /* found: merge */
            {
              rc = merge_sigs( onode, node, n_sigs, fname, keyid );
              if (rc )
                return rc;
	    }
	}
    }

  /* 4th: add new user-ids */
  for (node=keyblock->next; node; node=node->next)
    {
      if (node->pkt->pkttype == PKT_USER_ID)
        {
          /* do we have this in the original keyblock */
          for (onode=keyblock_orig->next; onode; onode=onode->next )
            if (onode->pkt->pkttype == PKT_USER_ID
                && !cmp_user_ids( onode->pkt->pkt.user_id,
                                  node->pkt->pkt.user_id ) )
              break;
          if (!onode ) /* this is a new user id: append */
            {
              rc = append_uid( keyblock_orig, node, n_sigs, fname, keyid);
              if (rc )
                return rc;
              ++*n_uids;
	    }
	}
    }

  /* 5th: add new subkeys */
  for (node=keyblock->next; node; node=node->next)
    {
      onode = NULL;
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        {
          /* do we have this in the original keyblock? */
          for(onode=keyblock_orig->next; onode; onode=onode->next)
            if (onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
                && !cmp_public_keys( onode->pkt->pkt.public_key,
                                     node->pkt->pkt.public_key))
              break;
          if (!onode ) /* This is a new subkey: append.  */
            {
              rc = append_key (keyblock_orig, node, n_sigs, fname, keyid);
              if (rc)
                return rc;
              ++*n_subk;
	    }
	}
      else if (node->pkt->pkttype == PKT_SECRET_SUBKEY)
        {
          /* do we have this in the original keyblock? */
          for (onode=keyblock_orig->next; onode; onode=onode->next )
            if (onode->pkt->pkttype == PKT_SECRET_SUBKEY
                && !cmp_public_keys (onode->pkt->pkt.public_key,
                                     node->pkt->pkt.public_key) )
              break;
          if (!onode ) /* This is a new subkey: append.  */
            {
              rc = append_key (keyblock_orig, node, n_sigs, fname, keyid);
              if (rc )
                return rc;
              ++*n_subk;
	    }
	}
    }

  /* 6th: merge subkey certificates */
  for (onode=keyblock_orig->next; onode; onode=onode->next)
    {
      if (!(onode->flag & 1)
          && (onode->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || onode->pkt->pkttype == PKT_SECRET_SUBKEY))
        {
          /* find the subkey in the imported keyblock */
          for(node=keyblock->next; node; node=node->next)
            {
              if ((node->pkt->pkttype == PKT_PUBLIC_SUBKEY
                   || node->pkt->pkttype == PKT_SECRET_SUBKEY)
                  && !cmp_public_keys( onode->pkt->pkt.public_key,
                                       node->pkt->pkt.public_key ) )
                break;
	    }
          if (node) /* Found: merge.  */
            {
              rc = merge_keysigs( onode, node, n_sigs, fname, keyid );
              if (rc )
                return rc;
	    }
	}
    }

  return 0;
}


/*
 * Append the userid starting with NODE and all signatures to KEYBLOCK.
 */
static int
append_uid (kbnode_t keyblock, kbnode_t node, int *n_sigs,
            const char *fname, u32 *keyid )
{
  kbnode_t n;
  kbnode_t n_where = NULL;

  (void)fname;
  (void)keyid;

  assert(node->pkt->pkttype == PKT_USER_ID );

  /* find the position */
  for (n = keyblock; n; n_where = n, n = n->next)
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || n->pkt->pkttype == PKT_SECRET_SUBKEY )
        break;
    }
  if (!n)
    n_where = NULL;

  /* and append/insert */
  while (node)
    {
      /* we add a clone to the original keyblock, because this
       * one is released first */
      n = clone_kbnode(node);
      if (n_where)
        {
          insert_kbnode( n_where, n, 0 );
          n_where = n;
	}
      else
        add_kbnode( keyblock, n );
      n->flag |= 1;
      node->flag |= 1;
      if (n->pkt->pkttype == PKT_SIGNATURE )
        ++*n_sigs;

      node = node->next;
      if (node && node->pkt->pkttype != PKT_SIGNATURE )
        break;
    }

  return 0;
}


/*
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_USER_ID.
 * (how should we handle comment packets here?)
 */
static int
merge_sigs (kbnode_t dst, kbnode_t src, int *n_sigs,
            const char *fname, u32 *keyid)
{
  kbnode_t n, n2;
  int found = 0;

  (void)fname;
  (void)keyid;

  assert(dst->pkt->pkttype == PKT_USER_ID );
  assert(src->pkt->pkttype == PKT_USER_ID );

  for (n=src->next; n && n->pkt->pkttype != PKT_USER_ID; n = n->next)
    {
      if (n->pkt->pkttype != PKT_SIGNATURE )
        continue;
      if (n->pkt->pkt.signature->sig_class == 0x18
          || n->pkt->pkt.signature->sig_class == 0x28 )
        continue; /* skip signatures which are only valid on subkeys */

      found = 0;
      for (n2=dst->next; n2 && n2->pkt->pkttype != PKT_USER_ID; n2 = n2->next)
        if (!cmp_signatures(n->pkt->pkt.signature,n2->pkt->pkt.signature))
          {
            found++;
            break;
          }
      if (!found )
        {
          /* This signature is new or newer, append N to DST.
           * We add a clone to the original keyblock, because this
           * one is released first */
          n2 = clone_kbnode(n);
          insert_kbnode( dst, n2, PKT_SIGNATURE );
          n2->flag |= 1;
          n->flag |= 1;
          ++*n_sigs;
	}
    }

  return 0;
}


/*
 * Merge the sigs from SRC onto DST. SRC and DST are both a PKT_xxx_SUBKEY.
 */
static int
merge_keysigs (kbnode_t dst, kbnode_t src, int *n_sigs,
               const char *fname, u32 *keyid)
{
  kbnode_t n, n2;
  int found = 0;

  (void)fname;
  (void)keyid;

  assert (dst->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || dst->pkt->pkttype == PKT_SECRET_SUBKEY);

  for (n=src->next; n ; n = n->next)
    {
      if (n->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || n->pkt->pkttype == PKT_PUBLIC_KEY )
        break;
      if (n->pkt->pkttype != PKT_SIGNATURE )
        continue;

      found = 0;
      for (n2=dst->next; n2; n2 = n2->next)
        {
          if (n2->pkt->pkttype == PKT_PUBLIC_SUBKEY
              || n2->pkt->pkttype == PKT_PUBLIC_KEY )
            break;
          if (n2->pkt->pkttype == PKT_SIGNATURE
              && (n->pkt->pkt.signature->keyid[0]
                  == n2->pkt->pkt.signature->keyid[0])
              && (n->pkt->pkt.signature->keyid[1]
                  == n2->pkt->pkt.signature->keyid[1])
              && (n->pkt->pkt.signature->timestamp
                  <= n2->pkt->pkt.signature->timestamp)
              && (n->pkt->pkt.signature->sig_class
                  == n2->pkt->pkt.signature->sig_class))
            {
              found++;
              break;
	    }
	}
      if (!found )
        {
          /* This signature is new or newer, append N to DST.
           * We add a clone to the original keyblock, because this
           * one is released first */
          n2 = clone_kbnode(n);
          insert_kbnode( dst, n2, PKT_SIGNATURE );
          n2->flag |= 1;
          n->flag |= 1;
          ++*n_sigs;
	}
    }

  return 0;
}


/*
 * Append the subkey starting with NODE and all signatures to KEYBLOCK.
 * Mark all new and copied packets by setting flag bit 0.
 */
static int
append_key (kbnode_t keyblock, kbnode_t node, int *n_sigs,
            const char *fname, u32 *keyid)
{
  kbnode_t n;

  (void)fname;
  (void)keyid;

  assert( node->pkt->pkttype == PKT_PUBLIC_SUBKEY
          || node->pkt->pkttype == PKT_SECRET_SUBKEY );

  while (node)
    {
      /* we add a clone to the original keyblock, because this
       * one is released first */
      n = clone_kbnode(node);
      add_kbnode( keyblock, n );
      n->flag |= 1;
      node->flag |= 1;
      if (n->pkt->pkttype == PKT_SIGNATURE )
        ++*n_sigs;

      node = node->next;
      if (node && node->pkt->pkttype != PKT_SIGNATURE )
        break;
    }

  return 0;
}
