/* keyid.c - key ID and fingerprint handling
 * Copyright (C) 1998, 1999, 2000, 2001, 2003,
 *               2004, 2006, 2010 Free Software Foundation, Inc.
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
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "main.h"
#include "packet.h"
#include "options.h"
#include "keydb.h"
#include "i18n.h"
#include "rmd160.h"
#include "host2net.h"


#define KEYID_STR_SIZE 19

#ifdef HAVE_UNSIGNED_TIME_T
# define IS_INVALID_TIME_T(a) ((a) == (time_t)(-1))
#else
  /* Error or 32 bit time_t and value after 2038-01-19.  */
# define IS_INVALID_TIME_T(a) ((a) < 0)
#endif


/* Return a letter describing the public key algorithms.  */
int
pubkey_letter( int algo )
{
  switch (algo)
    {
    case PUBKEY_ALGO_RSA:	return 'R' ;
    case PUBKEY_ALGO_RSA_E:	return 'r' ;
    case PUBKEY_ALGO_RSA_S:	return 's' ;
    case PUBKEY_ALGO_ELGAMAL_E: return 'g' ;
    case PUBKEY_ALGO_ELGAMAL:   return 'G' ;
    case PUBKEY_ALGO_DSA:	return 'D' ;
    case PUBKEY_ALGO_ECDH:	return 'e' ;	/* ECC DH (encrypt only) */
    case PUBKEY_ALGO_ECDSA:	return 'E' ;	/* ECC DSA (sign only)   */
    case PUBKEY_ALGO_EDDSA:	return 'E' ;	/* ECC EdDSA (sign only) */
    default: return '?';
    }
}

/* Return a string describing the public key algorithm and the
   keysize.  For elliptic curves the functions prints the name of the
   curve because the keysize is a property of the curve.  The string
   is copied to the supplied buffer up a length of BUFSIZE-1.
   Examples for the output are:

   "rsa2048"  - RSA with 2048 bit
   "elg1024"  - Elgamal with 1024 bit
   "ed25519"  - ECC using the curve Ed25519.
   "E_1.2.3.4"  - ECC using the unsupported curve with OID "1.2.3.4".
   "E_1.3.6.1.4.1.11591.2.12242973" ECC with a bogus OID.
   "unknown_N"  - Unknown OpenPGP algorithm N.

   If the option --legacy-list-mode is active, the output use the
   legacy format:

   "2048R" - RSA with 2048 bit
   "1024g" - Elgamal with 1024 bit
   "256E"  - ECDSA using a curve with 256 bit

   The macro PUBKEY_STRING_SIZE may be used to allocate a buffer with
   a suitable size.*/
char *
pubkey_string (PKT_public_key *pk, char *buffer, size_t bufsize)
{
  const char *prefix = NULL;

  if (opt.legacy_list_mode)
    {
      snprintf (buffer, bufsize, "%4u%c",
                nbits_from_pk (pk), pubkey_letter (pk->pubkey_algo));
      return buffer;
    }

  switch (pk->pubkey_algo)
    {
    case PUBKEY_ALGO_RSA:
    case PUBKEY_ALGO_RSA_E:
    case PUBKEY_ALGO_RSA_S:	prefix = "rsa"; break;
    case PUBKEY_ALGO_ELGAMAL_E: prefix = "elg"; break;
    case PUBKEY_ALGO_DSA:	prefix = "dsa"; break;
    case PUBKEY_ALGO_ELGAMAL:   prefix = "xxx"; break;
    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_EDDSA:     prefix = "";    break;
    }

  if (prefix && *prefix)
    snprintf (buffer, bufsize, "%s%u", prefix, nbits_from_pk (pk));
  else if (prefix)
    {
      char *curve = openpgp_oid_to_str (pk->pkey[0]);
      const char *name = openpgp_oid_to_curve (curve);

      if (*name && *name != '?')
        snprintf (buffer, bufsize, "%s", name);
      else if (curve)
        snprintf (buffer, bufsize, "E_%s", curve);
      else
        snprintf (buffer, bufsize, "E_error");
      xfree (curve);
    }
  else
    snprintf (buffer, bufsize, "unknown_%u", (unsigned int)pk->pubkey_algo);

  return buffer;
}


/* Hash a public key.  This function is useful for v4 fingerprints and
   for v3 or v4 key signing. */
void
hash_public_key (gcry_md_hd_t md, PKT_public_key *pk)
{
  unsigned int n = 6;
  unsigned int nn[PUBKEY_MAX_NPKEY];
  byte *pp[PUBKEY_MAX_NPKEY];
  int i;
  unsigned int nbits;
  size_t nbytes;
  int npkey = pubkey_get_npkey (pk->pubkey_algo);

  /* FIXME: We can avoid the extra malloc by calling only the first
     mpi_print here which computes the required length and calling the
     real mpi_print only at the end.  The speed advantage would only be
     for ECC (opaque MPIs) or if we could implement an mpi_print
     variant with a callback handler to do the hashing.  */
  if (npkey==0 && pk->pkey[0]
      && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      pp[0] = gcry_mpi_get_opaque (pk->pkey[0], &nbits);
      nn[0] = (nbits+7)/8;
      n+=nn[0];
    }
  else
    {
      for (i=0; i < npkey; i++ )
        {
          if (!pk->pkey[i])
            {
              /* This case may only happen if the parsing of the MPI
                 failed but the key was anyway created.  May happen
                 during "gpg KEYFILE".  */
              pp[i] = NULL;
              nn[i] = 0;
            }
          else if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_OPAQUE))
            {
              const void *p;

              p = gcry_mpi_get_opaque (pk->pkey[i], &nbits);
              pp[i] = xmalloc ((nbits+7)/8);
              if (p)
                memcpy (pp[i], p, (nbits+7)/8);
              else
                pp[i] = NULL;
              nn[i] = (nbits+7)/8;
              n += nn[i];
            }
          else
            {
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              pp[i] = xmalloc (nbytes);
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, pp[i], nbytes,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              nn[i] = nbytes;
              n += nn[i];
            }
        }
    }

  gcry_md_putc ( md, 0x99 );     /* ctb */
  /* What does it mean if n is greater than than 0xFFFF ? */
  gcry_md_putc ( md, n >> 8 );   /* 2 byte length header */
  gcry_md_putc ( md, n );
  gcry_md_putc ( md, pk->version );

  gcry_md_putc ( md, pk->timestamp >> 24 );
  gcry_md_putc ( md, pk->timestamp >> 16 );
  gcry_md_putc ( md, pk->timestamp >>  8 );
  gcry_md_putc ( md, pk->timestamp       );

  gcry_md_putc ( md, pk->pubkey_algo );

  if(npkey==0 && pk->pkey[0]
     && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      if (pp[0])
        gcry_md_write (md, pp[0], nn[0]);
    }
  else
    {
      for(i=0; i < npkey; i++ )
        {
          if (pp[i])
            gcry_md_write ( md, pp[i], nn[i] );
          xfree(pp[i]);
        }
    }
}


static gcry_md_hd_t
do_fingerprint_md( PKT_public_key *pk )
{
  gcry_md_hd_t md;

  if (gcry_md_open (&md, DIGEST_ALGO_SHA1, 0))
    BUG ();
  hash_public_key(md,pk);
  gcry_md_final( md );

  return md;
}


/* fixme: Check whether we can replace this function or if not
   describe why we need it.  */
u32
v3_keyid (gcry_mpi_t a, u32 *ki)
{
  byte *buffer, *p;
  size_t nbytes;

  if (gcry_mpi_print (GCRYMPI_FMT_USG, NULL, 0, &nbytes, a ))
    BUG ();
  /* fixme: allocate it on the stack */
  buffer = xmalloc (nbytes);
  if (gcry_mpi_print( GCRYMPI_FMT_USG, buffer, nbytes, NULL, a ))
    BUG ();
  if (nbytes < 8) /* oops */
    ki[0] = ki[1] = 0;
  else
    {
      p = buffer + nbytes - 8;
      ki[0] = buf32_to_u32 (p);
      p += 4;
      ki[1] = buf32_to_u32 (p);
    }
  xfree (buffer);
  return ki[1];
}


size_t
keystrlen(void)
{
  switch(opt.keyid_format)
    {
    case KF_SHORT:
      return 8;

    case KF_LONG:
      return 16;

    case KF_0xSHORT:
      return 10;

    case KF_0xLONG:
      return 18;

    default:
      BUG();
    }
}


const char *
keystr (u32 *keyid)
{
  static char keyid_str[KEYID_STR_SIZE];

  switch (opt.keyid_format)
    {
    case KF_SHORT:
      snprintf (keyid_str, sizeof keyid_str, "%08lX", (ulong)keyid[1]);
      break;

    case KF_LONG:
      if (keyid[0])
	snprintf (keyid_str, sizeof keyid_str, "%08lX%08lX",
                  (ulong)keyid[0], (ulong)keyid[1]);
      else
	snprintf (keyid_str, sizeof keyid_str, "%08lX", (ulong)keyid[1]);
      break;

    case KF_0xSHORT:
      snprintf (keyid_str, sizeof keyid_str, "0x%08lX", (ulong)keyid[1]);
      break;

    case KF_0xLONG:
      if(keyid[0])
	snprintf (keyid_str, sizeof keyid_str, "0x%08lX%08lX",
                  (ulong)keyid[0],(ulong)keyid[1]);
      else
	snprintf (keyid_str, sizeof keyid_str, "0x%08lX", (ulong)keyid[1]);
      break;

    default:
      BUG();
    }

  return keyid_str;
}


const char *
keystr_with_sub (u32 *main_kid, u32 *sub_kid)
{
  static char buffer[KEYID_STR_SIZE+1+KEYID_STR_SIZE];
  char *p;

  mem2str (buffer, keystr (main_kid), KEYID_STR_SIZE);
  if (sub_kid)
    {
      p = buffer + strlen (buffer);
      *p++ = '/';
      mem2str (p, keystr (sub_kid), KEYID_STR_SIZE);
    }
  return buffer;
}


const char *
keystr_from_pk(PKT_public_key *pk)
{
  keyid_from_pk(pk,NULL);

  return keystr(pk->keyid);
}


const char *
keystr_from_pk_with_sub (PKT_public_key *main_pk, PKT_public_key *sub_pk)
{
  keyid_from_pk (main_pk, NULL);
  if (sub_pk)
    keyid_from_pk (sub_pk, NULL);

  return keystr_with_sub (main_pk->keyid, sub_pk? sub_pk->keyid:NULL);
}



const char *
keystr_from_desc(KEYDB_SEARCH_DESC *desc)
{
  switch(desc->mode)
    {
    case KEYDB_SEARCH_MODE_LONG_KID:
    case KEYDB_SEARCH_MODE_SHORT_KID:
      return keystr(desc->u.kid);

    case KEYDB_SEARCH_MODE_FPR20:
      {
	u32 keyid[2];

	keyid[0] = buf32_to_u32 (desc->u.fpr+12);
	keyid[1] = buf32_to_u32 (desc->u.fpr+16);
	return keystr(keyid);
      }

    case KEYDB_SEARCH_MODE_FPR16:
      return "?v3 fpr?";

    default:
      BUG();
    }
}


/*
 * Get the keyid from the public key and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_pk (PKT_public_key *pk, u32 *keyid)
{
  u32 lowbits;
  u32 dummy_keyid[2];

  if (!keyid)
    keyid = dummy_keyid;

  if( pk->keyid[0] || pk->keyid[1] )
    {
      keyid[0] = pk->keyid[0];
      keyid[1] = pk->keyid[1];
      lowbits = keyid[1];
    }
  else
    {
      const byte *dp;
      gcry_md_hd_t md;

      md = do_fingerprint_md(pk);
      if(md)
	{
	  dp = gcry_md_read ( md, 0 );
	  keyid[0] = buf32_to_u32 (dp+12);
	  keyid[1] = buf32_to_u32 (dp+16);
	  lowbits = keyid[1];
	  gcry_md_close (md);
	  pk->keyid[0] = keyid[0];
	  pk->keyid[1] = keyid[1];
	}
      else
	pk->keyid[0]=pk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
    }

  return lowbits;
}


/*
 * Get the keyid from the fingerprint.	This function is simple for most
 * keys, but has to do a keylookup for old stayle keys.
 */
u32
keyid_from_fingerprint( const byte *fprint, size_t fprint_len, u32 *keyid )
{
  u32 dummy_keyid[2];

  if( !keyid )
    keyid = dummy_keyid;

  if (fprint_len != 20)
    {
      /* This is special as we have to lookup the key first.  */
      PKT_public_key pk;
      int rc;

      memset (&pk, 0, sizeof pk);
      rc = get_pubkey_byfprint (&pk, NULL, fprint, fprint_len);
      if( rc )
        {
          log_error("Oops: keyid_from_fingerprint: no pubkey\n");
          keyid[0] = 0;
          keyid[1] = 0;
        }
      else
        keyid_from_pk (&pk, keyid);
    }
  else
    {
      const byte *dp = fprint;
      keyid[0] = buf32_to_u32 (dp+12);
      keyid[1] = buf32_to_u32 (dp+16);
    }

  return keyid[1];
}


u32
keyid_from_sig (PKT_signature *sig, u32 *keyid)
{
  if( keyid )
    {
      keyid[0] = sig->keyid[0];
      keyid[1] = sig->keyid[1];
    }
  return sig->keyid[1];
}


byte *
namehash_from_uid (PKT_user_id *uid)
{
  if (!uid->namehash)
    {
      uid->namehash = xmalloc (20);

      if (uid->attrib_data)
	rmd160_hash_buffer (uid->namehash, uid->attrib_data, uid->attrib_len);
      else
	rmd160_hash_buffer (uid->namehash, uid->name, uid->len);
    }

  return uid->namehash;
}


/*
 * Return the number of bits used in PK.
 */
unsigned int
nbits_from_pk (PKT_public_key *pk)
{
    return pubkey_nbits (pk->pubkey_algo, pk->pkey);
}


static const char *
mk_datestr (char *buffer, time_t atime)
{
  struct tm *tp;

  if (IS_INVALID_TIME_T (atime))
    strcpy (buffer, "????" "-??" "-??"); /* Mark this as invalid. */
  else
    {
      tp = gmtime (&atime);
      sprintf (buffer,"%04d-%02d-%02d",
               1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday );
    }
  return buffer;
}


/*
 * return a string with the creation date of the pk
 * Note: this is alloced in a static buffer.
 *    Format is: yyyy-mm-dd
 */
const char *
datestr_from_pk (PKT_public_key *pk)
{
  static char buffer[11+5];
  time_t atime = pk->timestamp;

  return mk_datestr (buffer, atime);
}


const char *
datestr_from_sig (PKT_signature *sig )
{
  static char buffer[11+5];
  time_t atime = sig->timestamp;

  return mk_datestr (buffer, atime);
}


const char *
expirestr_from_pk (PKT_public_key *pk)
{
  static char buffer[11+5];
  time_t atime;

  if (!pk->expiredate)
    return _("never     ");
  atime = pk->expiredate;
  return mk_datestr (buffer, atime);
}


const char *
expirestr_from_sig (PKT_signature *sig)
{
  static char buffer[11+5];
  time_t atime;

  if (!sig->expiredate)
    return _("never     ");
  atime=sig->expiredate;
  return mk_datestr (buffer, atime);
}


const char *
revokestr_from_pk( PKT_public_key *pk )
{
  static char buffer[11+5];
  time_t atime;

  if(!pk->revoked.date)
    return _("never     ");
  atime=pk->revoked.date;
  return mk_datestr (buffer, atime);
}


const char *
usagestr_from_pk (PKT_public_key *pk, int fill)
{
  static char buffer[10];
  int i = 0;
  unsigned int use = pk->pubkey_usage;

  if ( use & PUBKEY_USAGE_SIG )
    buffer[i++] = 'S';

  if ( use & PUBKEY_USAGE_CERT )
    buffer[i++] = 'C';

  if ( use & PUBKEY_USAGE_ENC )
    buffer[i++] = 'E';

  if ( (use & PUBKEY_USAGE_AUTH) )
    buffer[i++] = 'A';

  while (fill && i < 4)
    buffer[i++] = ' ';

  buffer[i] = 0;
  return buffer;
}


const char *
colon_strtime (u32 t)
{
  static char buf[20];

  if (!t)
    return "";
  snprintf (buf, sizeof buf, "%lu", (ulong)t);
  return buf;
}

const char *
colon_datestr_from_pk (PKT_public_key *pk)
{
  static char buf[20];

  snprintf (buf, sizeof buf, "%lu", (ulong)pk->timestamp);
  return buf;
}


const char *
colon_datestr_from_sig (PKT_signature *sig)
{
  static char buf[20];

  snprintf (buf, sizeof buf, "%lu", (ulong)sig->timestamp);
  return buf;
}

const char *
colon_expirestr_from_sig (PKT_signature *sig)
{
  static char buf[20];

  if (!sig->expiredate)
    return "";

  snprintf (buf, sizeof buf,"%lu", (ulong)sig->expiredate);
  return buf;
}


/*
 * Return a byte array with the fingerprint for the given PK/SK
 * The length of the array is returned in ret_len. Caller must free
 * the array or provide an array of length MAX_FINGERPRINT_LEN.
 */
byte *
fingerprint_from_pk (PKT_public_key *pk, byte *array, size_t *ret_len)
{
  const byte *dp;
  size_t len;
  gcry_md_hd_t md;

  md = do_fingerprint_md(pk);
  dp = gcry_md_read( md, 0 );
  len = gcry_md_get_algo_dlen (gcry_md_get_algo (md));
  assert( len <= MAX_FINGERPRINT_LEN );
  if (!array)
    array = xmalloc ( len );
  memcpy (array, dp, len );
  pk->keyid[0] = buf32_to_u32 (dp+12);
  pk->keyid[1] = buf32_to_u32 (dp+16);
  gcry_md_close( md);

  if (ret_len)
    *ret_len = len;
  return array;
}


/* Return an allocated buffer with the fingerprint of PK formatted as
   a plain hexstring.  */
char *
hexfingerprint (PKT_public_key *pk)
{
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  size_t len;
  char *result;

  fingerprint_from_pk (pk, fpr, &len);
  result = xmalloc (2 * len + 1);
  bin2hex (fpr, len, result);
  return result;
}



/* Return the so called KEYGRIP which is the SHA-1 hash of the public
   key parameters expressed as an canoncial encoded S-Exp.  ARRAY must
   be 20 bytes long.  Returns 0 on sucess or an error code.  */
gpg_error_t
keygrip_from_pk (PKT_public_key *pk, unsigned char *array)
{
  gpg_error_t err;
  gcry_sexp_t s_pkey;

  if (DBG_PACKET)
    log_debug ("get_keygrip for public key\n");

  switch (pk->pubkey_algo)
    {
    case GCRY_PK_DSA:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                             pk->pkey[0], pk->pkey[1],
                             pk->pkey[2], pk->pkey[3]);
      break;

    case GCRY_PK_ELG:
    case GCRY_PK_ELG_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(elg(p%m)(g%m)(y%m)))",
                             pk->pkey[0], pk->pkey[1], pk->pkey[2]);
      break;

    case GCRY_PK_RSA:
    case GCRY_PK_RSA_S:
    case GCRY_PK_RSA_E:
      err = gcry_sexp_build (&s_pkey, NULL,
                             "(public-key(rsa(n%m)(e%m)))",
                             pk->pkey[0], pk->pkey[1]);
      break;

    case PUBKEY_ALGO_EDDSA:
    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
      {
        char *curve = openpgp_oid_to_str (pk->pkey[0]);
        if (!curve)
          err = gpg_error_from_syserror ();
        else
          {
            err = gcry_sexp_build (&s_pkey, NULL,
                                   pk->pubkey_algo == PUBKEY_ALGO_EDDSA ?
                                   "(public-key(ecc(curve%s)(flags eddsa)(q%m)))"
                                   : "(public-key(ecc(curve%s)(q%m)))",
                                   curve, pk->pkey[1]);
            xfree (curve);
          }
      }
      break;

    default:
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
      break;
    }

  if (err)
    return err;

  if (!gcry_pk_get_keygrip (s_pkey, array))
    {
      log_info ("error computing keygrip\n");
      memset (array, 0, 20);
      err = gpg_error (GPG_ERR_GENERAL);
    }
  else
    {
      if (DBG_PACKET)
        log_printhex ("keygrip=", array, 20);
      /* FIXME: Save the keygrip in PK.  */
    }
  gcry_sexp_release (s_pkey);

  return 0;
}


/* Store an allocated buffer with the keygrip of PK encoded as a
   hexstring at r_GRIP.  Returns 0 on success.  */
gpg_error_t
hexkeygrip_from_pk (PKT_public_key *pk, char **r_grip)
{
  gpg_error_t err;
  unsigned char grip[20];

  *r_grip = NULL;
  err = keygrip_from_pk (pk, grip);
  if (!err)
    {
      char * buf = xtrymalloc (20*2+1);
      if (!buf)
        err = gpg_error_from_syserror ();
      else
        {
          bin2hex (grip, 20, buf);
          *r_grip = buf;
        }
    }
  return err;
}
