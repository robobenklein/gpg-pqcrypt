/* pksign.c - public key signing (well, actually using a secret key)
 * Copyright (C) 2001-2004, 2010 Free Software Foundation, Inc.
 * Copyright (C) 2001-2004, 2010, 2013  Werner Koch
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
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "agent.h"
#include "i18n.h"


static int
do_encode_md (const byte * md, size_t mdlen, int algo, gcry_sexp_t * r_hash,
	      int raw_value)
{
  gcry_sexp_t hash;
  int rc;

  if (!raw_value)
    {
      const char *s;
      char tmp[16+1];
      int i;

      s = gcry_md_algo_name (algo);
      if (s && strlen (s) < 16)
	{
	  for (i=0; i < strlen (s); i++)
	    tmp[i] = tolower (s[i]);
	  tmp[i] = '\0';
	}

      rc = gcry_sexp_build (&hash, NULL,
			    "(data (flags pkcs1) (hash %s %b))",
			    tmp, (int)mdlen, md);
    }
  else
    {
      gcry_mpi_t mpi;

      rc = gcry_mpi_scan (&mpi, GCRYMPI_FMT_USG, md, mdlen, NULL);
      if (!rc)
	{
	  rc = gcry_sexp_build (&hash, NULL,
				"(data (flags raw) (value %m))",
				mpi);
	  gcry_mpi_release (mpi);
	}
      else
        hash = NULL;

    }

  *r_hash = hash;
  return rc;
}


/* Return the number of bits of the Q parameter from the DSA key
   KEY.  */
static unsigned int
get_dsa_qbits (gcry_sexp_t key)
{
  gcry_sexp_t l1, l2;
  gcry_mpi_t q;
  unsigned int nbits;

  l1 = gcry_sexp_find_token (key, "private-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (key, "protected-private-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (key, "shadowed-private-key", 0);
  if (!l1)
    l1 = gcry_sexp_find_token (key, "public-key", 0);
  if (!l1)
    return 0; /* Does not contain a key object.  */
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release  (l1);
  l1 = gcry_sexp_find_token (l2, "q", 1);
  gcry_sexp_release (l2);
  if (!l1)
    return 0; /* Invalid object.  */
  q = gcry_sexp_nth_mpi (l1, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l1);
  if (!q)
    return 0; /* Missing value.  */
  nbits = gcry_mpi_get_nbits (q);
  gcry_mpi_release (q);

  return nbits;
}


/* Return an appropriate hash algorithm to be used with RFC-6979 for a
   message digest of length MDLEN.  Although a fallback of SHA-256 is
   used the current implementation in Libgcrypt will reject a hash
   algorithm which does not match the length of the message.  */
static const char *
rfc6979_hash_algo_string (size_t mdlen)
{
  switch (mdlen)
    {
    case 20: return "sha1";
    case 28: return "sha224";
    case 32: return "sha256";
    case 48: return "sha384";
    case 64: return "sha512";
    default: return "sha256";
    }
}


/* Encode a message digest for use with the EdDSA algorithm
   (i.e. curve Ed25519). */
static gpg_error_t
do_encode_eddsa (const byte *md, size_t mdlen, gcry_sexp_t *r_hash)
{
  gpg_error_t err;
  gcry_sexp_t hash;

  *r_hash = NULL;
  err = gcry_sexp_build (&hash, NULL,
                         "(data(flags eddsa)(hash-algo sha512)(value %b))",
                         (int)mdlen, md);
  if (!err)
    *r_hash = hash;
  return err;
}


/* Encode a message digest for use with an DSA algorithm. */
static gpg_error_t
do_encode_dsa (const byte *md, size_t mdlen, int pkalgo, gcry_sexp_t pkey,
               gcry_sexp_t *r_hash)
{
  gpg_error_t err;
  gcry_sexp_t hash;
  unsigned int qbits;

  *r_hash = NULL;

  if (pkalgo == GCRY_PK_ECDSA)
    qbits = gcry_pk_get_nbits (pkey);
  else if (pkalgo == GCRY_PK_DSA)
    qbits = get_dsa_qbits (pkey);
  else
    return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);

  if (pkalgo == GCRY_PK_DSA && (qbits%8))
    {
      /* FIXME: We check the QBITS but print a message about the hash
         length.  */
      log_error (_("DSA requires the hash length to be a"
                   " multiple of 8 bits\n"));
      return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* Don't allow any Q smaller than 160 bits.  We don't want someone
     to issue signatures from a key with a 16-bit Q or something like
     that, which would look correct but allow trivial forgeries.  Yes,
     I know this rules out using MD5 with DSA. ;) */
  if (qbits < 160)
    {
      log_error (_("%s key uses an unsafe (%u bit) hash\n"),
                 gcry_pk_algo_name (pkalgo), qbits);
      return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* Check if we're too short.  Too long is safe as we'll
   * automatically left-truncate.
   *
   * This check would require the use of SHA512 with ECDSA 512. I
   * think this is overkill to fail in this case.  Therefore, relax
   * the check, but only for ECDSA keys.  We may need to adjust it
   * later for general case.  (Note that the check is really a bug for
   * ECDSA 521 as the only hash that matches it is SHA 512, but 512 <
   * 521 ).
   */
  if (mdlen < ((pkalgo==GCRY_PK_ECDSA && qbits > 521) ? 512 : qbits)/8)
    {
      log_error (_("a %zu bit hash is not valid for a %u bit %s key\n"),
                 mdlen*8,
                 gcry_pk_get_nbits (pkey),
                 gcry_pk_algo_name (pkalgo));
      /* FIXME: we need to check the requirements for ECDSA.  */
      if (mdlen < 20 || pkalgo == GCRY_PK_DSA)
        return gpg_error (GPG_ERR_INV_LENGTH);
    }

  /* Truncate.  */
  if (mdlen > qbits/8)
    mdlen = qbits/8;

  /* Create the S-expression.  */
  err = gcry_sexp_build (&hash, NULL,
                         "(data (flags rfc6979) (hash %s %b))",
                         rfc6979_hash_algo_string (mdlen),
                         (int)mdlen, md);
  if (!err)
    *r_hash = hash;
  return err;
}


/* Special version of do_encode_md to take care of pkcs#1 padding.
   For TLS-MD5SHA1 we need to do the padding ourself as Libgrypt does
   not know about this special scheme.  Fixme: We should have a
   pkcs1-only-padding flag for Libgcrypt. */
static int
do_encode_raw_pkcs1 (const byte *md, size_t mdlen, unsigned int nbits,
                     gcry_sexp_t *r_hash)
{
  int rc;
  gcry_sexp_t hash;
  unsigned char *frame;
  size_t i, n, nframe;

  nframe = (nbits+7) / 8;
  if ( !mdlen || mdlen + 8 + 4 > nframe )
    {
      /* Can't encode this hash into a frame of size NFRAME. */
      return gpg_error (GPG_ERR_TOO_SHORT);
    }

  frame = xtrymalloc (nframe);
  if (!frame)
    return gpg_error_from_syserror ();

  /* Assemble the pkcs#1 block type 1. */
  n = 0;
  frame[n++] = 0;
  frame[n++] = 1; /* Block type. */
  i = nframe - mdlen - 3 ;
  assert (i >= 8); /* At least 8 bytes of padding.  */
  memset (frame+n, 0xff, i );
  n += i;
  frame[n++] = 0;
  memcpy (frame+n, md, mdlen );
  n += mdlen;
  assert (n == nframe);

  /* Create the S-expression.  */
  rc = gcry_sexp_build (&hash, NULL,
                        "(data (flags raw) (value %b))",
                        (int)nframe, frame);
  xfree (frame);

  *r_hash = hash;
  return rc;
}



/* SIGN whatever information we have accumulated in CTRL and return
   the signature S-expression.  LOOKUP is an optional function to
   provide a way for lower layers to ask for the caching TTL.  If a
   CACHE_NONCE is given that cache item is first tried to get a
   passphrase.  If OVERRIDEDATA is not NULL, OVERRIDEDATALEN bytes
   from this buffer are used instead of the data in CTRL.  The
   override feature is required to allow the use of Ed25519 with ssh
   because Ed25519 dies the hashing itself.  */
int
agent_pksign_do (ctrl_t ctrl, const char *cache_nonce,
                 const char *desc_text,
		 gcry_sexp_t *signature_sexp,
                 cache_mode_t cache_mode, lookup_ttl_t lookup_ttl,
                 const void *overridedata, size_t overridedatalen)
{
  gcry_sexp_t s_skey = NULL, s_sig = NULL;
  unsigned char *shadow_info = NULL;
  unsigned int rc = 0;		/* FIXME: gpg-error? */
  const unsigned char *data;
  int datalen;

  if (overridedata)
    {
      data = overridedata;
      datalen = overridedatalen;
    }
  else
    {
      data = ctrl->digest.value;
      datalen = ctrl->digest.valuelen;
    }

  if (!ctrl->have_keygrip)
    return gpg_error (GPG_ERR_NO_SECKEY);

  rc = agent_key_from_file (ctrl, cache_nonce, desc_text, ctrl->keygrip,
                            &shadow_info, cache_mode, lookup_ttl,
                            &s_skey, NULL);
  if (rc)
    {
      if (gpg_err_code (rc) != GPG_ERR_NO_SECKEY)
        log_error ("failed to read the secret key\n");
      goto leave;
    }

  if (shadow_info)
    {
      /* Divert operation to the smartcard */
      size_t len;
      unsigned char *buf = NULL;
      int key_type;
      int is_RSA = 0;
      int is_ECDSA = 0;
      int is_EdDSA = 0;

      if (agent_is_eddsa_key (s_skey))
        is_EdDSA = 1;
      else
        {
          key_type = agent_is_dsa_key (s_skey);
          if (key_type == 0)
            is_RSA = 1;
          else if (key_type == GCRY_PK_ECDSA)
            is_ECDSA = 1;
        }

      rc = divert_pksign (ctrl,
                          data, datalen,
                          ctrl->digest.algo,
                          shadow_info, &buf, &len);
      if (rc)
        {
          log_error ("smartcard signing failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (is_RSA)
        {
          if (*buf & 0x80)
            {
              len++;
              buf = xtryrealloc (buf, len);
              if (!buf)
                goto leave;

              memmove (buf + 1, buf, len - 1);
              *buf = 0;
            }

          rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%b)))",
                                (int)len, buf);
        }
      else if (is_EdDSA)
        {
          rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(eddsa(r%b)(s%b)))",
                                (int)len/2, buf, (int)len/2, buf + len/2);
        }
      else if (is_ECDSA)
        {
          unsigned char *r_buf_allocated = NULL;
          unsigned char *s_buf_allocated = NULL;
          unsigned char *r_buf, *s_buf;
          int r_buflen, s_buflen;

          r_buflen = s_buflen = len/2;

          if (*buf & 0x80)
            {
              r_buflen++;
              r_buf_allocated = xtrymalloc (r_buflen);
              if (!r_buf_allocated)
                goto leave;

              r_buf = r_buf_allocated;
              memcpy (r_buf + 1, buf, len/2);
              *r_buf = 0;
            }
          else
            r_buf = buf;

          if (*(buf + len/2) & 0x80)
            {
              s_buflen++;
              s_buf_allocated = xtrymalloc (s_buflen);
              if (!s_buf_allocated)
                {
                  xfree (r_buf_allocated);
                  goto leave;
                }

              s_buf = s_buf_allocated;
              memcpy (s_buf + 1, buf + len/2, len/2);
              *s_buf = 0;
            }
          else
            s_buf = buf + len/2;

          rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(ecdsa(r%b)(s%b)))",
                                r_buflen, r_buf,
                                s_buflen, s_buf);
          xfree (r_buf_allocated);
          xfree (s_buf_allocated);
        }
      else
        rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

      xfree (buf);
      if (rc)
	{
	  log_error ("failed to convert sigbuf returned by divert_pksign "
		     "into S-Exp: %s", gpg_strerror (rc));
	  goto leave;
	}
    }
  else
    {
      /* No smartcard, but a private key */
      gcry_sexp_t s_hash = NULL;
      int dsaalgo;

      /* Put the hash into a sexp */
      if (agent_is_eddsa_key (s_skey))
        rc = do_encode_eddsa (data, datalen,
                              &s_hash);
      else if (ctrl->digest.algo == MD_USER_TLS_MD5SHA1)
        rc = do_encode_raw_pkcs1 (data, datalen,
                                  gcry_pk_get_nbits (s_skey),
                                  &s_hash);
      else if ( (dsaalgo = agent_is_dsa_key (s_skey)) )
        rc = do_encode_dsa (data, datalen,
                            dsaalgo, s_skey,
                            &s_hash);
      else
        rc = do_encode_md (data, datalen,
                           ctrl->digest.algo,
                           &s_hash,
                           ctrl->digest.raw_value);
      if (rc)
        goto leave;

      if (DBG_CRYPTO)
        {
          gcry_log_debugsxp ("skey", s_skey);
          gcry_log_debugsxp ("hash", s_hash);
        }

      /* sign */
      rc = gcry_pk_sign (&s_sig, s_hash, s_skey);
      gcry_sexp_release (s_hash);
      if (rc)
        {
          log_error ("signing failed: %s\n", gpg_strerror (rc));
          goto leave;
        }

      if (DBG_CRYPTO)
        gcry_log_debugsxp ("rslt", s_sig);
    }

 leave:

  *signature_sexp = s_sig;

  gcry_sexp_release (s_skey);
  xfree (shadow_info);

  return rc;
}

/* SIGN whatever information we have accumulated in CTRL and write it
   back to OUTFP.  If a CACHE_NONCE is given that cache item is first
   tried to get a passphrase.  */
int
agent_pksign (ctrl_t ctrl, const char *cache_nonce, const char *desc_text,
              membuf_t *outbuf, cache_mode_t cache_mode)
{
  gcry_sexp_t s_sig = NULL;
  char *buf = NULL;
  size_t len = 0;
  int rc = 0;

  rc = agent_pksign_do (ctrl, cache_nonce, desc_text, &s_sig, cache_mode, NULL,
                        NULL, 0);
  if (rc)
    goto leave;

  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xmalloc (len);
  len = gcry_sexp_sprint (s_sig, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  put_membuf (outbuf, buf, len);

 leave:
  gcry_sexp_release (s_sig);
  xfree (buf);

  return rc;
}
