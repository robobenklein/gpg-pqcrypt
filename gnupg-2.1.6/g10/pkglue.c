/* pkglue.c - public key operations glue code
 * Copyright (C) 2000, 2003, 2010 Free Software Foundation, Inc.
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
#include <assert.h>

#include "gpg.h"
#include "util.h"
#include "pkglue.h"
#include "main.h"
#include "options.h"

/* FIXME: Better chnage the fucntion name because mpi_ is used by
   gcrypt macros.  */
gcry_mpi_t
get_mpi_from_sexp (gcry_sexp_t sexp, const char *item, int mpifmt)
{
  gcry_sexp_t list;
  gcry_mpi_t data;

  list = gcry_sexp_find_token (sexp, item, 0);
  assert (list);
  data = gcry_sexp_nth_mpi (list, 1, mpifmt);
  assert (data);
  gcry_sexp_release (list);
  return data;
}



/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 */
int
pk_verify (pubkey_algo_t pkalgo, gcry_mpi_t hash,
           gcry_mpi_t *data, gcry_mpi_t *pkey)
{
  gcry_sexp_t s_sig, s_hash, s_pkey;
  int rc;

  /* Make a sexp from pkey.  */
  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2], pkey[3]);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL_E || pkalgo == PUBKEY_ALGO_ELGAMAL)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
    }
  else if (pkalgo == PUBKEY_ALGO_RSA || pkalgo == PUBKEY_ALGO_RSA_S)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))", pkey[0], pkey[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA)
    {
      char *curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecdsa(curve %s)(q%m)))",
                                curve, pkey[1]);
          xfree (curve);
        }
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      char *curve = openpgp_oid_to_str (pkey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecc(curve %s)"
                                "(flags eddsa)(q%m)))",
                                curve, pkey[1]);
          xfree (curve);
        }
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (rc)
    BUG ();  /* gcry_sexp_build should never fail.  */

  /* Put hash into a S-Exp s_hash. */
  if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      if (gcry_sexp_build (&s_hash, NULL,
                           "(data(flags eddsa)(hash-algo sha512)(value %m))",
                           hash))
        BUG (); /* gcry_sexp_build should never fail.  */
    }
  else
    {
      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        BUG (); /* gcry_sexp_build should never fail.  */
    }

  /* Put data into a S-Exp s_sig. */
  s_sig = NULL;
  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(dsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(ecdsa(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(eddsa(r%M)(s%M)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL || pkalgo == PUBKEY_ALGO_ELGAMAL_E)
    {
      if (!data[0] || !data[1])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL,
                              "(sig-val(elg(r%m)(s%m)))", data[0], data[1]);
    }
  else if (pkalgo == PUBKEY_ALGO_RSA || pkalgo == PUBKEY_ALGO_RSA_S)
    {
      if (!data[0])
        rc = gpg_error (GPG_ERR_BAD_MPI);
      else
        rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", data[0]);
    }
  else
    BUG ();

  if (!rc)
    rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  return rc;
}




/****************
 * Emulate our old PK interface here - sometime in the future we might
 * change the internal design to directly fit to libgcrypt.
 * PK is only required to compute the fingerprint for ECDH.
 */
int
pk_encrypt (pubkey_algo_t algo, gcry_mpi_t *resarr, gcry_mpi_t data,
            PKT_public_key *pk, gcry_mpi_t *pkey)
{
  gcry_sexp_t s_ciph = NULL;
  gcry_sexp_t s_data = NULL;
  gcry_sexp_t s_pkey = NULL;
  int rc;

  /* Make a sexp from pkey.  */
  if (algo == PUBKEY_ALGO_ELGAMAL || algo == PUBKEY_ALGO_ELGAMAL_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(elg(p%m)(g%m)(y%m)))",
			    pkey[0], pkey[1], pkey[2]);
      /* Put DATA into a simplified S-expression.  */
      if (!rc)
        rc = gcry_sexp_build (&s_data, NULL, "%m", data);
    }
  else if (algo == PUBKEY_ALGO_RSA || algo == PUBKEY_ALGO_RSA_E)
    {
      rc = gcry_sexp_build (&s_pkey, NULL,
			    "(public-key(rsa(n%m)(e%m)))",
			    pkey[0], pkey[1]);
      /* Put DATA into a simplified S-expression.  */
      if (!rc)
        rc = gcry_sexp_build (&s_data, NULL, "%m", data);
    }
  else if (algo == PUBKEY_ALGO_ECDH)
    {
      gcry_mpi_t k;

      rc = pk_ecdh_generate_ephemeral_key (pkey, &k);
      if (!rc)
        {
          char *curve;

          curve = openpgp_oid_to_str (pkey[0]);
          if (!curve)
            rc = gpg_error_from_syserror ();
          else
            {
              /* Now use the ephemeral secret to compute the shared point.  */
              rc = gcry_sexp_build (&s_pkey, NULL,
                                    "(public-key(ecdh(curve%s)(q%m)))",
                                    curve, pkey[1]);
              xfree (curve);
              /* Put K into a simplified S-expression.  */
              if (!rc)
                rc = gcry_sexp_build (&s_data, NULL, "%m", k);
            }
          gcry_mpi_release (k);
        }
    }
  else
    rc = gpg_error (GPG_ERR_PUBKEY_ALGO);

  /* Pass it to libgcrypt. */
  if (!rc)
    rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);

  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);

  if (rc)
    ;
  else if (algo == PUBKEY_ALGO_ECDH)
    {
      gcry_mpi_t shared, public, result;
      byte fp[MAX_FINGERPRINT_LEN];
      size_t fpn;

      /* Get the shared point and the ephemeral public key.  */
      shared = get_mpi_from_sexp (s_ciph, "s", GCRYMPI_FMT_USG);
      public = get_mpi_from_sexp (s_ciph, "e", GCRYMPI_FMT_USG);
      gcry_sexp_release (s_ciph);
      s_ciph = NULL;
      if (DBG_CRYPTO)
        {
          log_debug ("ECDH ephemeral key:");
          gcry_mpi_dump (public);
          log_printf ("\n");
        }

      result = NULL;
      fingerprint_from_pk (pk, fp, &fpn);
      if (fpn != 20)
        rc = gpg_error (GPG_ERR_INV_LENGTH);
      else
        rc = pk_ecdh_encrypt_with_shared_point (1 /*=encrypton*/, shared,
                                                fp, data, pkey, &result);
      gcry_mpi_release (shared);
      if (!rc)
        {
          resarr[0] = public;
          resarr[1] = result;
        }
      else
        {
          gcry_mpi_release (public);
          gcry_mpi_release (result);
        }
    }
  else /* Elgamal or RSA case.  */
    { /* Fixme: Add better error handling or make gnupg use
         S-expressions directly.  */
      resarr[0] = get_mpi_from_sexp (s_ciph, "a", GCRYMPI_FMT_USG);
      if (!is_RSA (algo))
        resarr[1] = get_mpi_from_sexp (s_ciph, "b", GCRYMPI_FMT_USG);
    }

  gcry_sexp_release (s_ciph);
  return rc;
}


/* Check whether SKEY is a suitable secret key. */
int
pk_check_secret_key (pubkey_algo_t pkalgo, gcry_mpi_t *skey)
{
  gcry_sexp_t s_skey;
  int rc;

  if (pkalgo == PUBKEY_ALGO_DSA)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4]);
    }
  else if (pkalgo == PUBKEY_ALGO_ELGAMAL || pkalgo == PUBKEY_ALGO_ELGAMAL_E)
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(elg(p%m)(g%m)(y%m)(x%m)))",
			    skey[0], skey[1], skey[2], skey[3]);
    }
  else if (is_RSA (pkalgo))
    {
      rc = gcry_sexp_build (&s_skey, NULL,
			    "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
			    skey[0], skey[1], skey[2], skey[3], skey[4],
			    skey[5]);
    }
  else if (pkalgo == PUBKEY_ALGO_ECDSA || pkalgo == PUBKEY_ALGO_ECDH)
    {
      char *curve = openpgp_oid_to_str (skey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_skey, NULL,
                                "(private-key(ecc(curve%s)(q%m)(d%m)))",
                                curve, skey[1], skey[2]);
          xfree (curve);
        }
    }
  else if (pkalgo == PUBKEY_ALGO_EDDSA)
    {
      char *curve = openpgp_oid_to_str (skey[0]);
      if (!curve)
        rc = gpg_error_from_syserror ();
      else
        {
          rc = gcry_sexp_build (&s_skey, NULL,
                                "(private-key(ecc(curve %s)"
                                "(flags eddsa)(q%m)(d%m)))",
                                curve, skey[1], skey[2]);
          xfree (curve);
        }
    }
  else
    return GPG_ERR_PUBKEY_ALGO;

  if (!rc)
    {
      rc = gcry_pk_testkey (s_skey);
      gcry_sexp_release (s_skey);
    }
  return rc;
}
