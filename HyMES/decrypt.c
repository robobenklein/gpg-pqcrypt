/*
* MCE, the real life implementation of McEliece encryption scheme.
* Copyright Projet SECRET, INRIA, Rocquencourt and Bhaskar Biswas and 
* Nicolas Sendrier (Bhaskar.Biswas@inria.fr, Nicolas.Sendrier@inria.fr).
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
#include <stdlib.h>
#include <string.h>
#include "sizes.h"
#include "gf.h"
#include "poly.h"
#include "dicho.h"
#include "randomize.h"

extern precomp_t cwdata;

poly_t g, sqrtmod[NB_ERRORS];
gf_t * Linv;
unsigned long * coeffs;

void sk_from_string(const unsigned char * sk)
{
  int i;
  // L, g, coeffs and sqrt declared as global variables:
  // gf_t *Linv, *coeffs;
  // poly_t g, sqrtmod[NB_ERRORS];

  coeffs = (unsigned long *) sk;
  sk += LENGTH *  BITS_TO_LONG(CODIMENSION) * sizeof (long);

  Linv = (gf_t *) sk;
  sk += LENGTH * sizeof (gf_t);

  g = poly_alloc_from_string(NB_ERRORS, sk);
  poly_set_deg(g, NB_ERRORS);
  sk += (NB_ERRORS + 1) * sizeof (gf_t);

  for (i = 0; i < NB_ERRORS; ++i) {
    sqrtmod[i] = poly_alloc_from_string(NB_ERRORS - 1, sk);
    poly_set_deg(sqrtmod[i], NB_ERRORS - 1);
    sk += NB_ERRORS * sizeof (gf_t);
  }
}

void sk_free()
{
  int i;

  free(g);
  for (i = 0; i < NB_ERRORS; ++i) {
    free(sqrtmod[i]);
  }
}

void xor(unsigned long * a, unsigned long * b) {
  int i;

  for (i = 0; i < BITS_TO_LONG(CODIMENSION); ++i)
    a[i] ^= b[i];
}

// syndrome computation is affected by the vec_concat procedure (see encrypt.c)
poly_t syndrome(const unsigned char * b)
{
  int i, j, k, l;
  poly_t R;
  gf_t a;
  unsigned long c[BITS_TO_LONG(CODIMENSION)];

  memset(c, 0, BITS_TO_LONG(CODIMENSION) * sizeof (long));

  R = poly_alloc(NB_ERRORS - 1);
  for (j = 0; j < LENGTH; j++)
    {
      if ((b[j / 8] >> (j % 8)) & 1)
	xor(c, coeffs + j * BITS_TO_LONG(CODIMENSION));
    }

  // transform the binary vector c of length EXT_DEGREE * NB_ERRORS in
  // a polynomial of degree NB_ERRORS
  for (l = 0; l < NB_ERRORS; ++l) {
    k = (l * EXT_DEGREE) / BIT_SIZE_OF_LONG;
    j = (l * EXT_DEGREE) % BIT_SIZE_OF_LONG;
    a = c[k] >> j;
    if (j + EXT_DEGREE > BIT_SIZE_OF_LONG)
      a ^= c[k + 1] << (BIT_SIZE_OF_LONG - j);
    a &= ((1 << EXT_DEGREE) - 1);
    poly_set_coeff(R, l, a);
  }

  poly_calcule_deg(R);
  return R;
}

int roots_berl_aux(poly_t sigma, int d, poly_t * tr_aux, poly_t * tr, int e, gf_t * res) {
  poly_t gcd1, gcd2;
  int i, j;
  gf_t a;

  if (d == 0) {
    return 0;
  }

  if (d == 1) {
    *res = gf_div(poly_coeff(sigma, 0), poly_coeff(sigma, 1));
    return 1;
  }

  // not before because we may have e == EXT_DEGREE and d == 1
  if (e >= EXT_DEGREE) {
    return 0;
  }

  if (tr[e] == NULL) {
    tr[e] = poly_alloc(NB_ERRORS - 1);
    a = gf_exp(e);
    for (i = 0; i < EXT_DEGREE; ++i) {
      for (j = 0; j < NB_ERRORS; ++j)
	poly_addto_coeff(tr[e], j, gf_mul(poly_coeff(tr_aux[i], j), a));
      a = gf_square(a);
    }
    poly_calcule_deg(tr[e]);
  }
  gcd1 = poly_gcd(tr[e], sigma);
  gcd2 = poly_quo(sigma, gcd1);

  i = poly_deg(gcd1);

  j = roots_berl_aux(gcd1, i, tr_aux, tr, e + 1, res);
  j += roots_berl_aux(gcd2, d - i, tr_aux, tr, e + 1, res + j);

  poly_free(gcd1);
  poly_free(gcd2);

  return j;
}

int roots_berl(poly_t sigma, gf_t * res) {
  poly_t * sq_aux, * tr, * tr_aux;
  int i, j, d;
  gf_t a;

  sq_aux = malloc(NB_ERRORS * sizeof (poly_t));
  tr_aux = malloc(EXT_DEGREE * sizeof (poly_t));
  tr = malloc(EXT_DEGREE * sizeof (poly_t));
  for (i = 0; i < NB_ERRORS; ++i)
    sq_aux[i] = poly_alloc(NB_ERRORS + 1);
  for (i = 0; i < EXT_DEGREE; ++i)
    tr_aux[i] = poly_alloc(NB_ERRORS - 1);
  for (i = 0; i < EXT_DEGREE; ++i)
    tr[i] = NULL;

  poly_sqmod_init(sigma, sq_aux);
  poly_set_coeff(tr_aux[0], 1, gf_unit());
  poly_set_deg(tr_aux[0], 1);
  tr[0] = poly_alloc(NB_ERRORS - 1);
  poly_set_coeff(tr[0], 1, gf_unit());
  for (i = 1; i < EXT_DEGREE; ++i) {
    poly_sqmod(tr_aux[i], tr_aux[i - 1], sq_aux, NB_ERRORS);
    for (j = 0; j < NB_ERRORS; ++j)
      poly_addto_coeff(tr[0], j, poly_coeff(tr_aux[i], j));
  }
  poly_calcule_deg(tr[0]);
  for (i = 0; i < NB_ERRORS; ++i)
    poly_free(sq_aux[i]);
  free(sq_aux);
  d = roots_berl_aux(sigma, NB_ERRORS, tr_aux, tr, 0, res);
  for (i = 0; i < EXT_DEGREE; ++i)
    poly_free(tr_aux[i]);
  free(tr_aux);
  for (i = 0; i < EXT_DEGREE; ++i)
    if (tr[i] != NULL)
      poly_free(tr[i]);
  free(tr);

  return d;
}

int partition (int * tableau, int gauche, int droite, int pivot) {
  int i, temp;
  for (i = gauche; i < droite; i++)
    if (tableau[i] <= pivot) {
      temp = tableau[i];
      tableau[i] = tableau[gauche];
      tableau[gauche] = temp;
      ++gauche;
    }
  return gauche;
}

void quickSort(int * tableau, int gauche, int droite, int min, int max) {
  if (gauche < droite - 1) {
    int milieu = partition(tableau, gauche, droite, (max + min) / 2);
    quickSort(tableau, gauche, milieu, min, (max + min) / 2);
    quickSort(tableau, milieu, droite, (max + min) / 2, max);
  }
}

int decode(const unsigned char * b, int * e)
{
  int i,j,d;
  poly_t u,v,h,sigma,R,S,aux;
  gf_t a, res[NB_ERRORS];

  gf_init(EXT_DEGREE);
  R = syndrome(b);

  //1. Compute S(z), such that, S(z)^2=(h(z)+z)%g(z).
  //2. Compute u(z),v(z), such that, deg(u)<=t/2, deg(v)<=(t-1)/2 and u(z)=S(z).v(z)%g(z).
  //3. Compute Sigma_e(z)=u(z^2)+z(v(z)^2).->The locator polynomial of the code C.

  poly_eeaux(&h ,&aux, R, g, 1);
  a = gf_inv(poly_coeff(aux,0));
  for (i = 0; i <= poly_deg(h); ++i)
    poly_set_coeff(h,i,gf_mul_fast(a,poly_coeff(h,i)));
  poly_free(aux);
  poly_free(R);

  //  compute h(z) += z
  poly_addto_coeff(h, 1, gf_unit());

  // compute S square root of h (using sqrtmod)
  S = poly_alloc(NB_ERRORS - 1);
  for(i=0;i<NB_ERRORS;i++) {
    a = gf_sqrt(poly_coeff(h,i));
    if (a != gf_zero()) {
      if (i & 1) {
	for(j=0;j<NB_ERRORS;j++)
	  poly_addto_coeff(S, j, gf_mul_fast(a, poly_coeff(sqrtmod[i],j)));
      }
      else
	poly_addto_coeff(S, i/2, a);
    }
  }
  poly_calcule_deg(S);
  poly_free(h);

  // solve the key equation u(z) = v(z)*S(z) mod g(z)
  poly_eeaux(&v, &u, S, g, NB_ERRORS/2+1);
  poly_free(S);

  // sigma = u^2+z*v^2
  sigma = poly_alloc(NB_ERRORS);
  for (i = 0; i <= poly_deg(u); ++i) {
    poly_set_coeff(sigma, 2*i, gf_square(poly_coeff(u,i)));
  }
  for (i = 0; i <= poly_deg(v); ++i) {
    poly_set_coeff(sigma, 2*i+1, gf_square(poly_coeff(v,i)));
  }
  poly_free(u);
  poly_free(v);

  poly_calcule_deg(sigma);

  d = poly_deg(sigma);
  if (d != NB_ERRORS) {
    poly_free(sigma);
    return -1;
  }

  d = roots_berl(sigma, res);
  if (d != NB_ERRORS) {
    poly_free(sigma);
    return -1;
  }

  for (i = 0; i < d; ++i)
    e[i] = Linv[res[i]];

  // we need the error pattern sorted in increasing order
  quickSort(e, 0, NB_ERRORS, 0, 1 << EXT_DEGREE);

  poly_free(sigma);

  return d;
}

int decrypt_block(unsigned char *cleartext, unsigned char *ciphertext, const unsigned char * sk)
{
  int i, j, k, l, e[NB_ERRORS];
  unsigned char c;

  sk_from_string(sk);

  // assumes e is ordered
  i = decode(ciphertext, e);
  sk_free();

  if (i < 0)
    return -1;

  // flip t error positions
  for (i = 0; i < NB_ERRORS; i++)
    ciphertext[e[i] / 8] ^= (1 << (e[i] % 8)); // As 8 is the length of unsigned char.

  memcpy(cleartext, ciphertext, BITS_TO_BYTES(DIMENSION));

  // writes into cleartext a binary bit stream of length ERROR_SIZE
  // starting at position DIMENSION corresponding to the error pattern
  // in cw
  i = dicho_cw2b(e, cleartext,
		 DIMENSION, ERROR_SIZE,
		 LOG_LENGTH, ERROR_WEIGHT, cwdata);
  // returns the number of bits used (i < 0 if less than ERROR_SIZE
  // bits are used)

  if (i < 0)
    return -1;

  return 1;
}

// The suffix _ss is for "semantically secure", the ciphertext is
// decrypted into cleartext which is unrandomize into message with a
// consistency check
int decrypt_block_ss(unsigned char *message, unsigned char *ciphertext, const unsigned char * sk)
{
  int i;
  unsigned char cleartext[CLEARTEXT_LENGTH];

  i = decrypt_block(cleartext, ciphertext, sk);

  if (i > 0)
    // returns a negative number in case of an unconsistent block
    return unrandomize(message, cleartext);

  return i;
}
