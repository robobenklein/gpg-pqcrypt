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
#include "matrix.h"

__inline int u8rnd() { return random() & 0xff; }

__inline unsigned int u32rnd() { return u8rnd() ^ (u8rnd()<<8) ^ (u8rnd()<<16) ^ (u8rnd()<<24); }

/*********************************************************************************************/
////////////////////////////////////KEY-GENERATION Function////////////////////////////////////
/*********************************************************************************************/

//The support for key-gen

void gop_supr(int n,gf_t *L) 
{
  unsigned int i, j;
  gf_t tmp;

  for (i = 0; i < n; ++i) 
    {
      j = i + u32rnd() % (n - i);

      tmp = L[j];
      L[j] = L[i];
      L[i] = tmp;
    }
}


binmat_t key_genmat(gf_t *L, poly_t g)
{
  //L- Support
  //t- Number of errors, i.e.=30.
  //n- Length of the Goppa code, i.e.=2^11
  //m- The extension degree of the GF, i.e. =11
  //g- The generator polynomial.
  gf_t x,y;
  binmat_t H,R; 
  int i,j,k,r,n;
  int * perm, Laux[LENGTH];

  n=LENGTH;//2^11=2048
  r=NB_ERRORS*EXT_DEGREE;//32 x 11=352

  H=mat_ini(r,n);//initialize matrix with actual no. of bits.
  mat_set_to_zero(H); //set the matrix with all 0's.

  for(i=0;i< n;i++)
    {
      x = poly_eval(g,L[i]);//evaluate the polynomial at the point L[i].
      x = gf_inv(x);
      y = x;
      for(j=0;j<NB_ERRORS;j++)
	{
	  for(k=0;k<EXT_DEGREE;k++)
	    {
	      if(y & (1<<k))//if((y>>k) & 1)
		mat_set_coeff_to_one(H,j*EXT_DEGREE + k,i);//the co-eff. are set in 2^0,...,2^11 ; 2^0,...,2^11 format along the rows/cols?
	    }
	  y = gf_mul(y,L[i]);
	}
    }//The H matrix is fed.
  
  perm = mat_rref(H);
  if (perm == NULL) {
    mat_free(H);
    return NULL;
  }
  
  R = mat_ini(n-r,r);
  mat_set_to_zero(R); //set the matrix with all 0's.
  for (i = 0; i < R->rown; ++i)
    for (j = 0; j < R->coln; ++j)
      if (mat_coeff(H,j,perm[i]))
	mat_change_coeff(R,i,j);

  for (i = 0; i < LENGTH; ++i)
    Laux[i] = L[perm[i]];
  for (i = 0; i < LENGTH; ++i)
    L[i] = Laux[i];

  mat_free(H);
  free(perm);

  return (R);
}

int keypair(unsigned char * sk, unsigned char * pk)
{
  int i, j, k, l;
  unsigned long * pt;
  gf_t *L, *Linv;
  poly_t g, *sqrtmod, *F;
  binmat_t R;

  gf_init(EXT_DEGREE);

  //pick the support.........
  L = malloc(LENGTH * sizeof(gf_t));

  for(i=0;i<LENGTH;i++)
    L[i]=i;
  gop_supr(LENGTH,L);

  do {
    //pick the irreducible polynomial.....
    g = poly_randgen_irred(NB_ERRORS, u8rnd);
    R = key_genmat(L,g);
    if (R == NULL)
      poly_free(g);
  } while (R == NULL);

  sqrtmod = poly_sqrtmod_init(g);
  F = poly_syndrome_init(g, L, LENGTH);

  // Each F[i] is the (precomputed) syndrome of the error vector with
  // a single '1' in i-th position.
  // We do not store the F[i] as polynomials of degree NB_ERRORS, but
  // as binary vectors of length EXT_DEGREE * NB_ERRORS (this will
  // speed up the syndrome computation)
  for (i = 0; i < LENGTH; ++i) {
    memset(sk, 0, BITS_TO_LONG(CODIMENSION) * sizeof (long));
    pt = (unsigned long *) sk;
    for (l = 0; l < NB_ERRORS; ++l) {
      k = (l * EXT_DEGREE) / BIT_SIZE_OF_LONG;
      j = (l * EXT_DEGREE) % BIT_SIZE_OF_LONG;
      pt[k] ^= poly_coeff(F[i], l) << j;
      if (j + EXT_DEGREE > BIT_SIZE_OF_LONG)
	pt[k + 1] ^= poly_coeff(F[i], l) >> (BIT_SIZE_OF_LONG - j);
    }
    sk += BITS_TO_LONG(CODIMENSION) * sizeof (long);
    poly_free(F[i]);
  }
  free(F);

  // We need the support L for decoding (decryption). In fact the
  // inverse is needed
  Linv = malloc(LENGTH * sizeof (gf_t));
  for (i = 0; i < LENGTH; ++i)
    Linv[L[i]] = i;
  memcpy(sk, Linv, LENGTH * sizeof (gf_t));
  sk += LENGTH * sizeof (gf_t);
  free(L);
  free(Linv);

  memcpy(sk, g->coeff, (NB_ERRORS + 1) * sizeof (gf_t));
  sk += (NB_ERRORS + 1) * sizeof (gf_t);
  poly_free(g);

  for (i = 0; i < NB_ERRORS; ++i) {
    memcpy(sk, sqrtmod[i]->coeff, NB_ERRORS * sizeof (gf_t));
    sk += NB_ERRORS * sizeof (gf_t);
    poly_free(sqrtmod[i]);
  }
  free(sqrtmod);

  memcpy(pk, R->elem, R->alloc_size);
  mat_free(R);

  return 1;
}
