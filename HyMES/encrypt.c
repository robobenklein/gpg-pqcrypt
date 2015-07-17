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
#include "dicho.h"
#include "randomize.h"

extern precomp_t cwdata;

// assumes DIMENSION+CODIMENSION multiple of 8
// assumes x, a, and b are large enough
void vec_concat(unsigned long* x, unsigned long* a, unsigned long* b)
{
  int i, j, k, l;

  if (DIMENSION % 8 == 0) { // and CODIMENSION % 8 == 0
    memcpy(x, a, BITS_TO_BYTES(DIMENSION));
    memcpy(((unsigned char *) x) + BITS_TO_BYTES(DIMENSION), b, BITS_TO_BYTES(CODIMENSION));
  }
  else {
    i = DIMENSION - BIT_SIZE_OF_LONG * (DIMENSION / BIT_SIZE_OF_LONG);
    j = BIT_SIZE_OF_LONG - i;
    l = DIMENSION / BIT_SIZE_OF_LONG;
    memcpy(x, a, sizeof (long) * (DIMENSION / BIT_SIZE_OF_LONG));
    x[l] = a[l] & ((1 << i) - 1); // masking

    for (k = 0; k < CODIMENSION / BIT_SIZE_OF_LONG; ++k) {
      x[l] ^= b[k] << i;
      ++l;
      x[l] = b[k] >> j;
    }
    x[l] ^= b[k] << i;
  }
}

void addto(unsigned long * a, unsigned long * b) {
  int i;

  for (i = 0; i < BITS_TO_LONG(CODIMENSION); ++i)
    a[i] ^= b[i];
}

int encrypt_block(unsigned char *ciphertext, unsigned char *cleartext, const unsigned char * pk)
{
  int i, j;
  unsigned long cR[BITS_TO_LONG(CODIMENSION)], *pt;
  int e[ERROR_WEIGHT];
  unsigned char c, d;

  pt = (unsigned long *) pk;
  memset(cR, 0, BITS_TO_LONG(CODIMENSION) * sizeof(long));
  for (i = 0; i < DIMENSION / 8; ++i) {
    for (j = 0; j < 8; ++j) {
      if (cleartext[i] & (1 << j))
	addto(cR, pt);
      pt += BITS_TO_LONG(CODIMENSION);
    }
  }
  for (j = 0; j < DIMENSION % 8 ; ++j) {
    if (cleartext[i] & (1 << j))
      addto(cR, pt);
    pt += BITS_TO_LONG(CODIMENSION);
  }

  // generate a constant weight word into e from cleartext, starting
  // at position DIMENSION and using ERROR_SIZE bits
  i = dicho_b2cw(cleartext, e,
		 DIMENSION, ERROR_SIZE,
		 LOG_LENGTH, ERROR_WEIGHT, cwdata);
  // returns the number of bits used (i < 0 if less than ERROR_SIZE
  // bits are used, this should not happen)

  if (i < 0)
    return -1;

  // TODO: check the endian problem with the cast
  vec_concat((unsigned long *) ciphertext, (unsigned long *) cleartext, cR);

  // flip t error positions
  for (i = 0; i < NB_ERRORS; i++) {
    ciphertext[e[i] / 8] ^= (1 << (e[i] % 8)); // As 8 is the length of unsigned char.
  }

  return 1;
}

// The suffix _ss is for "semantically secure", the message is
// randomized into the cleartext which will de encrypted
int encrypt_block_ss(unsigned char *ciphertext, unsigned char *message, const unsigned char * pk)
{
  unsigned char cleartext[CLEARTEXT_LENGTH];

  randomize(cleartext, message);
  return encrypt_block(ciphertext, cleartext, pk);
}
