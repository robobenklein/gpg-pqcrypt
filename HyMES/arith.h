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
#ifndef ARITH_H
#define ARITH_H

#include "buff.h"

#define PREC_TOTAL 32
#define PREC_INTER ((2 * PREC_TOTAL) / 3)
#define PREC_PROBA (PREC_TOTAL - PREC_INTER)

typedef struct {
  unsigned long min, max;
  unsigned long * prob;
} distrib_t;

#define distrib_get_proba(d, i) ((d).prob[(i) - (d).min])

typedef struct code_arith {
  int compteur;
  unsigned long min, max;
  struct buff * buffer;
} * arith_t;

arith_t arith_init(struct buff * b);
int coder(int i, distrib_t d, arith_t state);
int coder_uniforme(unsigned long i, unsigned long n, arith_t state);
int coder_bin_fin(int i, arith_t state);
int decoder(distrib_t d, int * lettre, arith_t state);
unsigned long decoder_uniforme(unsigned long n, unsigned long * lettre, arith_t state);
int decoder_bin_fin(arith_t state);
int tester_fin(arith_t state);
int tester_compteur(arith_t state);

#endif // ARITH_H
