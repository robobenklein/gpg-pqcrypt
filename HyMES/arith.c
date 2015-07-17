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
#include <stdio.h>
#include "arith.h"

int l2(unsigned long x) {
  static char table[256] = {
    0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
  };

#if __WORDSIZE == 64
  if (x >> 32)
    if (x >> 48)
      if (x >> 56)
	return table[x >> 56] + 56;
      else
	return table[x >> 48] + 48;
    else if (x >> 40)
      return table[x >> 40] + 40;
    else
      return table[x >> 32] + 32;
  else
#endif
    if (x >> 16)
      if (x >> 24)
	return table[x >> 24] + 24;
      else
	return table[x >> 16] + 16;
    else if (x >> 8)
      return table[x >> 8] + 8;
    else
      return table[x];
}

arith_t arith_init(struct buff * b) {
  arith_t state;

  state = (arith_t) malloc(sizeof (struct code_arith));

  state->min = 0;
  state->max = (1UL << PREC_INTER);
  state->compteur = 0;
  state->buffer = b;

  return state;
}

int ajuster(arith_t state, int coder) {
  int i, j;
  unsigned long x;

  // the current state is the interval [min,max[ = [min,max-1]
  // this is a subinterval of [0,2^PREC_INTER[
  // all the integers have PREC_INTER significant bits
  // the number of leading bits common to all the elements of the
  // interval is i (computed below)
  x = (state->max - 1) ^ state->min;
  i = PREC_INTER - l2(x);

  // we compute j such that
  // 2^(PREC_INTER - j - 1) <= (max-1)-min < 2^(PREC_INTER - j)
  // note that j >= i
  x = (state->max - 1) - state->min;
  j = PREC_INTER - l2(x) - 1; // watch out the minus 1

  // We want to multiply the range of the interval by 2 as many times
  // as possible. We can do that at most j times in general (could be
  // j+1 but it would be difficult to figure out and unnecessary in
  // practice)

  // if j is greater than i (the number of common leading bits) we can
  // write i bits in the buffer but we need to keep (j-i) in a counter
  // for future use (we use here the counter of the previous interval
  // adjustement)

  if (i > j) // i <= j+1
    i = j; // we don't write more bits than we remove
  if (i > 0) {
    if (coder) {
      x = state->min >> (PREC_INTER - 1);
      state->min &= ~(1UL << (PREC_INTER - 1));
      bwrite_bit(x, state->buffer);
      bwrite_bits(1 - x, state->compteur, state->buffer);
      bwrite(state->min >> (PREC_INTER - i), i - 1, state->buffer);
    }
    state->compteur = 0;
  }
  state->max = (state->max << j) & ((1UL << PREC_INTER) - 1);
  if (state->max == 0)
    state->max = 1UL << PREC_INTER;
  state->min = (state->min << j) & ((1UL << PREC_INTER) - 1);
  if (j - i > 0) {
    state->max ^= (1UL << (PREC_INTER - 1));
    state->min ^= (1UL << (PREC_INTER - 1));
    state->compteur += j - i;
  }

  return j;
}

// codage d'un élément i dans l'intervalle [d.min, d.max]. Les probabilités
// sont distrib_get_proba(d,d.min),...,distrib_get_proba(d,d.max)
int coder(int i, distrib_t d, arith_t state) {
  unsigned long x;
  unsigned long delta;
  int l;

#ifdef DEBUG
  printf("%u\t%u\t%u\n", state->min, state->max, i);
#endif

  delta = state->max - state->min;

  // pour être synchronisé avec decoder()
  bwrite_lock(PREC_INTER + state->compteur, state->buffer);

  if (i < d.max) {
    x = distrib_get_proba(d, i + 1);
    x *= delta;
    x >>= PREC_PROBA;
    state->max = state->min + x;
  }
  x = distrib_get_proba(d, i);
  x *= delta;
  x >>= PREC_PROBA;
  state->min += x;

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  l = ajuster(state, 1);

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  return l;
}

// loi uniforme 0 <= i < n
int coder_uniforme(unsigned long i, unsigned long n, arith_t state) {
  unsigned long x;
  unsigned long delta;
  int l;

#ifdef DEBUG
  printf("%u\t%u\t%u\t*%u\n", state->min, state->max, i, n);
#endif

  delta = state->max - state->min;

  // pour être synchronisé avec decoder_uniforme()
  bwrite_lock(PREC_INTER + state->compteur, state->buffer);

  x = i;
  x *= delta;
  // normalement pas de risque de dépassement avec x + delta <= n * delta
  state->max = state->min + ((x + delta) / n);
  state->min += x / n;

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  l = ajuster(state, 1);

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  return l;
}

int chercher(unsigned long valeur, unsigned long * sprob, int a, int b) {
  if (b - a == 1)
    return a;
  else {
    int m = (a + b) / 2;
    if (sprob[m] > valeur)
      return chercher(valeur, sprob, a, m);
    else
      return chercher(valeur, sprob, m, b);
  }
}

// décodage d'un élément dans l'intervalle [d.min,d.max]. Les
// probabilités sont distrib_get_proba(d,d.min),...,distrib_get_proba(d,d.max)
int decoder(distrib_t d, int * lettre, arith_t state) {
  unsigned long x;
  unsigned long delta, valeur;
  int i, r;

  delta = state->max - state->min;

  if (state->compteur)
    valeur = blook(PREC_INTER, state->buffer) ^ (1UL << (PREC_INTER - 1));
  else
    valeur = blook(PREC_INTER, state->buffer);

  bread_lock(PREC_INTER, state->buffer);

  x = valeur - state->min;
  x <<= PREC_PROBA;
  x /= delta;
  // appel dependant de la structure distrib_t (a changer ?)
  i = d.min + chercher(x, d.prob, 0, d.max - d.min + 1);

#ifdef DEBUG
  printf("%u\t%u\t", state->min, state->max);
#endif

  if (i < d.max) {
    x = distrib_get_proba(d, i + 1);
    x *= delta;
    x >>= PREC_PROBA;
    x += state->min;
    if (valeur >= x) { // il faut augmenter i
      ++i;
      if (i < d.max) {
	x = distrib_get_proba(d, i + 1);
	x *= delta;
	x >>= PREC_PROBA;
	state->max = state->min + x;
      }
    }
    else
      state->max = x;
  }
  x = distrib_get_proba(d, i);
  x *= delta;
  x >>= PREC_PROBA;
  state->min += x;

#ifdef DEBUG
  printf("%u\t%u\n", i, valeur);
#endif

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  r = ajuster(state, 0);
  bstep(r, state->buffer);

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  *lettre = i;
  return r;
}

// loi uniforme 0 <= i < n
unsigned long decoder_uniforme(unsigned long n, unsigned long * lettre, arith_t state) {
  unsigned long x;
  unsigned long delta, valeur;
  int i, r;

  delta = state->max - state->min;

  if (state->compteur)
    valeur = blook(PREC_INTER, state->buffer) ^ (1UL << (PREC_INTER - 1));
  else
    valeur = blook(PREC_INTER, state->buffer);

  bread_lock(PREC_INTER, state->buffer);

  x = valeur - state->min;
  x *= n;
  x /= delta;
  i = x;

#ifdef DEBUG
  printf("%u\t%u\t", state->min, state->max);
#endif

  x = i;
  x *= delta;
  state->max = state->min + ((x + delta) / n);
  // test obligatoire car max arrondi inférieurement
  if (valeur >= state->max) { // il faut augmenter i
    ++i;
    x += delta;
    state->max = state->min + ((x + delta) / n);
  }
  state->min += x / n;

#ifdef DEBUG
  printf("%u\t*%u\n", i, n);
#endif

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  r = ajuster(state, 0);
  bstep(r, state->buffer);

#ifdef DEBUG
  printf("%u\t%u\n", state->min, state->max);
#endif

  *lettre = i;
  return r;
}
