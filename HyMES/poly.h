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
#ifndef POLY_H
#define POLY_H

#include "gf.h"

typedef struct polynome {
  int deg, size;
  gf_t * coeff;
} * poly_t; /* polynomial has coefficients in the finite field */

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define poly_deg(p) ((p)->deg)
#define poly_size(p) ((p)->size)
#define poly_set_deg(p, d) ((p)->deg = (d))
#define poly_coeff(p, i) ((p)->coeff[i])
#define poly_set_coeff(p, i, a) ((p)->coeff[i] = (a))
#define poly_addto_coeff(p, i, a) ((p)->coeff[i] = gf_add((p)->coeff[i], (a)))
#define poly_multo_coeff(p, i, a) ((p)->coeff[i] = gf_mul((p)->coeff[i], (a)))
#define poly_tete(p) ((p)->coeff[(p)->deg])

/****** poly.c ******/

int poly_calcule_deg(poly_t p);
poly_t poly_alloc(int d);
poly_t poly_alloc_from_string(int d, const unsigned char * s);
poly_t poly_copy(poly_t p);
void poly_free(poly_t p);
void poly_set_to_zero(poly_t p);
void poly_set(poly_t p, poly_t q);
poly_t poly_mul(poly_t p, poly_t q);
void poly_rem(poly_t p, poly_t g);
void poly_sqmod_init(poly_t g, poly_t * sq);
void poly_sqmod(poly_t res, poly_t p, poly_t * sq, int d);
poly_t poly_gcd(poly_t p1, poly_t p2);
poly_t poly_quo(poly_t p, poly_t d);
gf_t poly_eval(poly_t p, gf_t a);
int poly_degppf(poly_t g);
void poly_eeaux(poly_t * u, poly_t * v, poly_t p, poly_t g, int t);

poly_t * poly_syndrome_init(poly_t generator, gf_t *support, int n);
poly_t * poly_sqrtmod_init(poly_t g);
poly_t poly_randgen_irred(int t, int (*u8rnd)());
#endif /* POLY_H */
