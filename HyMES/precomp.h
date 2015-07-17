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
#ifndef PERTE_H
#define PERTE_H

#include <stdio.h>
#include "arith.h"

typedef struct {
  int maximum, deadbits;
} leaf_info_t;

typedef struct precomp {
  int m, t, real_m, real_t;
  int * offset;
  distrib_t ** distrib;
  leaf_info_t ** leaf_info;
} precomp_t;

#define precomp_get_distrib(p, m , t) ((p).distrib[m][(t) - (p).offset[m]])

double binomial_d(int a, int b);
double log_binomial_d(int a, int b);
void clear_precomp(precomp_t p);
void write_precomp(precomp_t p, FILE * output_stream);
precomp_t precomp_build(int m, int t, int reduc);
double dicho_searchmin(precomp_t p, double min_value);
double * dicho_self_info_bounds(precomp_t p);

#endif // PERTE_H
