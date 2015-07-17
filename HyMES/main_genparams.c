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
#include <math.h>
#include "precomp.h"
#include "workfactor.h"

int main(int argc, char ** argv) {
  int m, t, r, len, i;
  FILE * fichier;
  precomp_t p, q;
  double * res, * res2, wf;

  m = t = 0;
  if (argc > 2) {
    m = atoi(argv[1]);
    t = atoi(argv[2]);
  }

  if ((m <= 0) || (t <= 0)) {
    fprintf(stderr, "Usage: %s m t [reduc [len]]\n", argv[0]);
    fprintf(stderr, "all arguments are positive integers, with m > 5, and 0 < t < 2^m/m\n");
    fprintf(stderr, "Look at the documentation for more information on the arguments\n");
    exit(0);
  }

  if (m * t > (1 << m)) {
    fprintf(stderr, "Wrong parameters for Goppa codes!\nThe error weight is %d and should not exceed %d in length %d\n", t, (1 << m) / m, 1 << m);
    exit(0);
  }

  if (argc > 3) {
    r = atoi(argv[3]);
    if (r > m - log2(t)) {
      fprintf(stderr, "Reduction of %d is to high, maximal reduction for (m,t)=(%d,%d) is %d\n", r, m, t, (int) (m - log2(t)));
      exit(0);
    }
    p = precomp_build(m, t, r);
    res = dicho_self_info_bounds(p);
    if (argc > 4) {
      len = atoi(argv[4]);
      if (len > res[1]) {
	fprintf(stderr, "Encoding %d bits in words of length %d and weight %d is impossible!\n", len, 1 << m, t);
	exit(0);
      }
      if (len > res[0]) {
	printf("Warning: constant weight length %d might be too high\n\t lower and upper bounds are %g and %g\n", len, res[0], res[1]);
      }
    }
    else {
      len = floor(res[0]);
    }
  }
  else {
    p = precomp_build(m, t, 0);
    res = dicho_self_info_bounds(p);
    len = floor(res[0]);
    i = ((1 << m) - t * m + len) % 8;
    // heuristic: a small loss of length for constant weight word
    // generation doesn't cost much (LENGTH_LOSS bits of security) and
    // improves (time and memory) the constant weight word generation
#define LENGTH_LOSS 1
    if (i <= LENGTH_LOSS)
      len -= i;
    else
      len -= LENGTH_LOSS;
    for (r = 1; r < m - log2(t); ++r) {
      q = precomp_build(m, t, r);
      res2 = dicho_self_info_bounds(q);
      if (len > floor(res2[0]))
	break;
      clear_precomp(p);
      free(res);
      p = q;
      res = res2;
    }
    if (r < m - log2(t)) {
      clear_precomp(q);
      free(res2);
    }
    --r;
    len = floor(res[0]);
  }
  printf("Security loss is %g\n", log_binomial_d(1 << m, t) - len);
  wf = workfactor(1 << m, (1 << m) - m * t, t);
  printf("Final security: %g bits\n", wf - log_binomial_d(1 << m, t) + len);


  fichier = fopen("params.h", "w");

  fprintf(fichier, "#define LOG_LENGTH %d\n", m);
  fprintf(fichier, "#define ERROR_WEIGHT %d\n\n", t);

  fprintf(fichier, "#define REDUC %d\n", r);
  fprintf(fichier, "#define ERROR_SIZE %d\n", len);
  fprintf(fichier, "// rounded down from %g\n", res[0]);
  fprintf(fichier, "// log_2(binomial(2^%d,%d)) = %g\n", m, t, log_binomial_d(1 << m, t));
  fprintf(fichier, "// log_2(binomial(2^%d,%d)) + %d * %d = %g\n", m - r, t, r, t, r * t + log_binomial_d(1 << (m - r), t));
  fprintf(fichier, "// security loss is %g\n", log_binomial_d(1 << m, t) - len);
  fprintf(fichier, "// final security is %g\n", wf - log_binomial_d(1 << m, t) + len);

  fclose(fichier);

  fichier = fopen("cwdata.c", "w");
  write_precomp(p, fichier);
  fclose(fichier);

  return 0;
}
