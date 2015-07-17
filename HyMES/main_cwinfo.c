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

int main(int argc, char ** argv) {
  int m, t, r, min, tmin, tmax, n;
  precomp_t p;
  double * res, x, y, max;

  m = atoi(argv[1]);
  if (argc > 2)
    tmin = tmax = atoi(argv[2]);
  else {
    tmin = 1;
    tmax = (1 << m) / m;
  }

  for (t = tmin; t <= tmax; ++t) {
    if (argc > 3) {
      min = max = atoi(argv[3]);
    }
    else {
      min = 0;
      max = m - log2(t);
    }
    x = log_binomial_d(1 << m, t);
    for (r = min; r <= max; ++r) {
      p = precomp_build(m, t, r);
      res = dicho_self_info_bounds(p);
      printf("%d\t%d\t%d\t%d\t%g\t%g\t%g\n", m, t, r, (int) floor(res[0]), res[0], res[1], x);
#ifdef FULL
      if (floor(res[0]) != floor(res[1])) {
	y = dicho_searchmin(p, floor(res[0]) + 1);
	printf("\t\t\t%d\t%g\n", (int) floor(y), y);
      }
#endif
      free(res);
      clear_precomp(p);
    }
  }

  return 0;
}





