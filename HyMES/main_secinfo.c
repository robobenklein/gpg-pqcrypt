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
#include "workfactor.h"

int main(int argc, char ** argv) {
  int n, k, t, m, tmin, tmax;

  m = atoi(argv[1]);
  n = 1 << m;
  t = (argc > 2) ? atoi(argv[2]) : 0;
  if (t != 0)
    tmin = tmax = t;
  else {
    tmin = 2;
    tmax = n / m;
  }

  for (t = tmin; t <= tmax; ++t) {
    k = n - t * m;

    printf("%d\t%d\t%g\n", m, t, workfactor(n, k, t));
  }

  return 1;
}
