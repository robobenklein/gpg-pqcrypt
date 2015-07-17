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
#include <math.h>

double binomial(int n, int k) {
  int i;
  double x = 1;

  for (i = 0; i < k; ++i) {
    x *= n - i;
    x /= k -i;
  }

  return x;
}

double log_binomial(int n, int k) {
  int i;
  double x = 0;

  for (i = 0; i < k; ++i) {
    x += log(n - i);
    x -= log(k - i);
  }

  return x / log(2);
}

double nb_iter(int n, int k, int w, int p, int l) {
  double x;

  x = 2 * log_binomial(k / 2, p);
  x += log_binomial(n - k - l, w - 2 * p);
  x = log_binomial(n, w) - x;

  return x;
}

double cout_iter(int n, int k, int p, int l) {
  double res, x;
  int i;

   // x <- binomial(k/2,p)
   x = binomial(k / 2, p);
   // i <- log[2](binomial(k/2,p))
   i = (int) (log(x) / log(2)); // normalement i < 2^31
   // res <- 2*p*(n-k-l)*binomial(k/2,p)^2/2^l
   res = 2 * p * (n - k - l) * ldexp(x * x, -l);
   // x <- binomial(k/2,p)*2*(2*l+log[2](binomial(k/2,p)))
   x *= 2 * (2 * l + i);
   // res <- k*(n-k)/2 +
   // binomial(k/2,p)*2*(2*l+log[2](binomial(k/2,p))) +
   // 2*p*(n-k-l)*binomial(k/2,p)^2/2^l
   res += x + k * ((n - k) / 2.0);

   return log(res) / log(2);
}

double memory_compl(int n, int k, int p, int l) {
  double x, res, aux;

   x = binomial(k / 2, p);
   res = log(x) / log(2);
   aux = (res > l) ? res : l;

   return res + log(log(aux) / log(2) + aux) / log(2);
}

double cout_total(int n, int k, int w, int p, int l) {
  double x, y;

  x = nb_iter(n, k, w, p, l);
  y = cout_iter(n, k, p, l);
  return x + y;
}

double best_wf(int n, int k, int w, int p, int *lmin, double *mem) {
  int u, l;
  double lwf, min;

  if (p >= k / 2)
    return -1;

  min = memory_compl(n, k, p, 0);

  u = min + 5; // heuristique

  // On part de l = u, en faisant croitre l.
  // On s'arrète dés que le work factor croit.
  // Puis on explore les valeurs <u, mais en tenant de la convexite'

  min = cout_total(n, k, w, p, u);
  *lmin = u;
  for (l = u + 1; l < n - k; ++l) {
    lwf = cout_total(n, k, w, p, l);
    if (lwf < min) {
      min = lwf;
      *lmin = l;
    }
    else
      break;
  }
  if (l == u + 1) // sinon pas la peine de regarder l < u
    for (l = u - 1; l > 0; --l) {
      lwf = cout_total(n, k, w, p, l);
      if (lwf < min) {
	min = lwf;
	*lmin = l;
      }
      else
	break;
    }

  *mem = memory_compl(n, k, p, 0);
  return min;
}

double workfactor(int n, int k, int t) {
  int p, l, lmin, pmin;
  double min, lwf, mem, memmin;

  pmin = 1;
  min = cout_total(n, k, t, 0, 0); // correspond a p=1
  lmin = 0;
  memmin = 0;
  for (p = pmin; p <= t / 2; ++p) {
    lwf = best_wf(n, k + 1, t, p, &l, &mem);
    if (lwf < 0)
      break;
    if ((min == 0) || (lwf < min)) {
      min = lwf;
      pmin = p;
      lmin = l;
      memmin = mem;
    }
    // heuristique: on arrete si lwf a augmenté 2 fois
    if (p >= pmin + 2)
      break;
  }

  return min;
}
