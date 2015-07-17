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
#include "sizes.h"
#include "mceliece.h"

__inline unsigned long long rdtsc()
{
  unsigned long long x;
  __asm__ volatile (".byte 0x0f, 0x31" :"=A" (x));
  return x;
}

int main(int argc, char ** argv) {
  unsigned char sk[SECRETKEY_BYTES], pk[PUBLICKEY_BYTES];
  FILE * fichier;
  char filename[16];
  unsigned r;
  int n;
  unsigned long long tmp, total;

  r = (argc > 1) ? atoi(argv[1]) : (((unsigned) rdtsc()) & 0x7fffffff);

  n = (argc > 2) ? atoi(argv[2]) : 0;
  if (n == 0) {
    srandom(r);
    keypair(sk, pk);

    sprintf(filename, "pk%d", r);
    fichier = fopen(filename, "w");
    n = EXT_DEGREE;
    fwrite(&n, sizeof(int), 1, fichier);
    n = NB_ERRORS;
    fwrite(&n, sizeof(int), 1, fichier);
    fwrite(pk, 1, PUBLICKEY_BYTES, fichier);
    fclose(fichier);
    sprintf(filename, "sk%d", r);
    fichier = fopen(filename, "w");
    n = EXT_DEGREE;
    fwrite(&n, sizeof(int), 1, fichier);
    n = NB_ERRORS;
    fwrite(&n, sizeof(int), 1, fichier);
    fwrite(sk, 1, SECRETKEY_BYTES, fichier);
    fclose(fichier);
  }
  else {
    total = 0;
    while (n > 0) {
      srandom(r);
      tmp = rdtsc();
      keypair(sk, pk);
      tmp = rdtsc() - tmp;
      total += tmp;
      --n;
      ++r;
    }
    fichier = fopen("plotkgendata", "a");
    fprintf(fichier, "%d\t %d\t %lld\n", LOG_LENGTH, ERROR_WEIGHT, total / atoi(argv[2]));
  }
  return 0;
}







