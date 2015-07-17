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
#include "params.h"
#include "precomp.h"

__inline unsigned long long rdtsc()
{
  unsigned long long x;
  __asm__ volatile (".byte 0x0f, 0x31" :"=A" (x));
  return x;
}

int check(unsigned char * cleartext, unsigned char * plaintext, int r) {
  int i, j;

  for (i = 0; CLEARTEXT_LENGTH - 8 * i >= 8 ; ++i)
    if (cleartext[i] != plaintext[i]) {
      fprintf(stderr, "encrypted/decrypted data mismatch at byte %d\n", i);
      fprintf(stderr, "message seed is %d\n", r);
      for (j = i; j < CLEARTEXT_BYTES; ++j)
	fprintf(stderr, "%02x", cleartext[j]);
      fprintf(stderr, "\n");
      for (j = i; j < CLEARTEXT_BYTES; ++j)
	fprintf(stderr, "%02x", plaintext[j]);
      fprintf(stderr, "\n");
      return -1;
    }
  j = CLEARTEXT_LENGTH - 8 * i;
  if (j > 0) {
    if ((cleartext[i] ^ plaintext[i]) & ((1 << j) - 1)) {
      fprintf(stderr, "encrypted/decrypted data mismatch at byte %d\n", i);
      fprintf(stderr, "message seed is %d\n", r);
      fprintf(stderr, "%02x\n", cleartext[j] & ((1 << j) - 1));
      fprintf(stderr, "%02x\n", plaintext[j] & ((1 << j) - 1));
      return -1;
    }
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char sk[SECRETKEY_BYTES], pk[PUBLICKEY_BYTES];
  unsigned char cleartext[CLEARTEXT_BYTES], plaintext[CLEARTEXT_BYTES], ciphertext[CIPHERTEXT_BYTES];
  unsigned r, r1;
  int i, j, n;
  unsigned long long tmp_enc, tmp_dec, total_enc, total_dec;

  FILE *fichier;

  n = (argc > 1) ? atoi(argv[1]) : 1;
  r1 = (argc > 2) ? atoi(argv[2]) : ((unsigned) rdtsc());
  r1 &= 0x7fffffff;
  r = (argc > 3) ? atoi(argv[3]) : ((unsigned) rdtsc());
  r &= 0x7fffffff;
  printf("seed for key: %d\n", r1);
  printf("seed for message: %d\n", r);

  srandom(r1);
  keypair(sk, pk);
  total_enc = total_dec = 0;

  for (j = 0; j < n; ++j) {
    srandom(r + j);
    for (i = 0; i < CLEARTEXT_BYTES; ++i)
      cleartext[i] = random() & 0xff;
    tmp_enc = rdtsc();
    if (encrypt_block(ciphertext, cleartext, pk) < 0) {
      fprintf(stderr, "fail to encrypt in attempt %d of %d\n", j + 1, n);
      exit(0);
    }
    tmp_enc = rdtsc() - tmp_enc;
    total_enc += tmp_enc;
    tmp_dec = rdtsc();
    if (decrypt_block(plaintext, ciphertext, sk) < 0) {
      fprintf(stderr, "fail to decrypt in attempt %d of %d\n", j + 1, n);
      exit(0);
    }
    tmp_dec = rdtsc() - tmp_dec;
    total_dec += tmp_dec;
    if (check(cleartext, plaintext, r + j) < 0)
      exit(0);
  }

  fichier = fopen("plotdata", "a");
  printf("running time is printed in file plotdata\n");
  //  fprintf(fichier, "%d\t %d\t %d\t %d\t %lld\t %lld\n", LOG_LENGTH, ERROR_WEIGHT, LENGTH, CLEARTEXT_LENGTH, total_enc / n, total_dec / n);
  fprintf(fichier, "%d\t %d\t %lld\t %lld\n", LOG_LENGTH, ERROR_WEIGHT, 8 * total_enc / n / CLEARTEXT_LENGTH, 8 * total_dec / n / CLEARTEXT_LENGTH);
  fclose(fichier);

  return 0;
}







