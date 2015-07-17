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
#include <string.h>
#include "sizes.h"
#include "mceliece.h"

int main(int argc, char ** argv) {
  int m, t;
  unsigned char sk[SECRETKEY_BYTES];
  unsigned char message[MESSAGE_BYTES], ciphertext[CIPHERTEXT_BYTES];
  int n;
  int size_n, fail;
  FILE * fichier, * output;

  if (argc <= 3) {
    printf("syntax: %s secret_key_file ciphertext_file output_file\n", argv[0]);
    exit(0);
  }

  fichier = fopen(argv[1], "r");
  fread(&m, sizeof(int), 1, fichier);
  fread(&t, sizeof(int), 1, fichier);
  if ((m != EXT_DEGREE) || (t != NB_ERRORS)) {
    fprintf(stderr, "invalid secret key file (m,t)=(%d,%d) instead of (%d,%d)\n", m, t, EXT_DEGREE, NB_ERRORS);
    exit(0);
  }
  fread(sk, 1, SECRETKEY_BYTES, fichier);
  fclose(fichier);

  fichier = fopen(argv[2], "r");
  fread(ciphertext, 1, CIPHERTEXT_BYTES, fichier);
  if (decrypt_block_ss(message, ciphertext, sk) < 0) {
    fclose(fichier);
    fprintf(stderr, "not a valid encrypted file!\n");
    exit(0);
  }
  else {
    fail = 0;
    output = fopen(argv[3], "w");
    size_n = sizeof (n);
    memcpy(&n, message, size_n);
    fwrite(message + size_n, 1, MESSAGE_BYTES - size_n, output);
    n -= MESSAGE_BYTES - size_n;

    while (n > MESSAGE_BYTES) {
      fread(ciphertext, 1, CIPHERTEXT_BYTES, fichier);
      if (decrypt_block_ss(message, ciphertext, sk) < 0) {
	fail = 1;
	break;
      }
      fwrite(message, 1, MESSAGE_BYTES, output);
      n -= MESSAGE_BYTES;
    }
  }

  if (!fail) {
    fread(ciphertext, 1, CIPHERTEXT_BYTES, fichier);
    if (decrypt_block_ss(message, ciphertext, sk) < 0)
      fail = 1;
    else
      fwrite(message, 1, n, output);
  }

  if (fail)
    fprintf(stderr, "invalid data in the encrypted file!\n");

  fclose(output);
  fclose(fichier);

  return 0;
}
