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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sizes.h"
#include "mceliece.h"

__inline unsigned long long rdtsc()
{
  unsigned long long x;
  __asm__ volatile (".byte 0x0f, 0x31" :"=A" (x));
  return x;
}

int main(int argc, char ** argv) {
  int m, t;
  unsigned char pk[PUBLICKEY_BYTES];
  unsigned char message[MESSAGE_BYTES], ciphertext[CIPHERTEXT_BYTES];
  int n;
  int size_n, data_bytes;
  FILE * fichier, * output;
  struct stat buf;

  if (argc <= 3) {
    printf("syntax: %s public_key_file cleartext_file output_file\n", argv[0]);
    exit(0);
  }

  fichier = fopen(argv[1], "r");
  fread(&m, sizeof(int), 1, fichier);
  fread(&t, sizeof(int), 1, fichier);
  if ((m != EXT_DEGREE) || (t != NB_ERRORS)) {
    fprintf(stderr, "invalid public key file (m,t)=(%d,%d) instead of (%d,%d)\n", m, t, EXT_DEGREE, NB_ERRORS);
    exit(0);
  }
  fread(pk, 1, PUBLICKEY_BYTES, fichier);
  fclose(fichier);

  fichier = fopen(argv[2], "r");
  output = fopen(argv[3], "w");

  stat(argv[2], &buf);
  n = buf.st_size;
  size_n = sizeof (n);

  memcpy(message, &n, size_n);
  fread(message + size_n, 1, MESSAGE_BYTES - size_n, fichier);

  n -= MESSAGE_BYTES - size_n;

  while (n > 0) {
    encrypt_block_ss(ciphertext, message, pk);
    fwrite(ciphertext, 1, CIPHERTEXT_BYTES, output);
    fread(message, 1, MESSAGE_BYTES, fichier);
    n -= MESSAGE_BYTES;
  }

  encrypt_block_ss(ciphertext, message, pk);
  fwrite(ciphertext, 1, CIPHERTEXT_BYTES, output);

  fclose(fichier);
  fclose(output);

  return 0;
}
