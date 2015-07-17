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
#include "buff.h"

#define LSB_TO_ONE(i) ((i) ? ((1UL << (i)) - 1) : 0)
#define LSB_TO_ZERO(i) (((i) == BUFFSIZE) ? 0 : (((unsigned long) -1) << (i)))

unsigned char bread_getchar(bread_t bin) {
  bin->courant++;
  if (bin->courant < bin->dernier)
    return bin->message[bin->courant];
  if (bin->courant == bin->dernier)
    return bin->message[bin->courant] & bin->masque_dernier;
  return 0;
}

void bwrite_putchar(unsigned char c, bwrite_t bout) {
  bout->courant++;
  if (bout->courant < bout->dernier)
    bout->message[bout->courant] = c;
  if (bout->courant == bout->dernier) {
    bout->message[bout->courant] &= ~ bout->masque_dernier;
    bout->message[bout->courant] ^= c & bout->masque_dernier;
  }
}

bread_t breadinit(unsigned char * message, int fin) {
  bread_t bin;

  bin = malloc (sizeof (struct buff));

  bin->message = message;
  bin->fin = fin;
  // adresse du dernier octet
  bin->dernier = (fin - 1) / 8;
  // masque à appliquer au dernier octet
  bin->masque_dernier = LSB_TO_ZERO((-fin) & 0x7);

  bin->courant = -1;
  bin->val = 0;
  bin->size = 0;
  bin->lock = 0;

  return bin;
}

bwrite_t bwriteinit(unsigned char * message, int fin) {
  bwrite_t bout;

  bout = malloc (sizeof (struct buff));

  bout->message = message;
  bout->fin = fin;
  // adresse du dernier octet
  bout->dernier = (fin - 1) / 8;
  // masque à appliquer au dernier octet
  bout->masque_dernier = LSB_TO_ZERO((-fin) & 0x7);

  bout->courant = -1;
  bout->val = 0;
  bout->size = BUFFSIZE;
  bout->lock = 0;

  return bout;
}

// uniquement sur un buffer vide
void bfill(bread_t bin) {
  int i;

  for (i = 0; i < BUFFSIZE; i += 8) {
    bin->val <<= 8;
    bin->val ^= bread_getchar(bin);
  }
  bin->size = BUFFSIZE;
}

// uniquement sur un buffer plein (sinon bflush_partiel)
void bflush(bwrite_t bout) {
  int i;

  for (i = BUFFSIZE - 8; i >= 0; i -= 8)
    bwrite_putchar(bout->val >> i, bout);
  bout->val = 0;
  bout->size = BUFFSIZE;
}

void bflush_partiel(bwrite_t bout) {
  int i;

  for (i = BUFFSIZE - 8; i >= bout->size; i -= 8)
    bwrite_putchar(bout->val >> i, bout);
  bout->size -= i;
  // 8 >= bout->size > 0
  if (bout->size < 8) { // sinon, bout->size == 8 et on a fini
    // Il reste (8 - bout->size) bits à écrire, mais sans en écraser d'autres
    // On met les bits qui nous intéressent dans le premier octet de bout->val
    bout->val >>= i;
    // On masque les bout->size bits les moins significatifs
    bout->val &= LSB_TO_ZERO(bout->size);

    // Un peu hérétique (un read sur un bwrite_t) mais c'est ce qu'il
    // faut. On récupère (dans les bits les moins significatifs de
    // bout->val) les bout->size bits de l'octet courant (ils doivent
    // rester intacts)
    bout->val ^= bread_getchar(bout) & LSB_TO_ONE(bout->size);
    // on recule car on va réécrire l'octet courant
    bout->courant--;
    bwrite_putchar(bout->val, bout);
  }
  bout->val = 0;
  bout->size = BUFFSIZE;
}

void breadclose(bread_t bin) {
  free(bin);
}

void bwriteclose(bwrite_t bout) {
  bflush_partiel(bout);
  free(bout);
}

void bread_retour(bread_t bin) {
  bin->courant = -1;
  bin->size = 0;
  bin->val = 0;
}

// nombre de bits disponibles (peut etre < 0)
int bread_available(bread_t bin) {
  return bin->fin - 8 * (bin->courant + 1) + bin->size;
}

// nombre de bits disponibles (peut etre < 0)
int bwrite_available(bwrite_t bout) {
  return bout->fin - 8 * (bout->courant + 1) - BUFFSIZE + bout->size;
}

// nombre de bits disponibles après le verrou
int bread_unlocked(bread_t bin) {
  return bin->fin - bin->lock;
}

// nombre de bits disponibles après le verrou
int bwrite_unlocked(bwrite_t bout) {
  return bout->fin - bout->lock;
}

int bread_position(bread_t bin) {
  return 8 * (bin->courant + 1) - bin->size;
}

void bread_changer_position(bread_t bin, int i) {
  // adresse précédant l'octet contenant le i-ième bit
  bin->courant = i / 8 - 1;
  // on place l'octet du i-eme bit dans bin->val
  bin->val = bread_getchar(bin);
  // le nombre de bits "utiles" dans l'octet courant
  bin->size = 8 - (i % 8);
}

// si i < 0, on recule
void bread_decaler_fin(bread_t bin, int i) {
  bin->fin += i;
  bin->dernier = (bin->fin - 1) / 8;
  bin->masque_dernier = LSB_TO_ZERO((-bin->fin) & 0x7);
  bread_changer_position(bin, bread_position(bin));
}

void bwrite_changer_position(bwrite_t bout, int i) {
  // On commence par faire table rase du passé.
  // Si bout->size == BUFFSIZE (après init par ex.) il ne se passera
  // rien avec bflush_partiel(), sinon il faut écrire qq bits en
  // prenant garde de ne rien écraser
  bflush_partiel(bout);
  // adresse précédant l'octet contenant le i-ième bit
  // l'écriture recommencera à partir de l'octet bout->courant + 1
  bout->courant = i / 8 - 1;
  // le nombre de bits restant "à écrire" dans le buffer
  bout->size = BUFFSIZE - (i % 8);
  if (i % 8 == 0)
    bout->val = 0;
  else {
    // on place l'octet du i-eme bit au début de bout->val
    bout->val = ((unsigned long) bout->message[i / 8]) << (BUFFSIZE - 8);
    // On efface les bout->size derniers bits de bout->val
    bout->val &= LSB_TO_ZERO(bout->size);
  }
}

// si i < 0, on recule
void bwrite_decaler_fin(bwrite_t bout, int i) {
  bout->fin += i;
  bout->dernier = (bout->fin - 1) / 8;
  bout->masque_dernier = LSB_TO_ZERO((-bout->fin) & 0x7);
}

// suppose i <= BUFFSIZE
unsigned bread(int i, bread_t bin) {
  unsigned res = 0;

  if (bin->size < i) {
    res = bin->val & LSB_TO_ONE(bin->size);
    i -= bin->size;
    res <<= i;
    bfill(bin);
  }
  bin->size -= i;
  res ^= (bin->val >> bin->size) & LSB_TO_ONE(i);

  return res;
}

void bread_lock(int i, bread_t bin) {
  bin->lock = 8 * (bin->courant + 1) - bin->size + i;
}

void bwrite_lock(int i, bwrite_t bout) {
  bout->lock = 8 * (bout->courant + 1) + BUFFSIZE - bout->size + i;
}

// suppose i <= BUFFSIZE - 8
// comme bread mais on n'avance pas dans le buffer
unsigned blook(int i, bread_t bin) {
  unsigned res = 0;

  while (bin->size < i) {
    bin->val <<= 8;
    bin->val ^= bread_getchar(bin);
    bin->size += 8;
  }
  res ^= (bin->val >> (bin->size - i)) & LSB_TO_ONE(i);

  return res;
}

// suppose i <= BUFFSIZE
void bstep(int i, bread_t bin) {
  if (bin->size < i) {
    i -= bin->size;
    bfill(bin);
  }
  bin->size -= i;
}

int bread_bit(bread_t bin) {
  if (bin->size <= 0)
    bfill(bin);
  bin->size--;
  return (bin->val >> bin->size) & 1;
}

// On suppose i <= BUFFSIZE et x < (1 << i)
void bwrite(unsigned int x, int i, bwrite_t bout) {
  if (bout->size < i) { // pas assez de place
    i -= bout->size;
    bout->val ^= x >> i;
    bflush(bout);
    x &= LSB_TO_ONE(i);
  }
  // i <= bout->size
  bout->size -= i;
  bout->val ^= x << bout->size;
}

// x = 0 ou 1
void bwrite_bit(unsigned int x, bwrite_t bout) {
  if (bout->size <= 0)
    bflush(bout);
  bout->size--;
  bout->val ^= x << bout->size;
}

// x = 0 ou 1
void bwrite_bits(unsigned int x, int n, bwrite_t bout) {
  if (bout->size <= 0)
    bflush(bout);
  x = x ? -1 : 0;
  if (n > bout->size) { // pas assez de place
    bout->val ^= x >> (BUFFSIZE - bout->size);
    n -= bout->size;
    bflush(bout);
    while (n > BUFFSIZE) { // toujours pas assez de place
      bout->val = x;
      n -= BUFFSIZE;
      bflush(bout);
    }
  }
  if (n > 0) {
    bout->size -= n;
    bout->val ^= (x >> (BUFFSIZE - n)) << bout->size;
  }
}
