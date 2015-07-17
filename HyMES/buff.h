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
#ifndef BUFF_H
#define BUFF_H

struct buff {
  int size;
  unsigned long val;
  unsigned char masque_dernier;
  unsigned char * message;
  int fin, dernier, courant, lock;
};

#define BUFFSIZE (8 * sizeof (unsigned long))

typedef struct buff * bread_t;
typedef struct buff * bwrite_t;

bread_t breadinit(unsigned char * message, int fin);
bwrite_t bwriteinit(unsigned char * message, int fin);
void breadclose(bread_t bin);
void bwriteclose(bwrite_t bout);

void bread_retour(bread_t bin);
int bread_available(bread_t bin);
int bwrite_available(bwrite_t bout);
int bread_unlocked(bread_t bin);
int bwrite_unlocked(bwrite_t bout);
void bread_changer_position(bread_t bin, int i);
void bread_decaler_fin(bread_t bin, int i);
void bwrite_changer_position(bwrite_t bout, int i);
void bwrite_decaler_fin(bwrite_t bout, int i);

void bread_lock(int i, bread_t bin);
void bwrite_lock(int i, bwrite_t bout);

unsigned bread(int i, bread_t bin);
unsigned blook(int i, bread_t bin);
void bstep(int i, bread_t bin);
int bread_bit(bread_t bin);
void bwrite(unsigned int x, int i, bwrite_t bout);
void bwrite_bit(unsigned int x, bwrite_t bout);
void bwrite_bits(unsigned int x, int n, bwrite_t bout);

#endif // BUFF_H
