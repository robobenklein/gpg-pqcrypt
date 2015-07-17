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
#ifndef _MATRIX_H
#define _MATRIX_H

#define BITS_PER_LONG (8 * sizeof (unsigned long))

typedef struct matrix{
   int rown;//number of rows.
   int coln;//number of columns.
   int rwdcnt;//number of words in a row
   int alloc_size;//number of allocated bytes
   unsigned long *elem;//row index.
   }*binmat_t;

#define mat_coeff(A, i, j) (((A)->elem[(i) * A->rwdcnt + (j) / BITS_PER_LONG] >> (j % BITS_PER_LONG)) & 1)
//#define mat_row(A, i) ((A)->elem + ((i) * A->rwdcnt))
#define mat_set_coeff_to_one(A, i, j) ((A)->elem[(i) * A->rwdcnt + (j) / BITS_PER_LONG] |= (1UL << ((j) % BITS_PER_LONG)))
#define mat_change_coeff(A, i, j) ((A)->elem[(i) * A->rwdcnt + (j) / BITS_PER_LONG] ^= (1UL << ((j) % BITS_PER_LONG)))
#define mat_set_to_zero(R) memset((R)->elem,0,(R)->alloc_size);


binmat_t mat_ini(int rown, int coln);
binmat_t mat_ini_from_string(int rown, int coln, const unsigned char * s);
void mat_free(binmat_t A);
binmat_t mat_copy(binmat_t A);
binmat_t mat_rowxor(binmat_t A,int a, int b);
int * mat_rref(binmat_t A);
void mat_vec_mul(unsigned long *cR, unsigned char *x, binmat_t A);
binmat_t mat_mul(binmat_t A, binmat_t B);

#endif

