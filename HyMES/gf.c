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
#include <stdio.h>
#include <stdlib.h>

#include "gf.h"

#define MAX_EXT_DEG 16//this is our primary consideration....think about changing!?

static unsigned prim_poly[MAX_EXT_DEG + 1] = {
    01,		/* extension degree 0 (!) never used */
    03,		/* extension degree 1 (!) never used */
    07, 		/* extension degree 2 */
    013, 		/* extension degree 3 */
    023, 		/* extension degree 4 */
    045, 		/* extension degree 5 */
    0103, 		/* extension degree 6 */
    0203, 		/* extension degree 7 */
    0435, 		/* extension degree 8 */
    01041, 		/* extension degree 9 */
    02011,		/* extension degree 10 */
    04005,		/* extension degree 11 */
    010123,		/* extension degree 12 */
    020033,		/* extension degree 13 */
    042103,		/* extension degree 14 */
    0100003,		/* extension degree 15 */
    0210013		/* extension degree 16 */

};//we predefine the primitive polynomials here.

/*********************************************************************************************/
////////////////////////////////////GF Functions.//////////////////////////////////////////////
/*********************************************************************************************/

// construct the table gf_exp[i]=alpha^i
void gf_init_exp() {
  int i;

  gf_exp = (gf_t *) malloc((1 << gf_extd()) * sizeof (gf_t));

  gf_exp[0] = 1;
  for (i = 1; i < gf_ord(); ++i) {
    gf_exp[i] = gf_exp[i - 1] << 1;
    if (gf_exp[i - 1] & (1 << (gf_extd()-1)))
      gf_exp[i] ^= prim_poly[gf_extd()];
  }
  // hack for the multiplication
  gf_exp[gf_ord()] = 1;
}

// construct the table gf_log[alpha^i]=i
void gf_init_log()
{
  int i;

  gf_log = (gf_t *) malloc((1 << gf_extd()) * sizeof (gf_t));

  gf_log[0] = gf_ord();//(1 << 16) - 1; // log of 0 par convention
  for (i = 0; i < gf_ord() ; ++i)
    gf_log[gf_exp[i]] = i;
}

int init_done = 0;

int gf_init(int extdeg)
{
  if (extdeg > MAX_EXT_DEG) {
    fprintf(stderr,"Extension degree %d not implemented !\n", extdeg);
    exit(0);
  }
  if (init_done != extdeg) {
    if (init_done) {
      free(gf_exp);
      free(gf_log);
    }
    init_done = gf_extension_degree = extdeg;
    gf_cardinality = 1 << extdeg;
    gf_multiplicative_order = gf_cardinality - 1;
    gf_init_exp();
    gf_init_log();
  }

  return 1;
}

// we suppose i >= 0. Par convention 0^0 = 1
gf_t gf_pow(gf_t x, int i) {
  if (i == 0)
    return 1;
  else if (x == 0)
    return 0;
  else {
    // i mod (q-1)
    while (i >> gf_extd())
      i = (i & (gf_ord())) + (i >> gf_extd());
    i *= gf_log[x];
    while (i >> gf_extd())
      i = (i & (gf_ord())) + (i >> gf_extd());
    return gf_exp[i];
  }
}

// u8rnd is a function returning a random byte
gf_t gf_rand(int (*u8rnd)()) {
  return (u8rnd() ^ (u8rnd() << 8)) & gf_ord();
}
