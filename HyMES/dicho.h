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
#include "precomp.h"

int dicho_b2cw(unsigned char * input_message, int * cw, int start, int len, int m, int t, precomp_t p);
int dicho_cw2b(int * cw, unsigned char * output_message, int start, int len, int m, int t, precomp_t p);
