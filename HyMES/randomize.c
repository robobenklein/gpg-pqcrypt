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
#include <string.h>
#include "sizes.h"

/* This function is aimed at randomizing the cleartext to provide
   semantic security. Here, it is a fake and we just make a copy.

   In a real conversion the message is first padded with random bytes
   and zeroes then shuffled, for instance with a 3 round
   "Fiestel-like" scheme. The message of size MESSAGE_BYTES bytes is
   transformed into a randomized block of size CLEARTEXT_LENGTH
   bits. */
void randomize(unsigned char * cleartext, unsigned char * message)
{
  memcpy(cleartext, message, MESSAGE_BYTES);
}

/* The inverse of randomize. */
int unrandomize(unsigned char * message, unsigned char * cleartext)
{
  memcpy(message, cleartext, MESSAGE_BYTES);

  return 1; //Shall put a test in case the function fails.
}
