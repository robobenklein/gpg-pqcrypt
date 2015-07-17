/* t-support.h - Helper for the regression tests
 * Copyright (C) 2007  Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify it
 * under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * GnuPG is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GNUPG_COMMON_T_SUPPORT_H
#define GNUPG_COMMON_T_SUPPORT_H 1

#ifdef GCRYPT_VERSION
#error The regression tests should not include with gcrypt.h
#endif

#ifdef HAVE_W32CE_SYSTEM
#include <gpg-error.h>  /* Defines strerror.  */
#endif


#ifndef HAVE_GETENV
# define getenv(a)  (NULL)
#endif

#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif


/* Replacement prototypes. */
void *gcry_xmalloc (size_t n);
void *gcry_xcalloc (size_t n, size_t m);
void *gcry_xrealloc (void *a, size_t n);
char *gcry_xstrdup (const char * a);
void  gcry_free (void *a);

/* Map the used xmalloc functions to those implemented by t-support.c */
#define xmalloc(a)    gcry_xmalloc ( (a) )
#define xcalloc(a,b)  gcry_xcalloc ( (a), (b) )
#define xrealloc(a,n) gcry_xrealloc ( (a), (n) )
#define xstrdup(a)    gcry_xstrdup ( (a) )
#define xfree(a)      gcry_free ( (a) )


/* Macros to print the result of a test.  */
#define pass()  do { ; } while(0)
#define fail(a)  do { fprintf (stderr, "%s:%d: test %d failed\n",\
                               __FILE__,__LINE__, (a));          \
                     exit (1);                                   \
                   } while(0)


#endif /*GNUPG_COMMON_T_SUPPORT_H*/
