/* ks-engine-hkp.c - HKP keyserver engine
 * Copyright (C) 2011, 2012 Free Software Foundation, Inc.
 * Copyright (C) 2011, 2012, 2014 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else /*!HAVE_W32_SYSTEM*/
# include <sys/types.h>
# include <sys/socket.h>
# include <netdb.h>
#endif /*!HAVE_W32_SYSTEM*/

#include "dirmngr.h"
#include "misc.h"
#include "userids.h"
#include "ks-engine.h"

/* Substitutes for missing Mingw macro.  The EAI_SYSTEM mechanism
   seems not to be available (probably because there is only one set
   of error codes anyway).  For now we use WSAEINVAL. */
#ifndef EAI_OVERFLOW
# define EAI_OVERFLOW EAI_FAIL
#endif
#ifdef HAVE_W32_SYSTEM
# ifndef EAI_SYSTEM
#  define EAI_SYSTEM WSAEINVAL
# endif
#endif


/* Number of seconds after a host is marked as resurrected.  */
#define RESURRECT_INTERVAL  (3600*3)  /* 3 hours */

/* To match the behaviour of our old gpgkeys helper code we escape
   more characters than actually needed. */
#define EXTRA_ESCAPE_CHARS "@!\"#$%&'()*+,-./:;<=>?[\\]^_{|}~"

/* How many redirections do we allow.  */
#define MAX_REDIRECTS 2

/* Number of retries done for a dead host etc.  */
#define SEND_REQUEST_RETRIES 3

/* Objects used to maintain information about hosts.  */
struct hostinfo_s;
typedef struct hostinfo_s *hostinfo_t;
struct hostinfo_s
{
  time_t lastfail;   /* Time we tried to connect and failed.  */
  time_t lastused;   /* Time of last use.  */
  int *pool;         /* A -1 terminated array with indices into
                        HOSTTABLE or NULL if NAME is not a pool
                        name.  */
  int poolidx;       /* Index into POOL with the used host.  -1 if not set.  */
  unsigned int v4:1; /* Host supports AF_INET.  */
  unsigned int v6:1; /* Host supports AF_INET6.  */
  unsigned int dead:1; /* Host is currently unresponsive.  */
  time_t died_at;    /* The time the host was marked dead.  If this is
                        0 the host has been manually marked dead.  */
  char *cname;       /* Canonical name of the host.  Only set if this
                        is a pool.  */
  char *v4addr;      /* A string with the v4 IP address of the host.
                        NULL if NAME has a numeric IP address or no v4
                        address is available.  */
  char *v6addr;      /* A string with the v6 IP address of the host.
                        NULL if NAME has a numeric IP address or no v4
                        address is available.  */
  char name[1];      /* The hostname.  */
};


/* An array of hostinfo_t for all hosts requested by the caller or
   resolved from a pool name and its allocated size.*/
static hostinfo_t *hosttable;
static int hosttable_size;

/* The number of host slots we initally allocate for HOSTTABLE.  */
#define INITIAL_HOSTTABLE_SIZE 10


/* Create a new hostinfo object, fill in NAME and put it into
   HOSTTABLE.  Return the index into hosttable on success or -1 on
   error. */
static int
create_new_hostinfo (const char *name)
{
  hostinfo_t hi, *newtable;
  int newsize;
  int idx, rc;

  hi = xtrymalloc (sizeof *hi + strlen (name));
  if (!hi)
    return -1;
  strcpy (hi->name, name);
  hi->pool = NULL;
  hi->poolidx = -1;
  hi->lastused = (time_t)(-1);
  hi->lastfail = (time_t)(-1);
  hi->v4 = 0;
  hi->v6 = 0;
  hi->dead = 0;
  hi->died_at = 0;
  hi->cname = NULL;
  hi->v4addr = NULL;
  hi->v6addr = NULL;

  /* Add it to the hosttable. */
  for (idx=0; idx < hosttable_size; idx++)
    if (!hosttable[idx])
      {
        hosttable[idx] = hi;
        return idx;
      }
  /* Need to extend the hosttable.  */
  newsize = hosttable_size + INITIAL_HOSTTABLE_SIZE;
  newtable = xtryrealloc (hosttable, newsize * sizeof *hosttable);
  if (!newtable)
    {
      xfree (hi);
      return -1;
    }
  hosttable = newtable;
  idx = hosttable_size;
  hosttable_size = newsize;
  rc = idx;
  hosttable[idx++] = hi;
  while (idx < hosttable_size)
    hosttable[idx++] = NULL;

  return rc;
}


/* Find the host NAME in our table.  Return the index into the
   hosttable or -1 if not found.  */
static int
find_hostinfo (const char *name)
{
  int idx;

  for (idx=0; idx < hosttable_size; idx++)
    if (hosttable[idx] && !ascii_strcasecmp (hosttable[idx]->name, name))
      return idx;
  return -1;
}


static int
sort_hostpool (const void *xa, const void *xb)
{
  int a = *(int *)xa;
  int b = *(int *)xb;

  assert (a >= 0 && a < hosttable_size);
  assert (b >= 0 && b < hosttable_size);
  assert (hosttable[a]);
  assert (hosttable[b]);

  return ascii_strcasecmp (hosttable[a]->name, hosttable[b]->name);
}


/* Return true if the host with the hosttable index TBLIDX is in POOL.  */
static int
host_in_pool_p (int *pool, int tblidx)
{
  int i, pidx;

  for (i=0; (pidx = pool[i]) != -1; i++)
    if (pidx == tblidx && hosttable[pidx])
      return 1;
  return 0;
}


/* Select a random host.  Consult TABLE which indices into the global
   hosttable.  Returns index into TABLE or -1 if no host could be
   selected.  */
static int
select_random_host (int *table)
{
  int *tbl;
  size_t tblsize;
  int pidx, idx;

  /* We create a new table so that we randomly select only from
     currently alive hosts.  */
  for (idx=0, tblsize=0; (pidx = table[idx]) != -1; idx++)
    if (hosttable[pidx] && !hosttable[pidx]->dead)
      tblsize++;
  if (!tblsize)
    return -1; /* No hosts.  */

  tbl = xtrymalloc (tblsize * sizeof *tbl);
  if (!tbl)
    return -1;
  for (idx=0, tblsize=0; (pidx = table[idx]) != -1; idx++)
    if (hosttable[pidx] && !hosttable[pidx]->dead)
      tbl[tblsize++] = pidx;

  if (tblsize == 1)  /* Save a get_uint_nonce.  */
    pidx = tbl[0];
  else
    pidx = tbl[get_uint_nonce () % tblsize];

  xfree (tbl);
  return pidx;
}


/* Simplified version of getnameinfo which also returns a numeric
   hostname inside of brackets.  The caller should provide a buffer
   for HOST which is 2 bytes larger than the largest hostname.  If
   NUMERIC is true the returned value is numeric IP address.  Returns
   0 on success or an EAI error code.  True is stored at R_ISNUMERIC
   if HOST has a numeric IP address. */
static int
my_getnameinfo (struct addrinfo *ai, char *host, size_t hostlen,
                int numeric, int *r_isnumeric)
{
  int ec;
  char *p;

  *r_isnumeric = 0;

  if (hostlen < 5)
    return EAI_OVERFLOW;

  if (numeric)
    ec = EAI_NONAME;
  else
    ec = getnameinfo (ai->ai_addr, ai->ai_addrlen,
                      host, hostlen, NULL, 0, NI_NAMEREQD);

  if (!ec && *host == '[')
    ec = EAI_FAIL;  /* A name may never start with a bracket.  */
  else if (ec == EAI_NONAME)
    {
      p = host;
      if (ai->ai_family == AF_INET6)
        {
          *p++ = '[';
          hostlen -= 2;
        }
      ec = getnameinfo (ai->ai_addr, ai->ai_addrlen,
                        p, hostlen, NULL, 0, NI_NUMERICHOST);
      if (!ec && ai->ai_family == AF_INET6)
        strcat (host, "]");

      *r_isnumeric = 1;
    }

  return ec;
}


/* Check whether NAME is an IP address.  */
static int
is_ip_address (const char *name)
{
  int ndots, n;

  if (*name == '[')
    return 1;
  /* Check whether it is legacy IP address.  */
  if (*name == '.')
    return 0; /* No.  */
  ndots = n = 0;
  for (; *name; name++)
    {
      if (*name == '.')
        {
          if (name[1] == '.')
            return 0; /* No. */
          if (atoi (name+1) > 255)
            return 0; /* Value too large.  */
          ndots++;
          n = 0;
        }
      else if (!strchr ("012345678", *name))
        return 0; /* Not a digit.  */
      else if (++n > 3)
        return 0; /* More than 3 digits.  */
    }
  return !!(ndots == 3);
}


/* Map the host name NAME to the actual to be used host name.  This
   allows us to manage round robin DNS names.  We use our own strategy
   to choose one of the hosts.  For example we skip those hosts which
   failed for some time and we stick to one host for a time
   independent of DNS retry times.  If FORCE_RESELECT is true a new
   host is always selected.  The selected host is stored as a malloced
   string at R_HOST; on error NULL is stored.  If R_HTTPFLAGS is not
   NULL it will receive flags which are to be passed to http_open.  If
   R_POOLNAME is not NULL a malloced name of the pool is stored or
   NULL if it is not a pool. */
static gpg_error_t
map_host (ctrl_t ctrl, const char *name, int force_reselect,
          char **r_host, unsigned int *r_httpflags, char **r_poolname)
{
  gpg_error_t err = 0;
  hostinfo_t hi;
  int idx;

  *r_host = NULL;
  if (r_httpflags)
    *r_httpflags = 0;
  if (r_poolname)
    *r_poolname = NULL;

  /* No hostname means localhost.  */
  if (!name || !*name)
    {
      *r_host = xtrystrdup ("localhost");
      return *r_host? 0 : gpg_error_from_syserror ();
    }

  /* See whether the host is in our table.  */
  idx = find_hostinfo (name);
  if (idx == -1)
    {
      /* We never saw this host.  Allocate a new entry.  */
      struct addrinfo hints, *aibuf, *ai;
      int *reftbl;
      size_t reftblsize;
      int refidx;
      int is_pool = 0;

      reftblsize = 100;
      reftbl = xtrymalloc (reftblsize * sizeof *reftbl);
      if (!reftbl)
        return gpg_error_from_syserror ();
      refidx = 0;

      idx = create_new_hostinfo (name);
      if (idx == -1)
        {
          err = gpg_error_from_syserror ();
          xfree (reftbl);
          return err;
        }
      hi = hosttable[idx];

      /* Find all A records for this entry and put them into the pool
         list - if any.  */
      memset (&hints, 0, sizeof (hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;
      /* We can't use the the AI_IDN flag because that does the
         conversion using the current locale.  However, GnuPG always
         used UTF-8.  To support IDN we would need to make use of the
         libidn API.  */
      if (!getaddrinfo (name, NULL, &hints, &aibuf))
        {
          int n_v6, n_v4;

          /* First figure out whether this is a pool.  For a pool we
             use a different strategy than for a plains erver: We use
             the canonical name of the pool as the virtual host along
             with the IP addresses.  If it is not a pool, we use the
             specified name. */
          n_v6 = n_v4 = 0;
          for (ai = aibuf; ai; ai = ai->ai_next)
            {
              if (ai->ai_family != AF_INET6)
                n_v6++;
              else if (ai->ai_family != AF_INET)
                n_v4++;
            }
          if (n_v6 > 1 || n_v4 > 1)
            is_pool = 1;
          if (is_pool && aibuf->ai_canonname)
            hi->cname = xtrystrdup (aibuf->ai_canonname);

          for (ai = aibuf; ai; ai = ai->ai_next)
            {
              char tmphost[NI_MAXHOST + 2];
              int tmpidx;
              int is_numeric;
              int ec;
              int i;

              if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
                continue;

              dirmngr_tick (ctrl);

              if (!is_pool && !is_ip_address (name))
                {
                  /* This is a hostname but not a pool.  Use the name
                     as given without going through getnameinfo.  */
                  if (strlen (name)+1 > sizeof tmphost)
                    {
                      ec = EAI_SYSTEM;
                      gpg_err_set_errno (EINVAL);
                    }
                  else
                    {
                      ec = 0;
                      strcpy (tmphost, name);
                    }
                  is_numeric = 0;
                }
              else
                ec = my_getnameinfo (ai, tmphost, sizeof tmphost,
                                     0, &is_numeric);

              if (ec)
                {
                  log_info ("getnameinfo failed while checking '%s': %s\n",
                            name, gai_strerror (ec));
                }
              else if (refidx+1 >= reftblsize)
                {
                  log_error ("getnameinfo returned for '%s': '%s'"
                            " [index table full - ignored]\n", name, tmphost);
                }
              else
                {
                  tmpidx = find_hostinfo (tmphost);
                  log_info ("getnameinfo returned for '%s': '%s'%s\n",
                            name, tmphost,
                            tmpidx == -1? "" : " [already known]");

                  if (tmpidx == -1) /* Create a new entry.  */
                    tmpidx = create_new_hostinfo (tmphost);

                  if (tmpidx == -1)
                    {
                      log_error ("map_host for '%s' problem: %s - '%s'"
                                 " [ignored]\n",
                                 name, strerror (errno), tmphost);
                    }
                  else  /* Set or update the entry. */
                    {
                      char *ipaddr = NULL;

                      if (!is_numeric)
                        {
                          ec = my_getnameinfo (ai, tmphost, sizeof tmphost,
                                               1, &is_numeric);
                          if (!ec && !(ipaddr = xtrystrdup (tmphost)))
                            ec = EAI_SYSTEM;
                          if (ec)
                            log_info ("getnameinfo failed: %s\n",
                                      gai_strerror (ec));
                        }

                      if (ai->ai_family == AF_INET6)
                        {
                          hosttable[tmpidx]->v6 = 1;
                          xfree (hosttable[tmpidx]->v6addr);
                          hosttable[tmpidx]->v6addr = ipaddr;
                        }
                      else if (ai->ai_family == AF_INET)
                        {
                          hosttable[tmpidx]->v4 = 1;
                          xfree (hosttable[tmpidx]->v4addr);
                          hosttable[tmpidx]->v4addr = ipaddr;
                        }
                      else
                        BUG ();

                      for (i=0; i < refidx; i++)
                        if (reftbl[i] == tmpidx)
                          break;
                      if (!(i < refidx) && tmpidx != idx)
                        reftbl[refidx++] = tmpidx;
                    }
                }
            }
          freeaddrinfo (aibuf);
        }
      reftbl[refidx] = -1;
      if (refidx && is_pool)
        {
          assert (!hi->pool);
          hi->pool = xtryrealloc (reftbl, (refidx+1) * sizeof *reftbl);
          if (!hi->pool)
            {
              err = gpg_error_from_syserror ();
              log_error ("shrinking index table in map_host failed: %s\n",
                         gpg_strerror (err));
              xfree (reftbl);
              return err;
            }
          qsort (reftbl, refidx, sizeof *reftbl, sort_hostpool);
        }
      else
        xfree (reftbl);
    }

  hi = hosttable[idx];
  if (hi->pool)
    {
      /* Deal with the pool name before selecting a host. */
      if (r_poolname && hi->cname)
        {
          *r_poolname = xtrystrdup (hi->cname);
          if (!*r_poolname)
            return gpg_error_from_syserror ();
        }

      /* If the currently selected host is now marked dead, force a
         re-selection .  */
      if (force_reselect)
        hi->poolidx = -1;
      else if (hi->poolidx >= 0 && hi->poolidx < hosttable_size
               && hosttable[hi->poolidx] && hosttable[hi->poolidx]->dead)
        hi->poolidx = -1;

      /* Select a host if needed.  */
      if (hi->poolidx == -1)
        {
          hi->poolidx = select_random_host (hi->pool);
          if (hi->poolidx == -1)
            {
              log_error ("no alive host found in pool '%s'\n", name);
              if (r_poolname)
                {
                  xfree (*r_poolname);
                  *r_poolname = NULL;
                }
              return gpg_error (GPG_ERR_NO_KEYSERVER);
            }
        }

      assert (hi->poolidx >= 0 && hi->poolidx < hosttable_size);
      hi = hosttable[hi->poolidx];
      assert (hi);
    }

  if (hi->dead)
    {
      log_error ("host '%s' marked as dead\n", hi->name);
      if (r_poolname)
        {
          xfree (*r_poolname);
          *r_poolname = NULL;
        }
      return gpg_error (GPG_ERR_NO_KEYSERVER);
    }

  if (r_httpflags)
    {
      /* If the hosttable does not indicate that a certain host
         supports IPv<N>, we explicit set the corresponding http
         flags.  The reason for this is that a host might be listed in
         a pool as not v6 only but actually support v6 when later
         the name is resolved by our http layer.  */
      if (!hi->v4)
        *r_httpflags |= HTTP_FLAG_IGNORE_IPv4;
      if (!hi->v6)
        *r_httpflags |= HTTP_FLAG_IGNORE_IPv6;
    }

  *r_host = xtrystrdup (hi->name);
  if (!*r_host)
    {
      err = gpg_error_from_syserror ();
      if (r_poolname)
        {
          xfree (*r_poolname);
          *r_poolname = NULL;
        }
      return err;
    }
  return 0;
}


/* Mark the host NAME as dead.  NAME may be given as an URL.  Returns
   true if a host was really marked as dead or was already marked dead
   (e.g. by a concurrent session).  */
static int
mark_host_dead (const char *name)
{
  const char *host;
  char *host_buffer = NULL;
  parsed_uri_t parsed_uri = NULL;
  int done = 0;

  if (name && *name && !http_parse_uri (&parsed_uri, name, 1))
    {
      if (parsed_uri->v6lit)
        {
          host_buffer = strconcat ("[", parsed_uri->host, "]", NULL);
          if (!host_buffer)
            log_error ("out of core in mark_host_dead");
          host = host_buffer;
        }
      else
        host = parsed_uri->host;
    }
  else
    host = name;

  if (host && *host && strcmp (host, "localhost"))
    {
      hostinfo_t hi;
      int idx;

      idx = find_hostinfo (host);
      if (idx != -1)
        {
          hi = hosttable[idx];
          log_info ("marking host '%s' as dead%s\n",
                    hi->name, hi->dead? " (again)":"");
          hi->dead = 1;
          hi->died_at = gnupg_get_time ();
          if (!hi->died_at)
            hi->died_at = 1;
          done = 1;
        }
    }

  http_release_parsed_uri (parsed_uri);
  xfree (host_buffer);
  return done;
}


/* Mark a host in the hosttable as dead or - if ALIVE is true - as
   alive.  */
gpg_error_t
ks_hkp_mark_host (ctrl_t ctrl, const char *name, int alive)
{
  gpg_error_t err = 0;
  hostinfo_t hi, hi2;
  int idx, idx2, idx3, n;

  if (!name || !*name || !strcmp (name, "localhost"))
    return 0;

  idx = find_hostinfo (name);
  if (idx == -1)
    return gpg_error (GPG_ERR_NOT_FOUND);

  hi = hosttable[idx];
  if (alive && hi->dead)
    {
      hi->dead = 0;
      err = ks_printf_help (ctrl, "marking '%s' as alive", name);
    }
  else if (!alive && !hi->dead)
    {
      hi->dead = 1;
      hi->died_at = 0; /* Manually set dead.  */
      err = ks_printf_help (ctrl, "marking '%s' as dead", name);
    }

  /* If the host is a pool mark all member hosts. */
  if (!err && hi->pool)
    {
      for (idx2=0; !err && (n=hi->pool[idx2]) != -1; idx2++)
        {
          assert (n >= 0 && n < hosttable_size);

          if (!alive)
            {
              /* Do not mark a host from a pool dead if it is also a
                 member in another pool.  */
              for (idx3=0; idx3 < hosttable_size; idx3++)
                {
                  if (hosttable[idx3]
                      && hosttable[idx3]->pool
                      && idx3 != idx
                      && host_in_pool_p (hosttable[idx3]->pool, n))
                    break;
                }
              if (idx3 < hosttable_size)
                continue;  /* Host is also a member of another pool.  */
            }

          hi2 = hosttable[n];
          if (!hi2)
            ;
          else if (alive && hi2->dead)
            {
              hi2->dead = 0;
              err = ks_printf_help (ctrl, "marking '%s' as alive",
                                    hi2->name);
            }
          else if (!alive && !hi2->dead)
            {
              hi2->dead = 1;
              hi2->died_at = 0; /* Manually set dead. */
              err = ks_printf_help (ctrl, "marking '%s' as dead",
                                    hi2->name);
            }
        }
    }

  return err;
}


/* Debug function to print the entire hosttable.  */
gpg_error_t
ks_hkp_print_hosttable (ctrl_t ctrl)
{
  gpg_error_t err;
  int idx, idx2;
  hostinfo_t hi;
  membuf_t mb;
  time_t curtime;
  char *p, *died;
  const char *diedstr;

  err = ks_print_help (ctrl, "hosttable (idx, ipv6, ipv4, dead, name, time):");
  if (err)
    return err;

  curtime = gnupg_get_time ();
  for (idx=0; idx < hosttable_size; idx++)
    if ((hi=hosttable[idx]))
      {
        if (hi->dead && hi->died_at)
          {
            died = elapsed_time_string (hi->died_at, curtime);
            diedstr = died? died : "error";
          }
        else
          diedstr = died = NULL;
        err = ks_printf_help (ctrl, "%3d %s %s %s %s%s%s%s%s%s%s%s\n",
                              idx, hi->v6? "6":" ", hi->v4? "4":" ",
                              hi->dead? "d":" ",
                              hi->name,
                              hi->v6addr? " v6=":"",
                              hi->v6addr? hi->v6addr:"",
                              hi->v4addr? " v4=":"",
                              hi->v4addr? hi->v4addr:"",
                              diedstr? "  (":"",
                              diedstr? diedstr:"",
                              diedstr? ")":""   );
        xfree (died);
        if (err)
          return err;

        if (hi->cname)
          err = ks_printf_help (ctrl, "  .       %s", hi->cname);
        if (err)
          return err;

        if (hi->pool)
          {
            init_membuf (&mb, 256);
            put_membuf_printf (&mb, "  .   -->");
            for (idx2=0; hi->pool[idx2] != -1; idx2++)
              {
                put_membuf_printf (&mb, " %d", hi->pool[idx2]);
                if (hi->poolidx == hi->pool[idx2])
                  put_membuf_printf (&mb, "*");
              }
            put_membuf( &mb, "", 1);
            p = get_membuf (&mb, NULL);
            if (!p)
              return gpg_error_from_syserror ();
            err = ks_print_help (ctrl, p);
            xfree (p);
            if (err)
              return err;
          }
      }
  return 0;
}



/* Print a help output for the schemata supported by this module. */
gpg_error_t
ks_hkp_help (ctrl_t ctrl, parsed_uri_t uri)
{
  const char const data[] =
    "Handler for HKP URLs:\n"
    "  hkp://\n"
#if  HTTP_USE_GNUTLS || HTTP_USE_NTBTLS
    "  hkps://\n"
#endif
    "Supported methods: search, get, put\n";
  gpg_error_t err;

#if  HTTP_USE_GNUTLS || HTTP_USE_NTBTLS
  const char data2[] = "  hkp\n  hkps";
#else
  const char data2[] = "  hkp";
#endif

  if (!uri)
    err = ks_print_help (ctrl, data2);
  else if (uri->is_http && (!strcmp (uri->scheme, "hkp")
                            || !strcmp (uri->scheme, "hkps")))
    err = ks_print_help (ctrl, data);
  else
    err = 0;

  return err;
}


/* Build the remote part of the URL from SCHEME, HOST and an optional
   PORT.  Returns an allocated string at R_HOSTPORT or NULL on failure
   If R_POOLNAME is not NULL it receives a malloced string with the
   poolname.  */
static gpg_error_t
make_host_part (ctrl_t ctrl,
                const char *scheme, const char *host, unsigned short port,
                int force_reselect,
                char **r_hostport, unsigned int *r_httpflags, char **r_poolname)
{
  gpg_error_t err;
  char portstr[10];
  char *hostname;

  *r_hostport = NULL;

  /* Map scheme and port.  */
  if (!strcmp (scheme, "hkps") || !strcmp (scheme,"https"))
    {
      scheme = "https";
      strcpy (portstr, "443");
    }
  else /* HKP or HTTP.  */
    {
      scheme = "http";
      strcpy (portstr, "11371");
    }
  if (port)
    snprintf (portstr, sizeof portstr, "%hu", port);
  else
    {
      /*fixme_do_srv_lookup ()*/
    }

  err = map_host (ctrl, host, force_reselect,
                  &hostname, r_httpflags, r_poolname);
  if (err)
    return err;

  *r_hostport = strconcat (scheme, "://", hostname, ":", portstr, NULL);
  xfree (hostname);
  if (!*r_hostport)
    {
      if (r_poolname)
        {
          xfree (*r_poolname);
          *r_poolname = NULL;
        }
      return gpg_error_from_syserror ();
    }
  return 0;
}


/* Resolve all known keyserver names and update the hosttable.  This
   is mainly useful for debugging because the resolving is anyway done
   on demand.  */
gpg_error_t
ks_hkp_resolve (ctrl_t ctrl, parsed_uri_t uri)
{
  gpg_error_t err;
  char *hostport = NULL;

  err = make_host_part (ctrl, uri->scheme, uri->host, uri->port, 1,
                        &hostport, NULL, NULL);
  if (err)
    {
      err = ks_printf_help (ctrl, "%s://%s:%hu: resolve failed: %s",
                            uri->scheme, uri->host, uri->port,
                            gpg_strerror (err));
    }
  else
    {
      err = ks_printf_help (ctrl, "%s", hostport);
      xfree (hostport);
    }
  return err;
}


/* Housekeeping function called from the housekeeping thread.  It is
   used to mark dead hosts alive so that they may be tried again after
   some time.  */
void
ks_hkp_housekeeping (time_t curtime)
{
  int idx;
  hostinfo_t hi;

  for (idx=0; idx < hosttable_size; idx++)
    {
      hi = hosttable[idx];
      if (!hi)
        continue;
      if (!hi->dead)
        continue;
      if (!hi->died_at)
        continue; /* Do not resurrect manually shot hosts.  */
      if (hi->died_at + RESURRECT_INTERVAL <= curtime
          || hi->died_at > curtime)
        {
          hi->dead = 0;
          log_info ("resurrected host '%s'", hi->name);
        }
    }
}


/* Send an HTTP request.  On success returns an estream object at
   R_FP.  HOSTPORTSTR is only used for diagnostics.  If HTTPHOST is
   not NULL it will be used as HTTP "Host" header.  If POST_CB is not
   NULL a post request is used and that callback is called to allow
   writing the post data.  */
static gpg_error_t
send_request (ctrl_t ctrl, const char *request, const char *hostportstr,
              const char *httphost, unsigned int httpflags,
              gpg_error_t (*post_cb)(void *, http_t), void *post_cb_value,
              estream_t *r_fp)
{
  gpg_error_t err;
  http_session_t session = NULL;
  http_t http = NULL;
  int redirects_left = MAX_REDIRECTS;
  estream_t fp = NULL;
  char *request_buffer = NULL;

  *r_fp = NULL;

  err = http_session_new (&session, NULL);
  if (err)
    goto leave;
  http_session_set_log_cb (session, cert_log_cb);

 once_more:
  err = http_open (&http,
                   post_cb? HTTP_REQ_POST : HTTP_REQ_GET,
                   request,
                   httphost,
                   /* fixme: AUTH */ NULL,
                   (httpflags | (opt.honor_http_proxy? HTTP_FLAG_TRY_PROXY:0)),
                   ctrl->http_proxy,
                   session,
                   NULL,
                   /*FIXME curl->srvtag*/NULL);
  if (!err)
    {
      fp = http_get_write_ptr (http);
      /* Avoid caches to get the most recent copy of the key.  We set
         both the Pragma and Cache-Control versions of the header, so
         we're good with both HTTP 1.0 and 1.1.  */
      es_fputs ("Pragma: no-cache\r\n"
                "Cache-Control: no-cache\r\n", fp);
      if (post_cb)
        err = post_cb (post_cb_value, http);
      if (!err)
        {
          http_start_data (http);
          if (es_ferror (fp))
            err = gpg_error_from_syserror ();
        }
    }
  if (err)
    {
      /* Fixme: After a redirection we show the old host name.  */
      log_error (_("error connecting to '%s': %s\n"),
                 hostportstr, gpg_strerror (err));
      goto leave;
    }

  /* Wait for the response.  */
  dirmngr_tick (ctrl);
  err = http_wait_response (http);
  if (err)
    {
      log_error (_("error reading HTTP response for '%s': %s\n"),
                 hostportstr, gpg_strerror (err));
      goto leave;
    }

  if (http_get_tls_info (http, NULL))
    {
      /* Update the httpflags so that a redirect won't fallback to an
         unencrypted connection.  */
      httpflags |= HTTP_FLAG_FORCE_TLS;
    }

  switch (http_get_status_code (http))
    {
    case 200:
      err = 0;
      break; /* Success.  */

    case 301:
    case 302:
    case 307:
      {
        const char *s = http_get_header (http, "Location");

        log_info (_("URL '%s' redirected to '%s' (%u)\n"),
                  request, s?s:"[none]", http_get_status_code (http));
        if (s && *s && redirects_left-- )
          {
            xfree (request_buffer);
            request_buffer = xtrystrdup (s);
            if (request_buffer)
              {
                request = request_buffer;
                http_close (http, 0);
                http = NULL;
                goto once_more;
              }
            err = gpg_error_from_syserror ();
          }
        else
          err = gpg_error (GPG_ERR_NO_DATA);
        log_error (_("too many redirections\n"));
      }
      goto leave;

    default:
      log_error (_("error accessing '%s': http status %u\n"),
                 request, http_get_status_code (http));
      err = gpg_error (GPG_ERR_NO_DATA);
      goto leave;
    }

  /* FIXME: We should register a permanent redirection and whether a
     host has ever used TLS so that future calls will always use
     TLS. */

  fp = http_get_read_ptr (http);
  if (!fp)
    {
      err = gpg_error (GPG_ERR_BUG);
      goto leave;
    }

  /* Return the read stream and close the HTTP context.  */
  *r_fp = fp;
  http_close (http, 1);
  http = NULL;

 leave:
  http_close (http, 0);
  http_session_release (session);
  xfree (request_buffer);
  return err;
}


/* Helper to evaluate the error code ERR form a send_request() call
   with REQUEST.  The function returns true if the caller shall try
   again.  TRIES_LEFT points to a variable to track the number of
   retries; this function decrements it and won't return true if it is
   down to zero. */
static int
handle_send_request_error (gpg_error_t err, const char *request,
                           unsigned int *tries_left)
{
  int retry = 0;

  switch (gpg_err_code (err))
    {
    case GPG_ERR_ECONNREFUSED:
    case GPG_ERR_ENETUNREACH:
    case GPG_ERR_UNKNOWN_HOST:
    case GPG_ERR_NETWORK:
      if (mark_host_dead (request) && *tries_left)
        retry = 1;
      break;

    case GPG_ERR_ETIMEDOUT:
      if (*tries_left)
        {
          log_info ("selecting a different host due to a timeout\n");
          retry = 1;
        }

    default:
      break;
    }

  if (*tries_left)
    --*tries_left;

  return retry;
}


/* Search the keyserver identified by URI for keys matching PATTERN.
   On success R_FP has an open stream to read the data.  */
gpg_error_t
ks_hkp_search (ctrl_t ctrl, parsed_uri_t uri, const char *pattern,
               estream_t *r_fp)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char fprbuf[2+40+1];
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;
  int reselect;
  unsigned int httpflags;
  char *httphost = NULL;
  unsigned int tries = SEND_REQUEST_RETRIES;

  *r_fp = NULL;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id (pattern, &desc, 1);
  if (err)
    return err;
  switch (desc.mode)
    {
    case KEYDB_SEARCH_MODE_EXACT:
    case KEYDB_SEARCH_MODE_SUBSTR:
    case KEYDB_SEARCH_MODE_MAIL:
    case KEYDB_SEARCH_MODE_MAILSUB:
      pattern = desc.u.name;
      break;
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf (fprbuf, sizeof fprbuf, "0x%08lX", (ulong)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf (fprbuf, sizeof fprbuf, "0x%08lX%08lX",
                (ulong)desc.u.kid[0], (ulong)desc.u.kid[1]);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR16:
      bin2hex (desc.u.fpr, 16, fprbuf);
      pattern = fprbuf;
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      bin2hex (desc.u.fpr, 20, fprbuf);
      pattern = fprbuf;
      break;
    default:
      return gpg_error (GPG_ERR_INV_USER_ID);
    }

  /* Build the request string.  */
  reselect = 0;
 again:
  {
    char *searchkey;

    xfree (hostport); hostport = NULL;
    xfree (httphost); httphost = NULL;
    err = make_host_part (ctrl, uri->scheme, uri->host, uri->port, reselect,
                          &hostport, &httpflags, &httphost);
    if (err)
      goto leave;

    searchkey = http_escape_string (pattern, EXTRA_ESCAPE_CHARS);
    if (!searchkey)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }

    xfree (request);
    request = strconcat (hostport,
                         "/pks/lookup?op=index&options=mr&search=",
                         searchkey,
                         NULL);
    xfree (searchkey);
    if (!request)
      {
        err = gpg_error_from_syserror ();
        goto leave;
      }
  }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, httphost, httpflags,
                      NULL, NULL, &fp);
  if (handle_send_request_error (err, request, &tries))
    {
      reselect = 1;
      goto again;
    }
  if (err)
    goto leave;

  err = dirmngr_status (ctrl, "SOURCE", hostport, NULL);
  if (err)
    goto leave;

  /* Peek at the response.  */
  {
    int c = es_getc (fp);
    if (c == -1)
      {
        err = es_ferror (fp)?gpg_error_from_syserror ():gpg_error (GPG_ERR_EOF);
        log_error ("error reading response: %s\n", gpg_strerror (err));
        goto leave;
      }
    if (c == '<')
      {
        /* The document begins with a '<': Assume a HTML response,
           which we don't support.  */
        err = gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);
        goto leave;
      }
    es_ungetc (c, fp);
  }

  /* Return the read stream.  */
  *r_fp = fp;
  fp = NULL;

 leave:
  es_fclose (fp);
  xfree (request);
  xfree (hostport);
  xfree (httphost);
  return err;
}


/* Get the key described key the KEYSPEC string from the keyserver
   identified by URI.  On success R_FP has an open stream to read the
   data.  The data will be provided in a format GnuPG can import
   (either a binary OpenPGP message or an armored one).  */
gpg_error_t
ks_hkp_get (ctrl_t ctrl, parsed_uri_t uri, const char *keyspec, estream_t *r_fp)
{
  gpg_error_t err;
  KEYDB_SEARCH_DESC desc;
  char kidbuf[2+40+1];
  const char *exactname = NULL;
  char *searchkey = NULL;
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;
  int reselect;
  char *httphost = NULL;
  unsigned int httpflags;
  unsigned int tries = SEND_REQUEST_RETRIES;

  *r_fp = NULL;

  /* Remove search type indicator and adjust PATTERN accordingly.
     Note that HKP keyservers like the 0x to be present when searching
     by keyid.  We need to re-format the fingerprint and keyids so to
     remove the gpg specific force-use-of-this-key flag ("!").  */
  err = classify_user_id (keyspec, &desc, 1);
  if (err)
    return err;
  switch (desc.mode)
    {
    case KEYDB_SEARCH_MODE_SHORT_KID:
      snprintf (kidbuf, sizeof kidbuf, "0x%08lX", (ulong)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_LONG_KID:
      snprintf (kidbuf, sizeof kidbuf, "0x%08lX%08lX",
		(ulong)desc.u.kid[0], (ulong)desc.u.kid[1]);
      break;
    case KEYDB_SEARCH_MODE_FPR20:
    case KEYDB_SEARCH_MODE_FPR:
      /* This is a v4 fingerprint. */
      kidbuf[0] = '0';
      kidbuf[1] = 'x';
      bin2hex (desc.u.fpr, 20, kidbuf+2);
      break;

    case KEYDB_SEARCH_MODE_EXACT:
      exactname = desc.u.name;
      break;

    case KEYDB_SEARCH_MODE_FPR16:
      log_error ("HKP keyservers do not support v3 fingerprints\n");
    default:
      return gpg_error (GPG_ERR_INV_USER_ID);
    }

  searchkey = http_escape_string (exactname? exactname : kidbuf,
                                  EXTRA_ESCAPE_CHARS);
  if (!searchkey)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  reselect = 0;
 again:
  /* Build the request string.  */
  xfree (hostport); hostport = NULL;
  xfree (httphost); httphost = NULL;
  err = make_host_part (ctrl, uri->scheme, uri->host, uri->port, reselect,
                        &hostport, &httpflags, &httphost);
  if (err)
    goto leave;

  xfree (request);
  request = strconcat (hostport,
                       "/pks/lookup?op=get&options=mr&search=",
                       searchkey,
                       exactname? "&exact=on":"",
                       NULL);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, httphost, httpflags,
                      NULL, NULL, &fp);
  if (handle_send_request_error (err, request, &tries))
    {
      reselect = 1;
      goto again;
    }
  if (err)
    goto leave;

  err = dirmngr_status (ctrl, "SOURCE", hostport, NULL);
  if (err)
    goto leave;

  /* Return the read stream and close the HTTP context.  */
  *r_fp = fp;
  fp = NULL;

 leave:
  es_fclose (fp);
  xfree (request);
  xfree (hostport);
  xfree (httphost);
  xfree (searchkey);
  return err;
}




/* Callback parameters for put_post_cb.  */
struct put_post_parm_s
{
  char *datastring;
};


/* Helper for ks_hkp_put.  */
static gpg_error_t
put_post_cb (void *opaque, http_t http)
{
  struct put_post_parm_s *parm = opaque;
  gpg_error_t err = 0;
  estream_t fp;
  size_t len;

  fp = http_get_write_ptr (http);
  len = strlen (parm->datastring);

  es_fprintf (fp,
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: %zu\r\n", len+8 /* 8 is for "keytext" */);
  http_start_data (http);
  if (es_fputs ("keytext=", fp) || es_write (fp, parm->datastring, len, NULL))
    err = gpg_error_from_syserror ();
  return err;
}


/* Send the key in {DATA,DATALEN} to the keyserver identified by URI.  */
gpg_error_t
ks_hkp_put (ctrl_t ctrl, parsed_uri_t uri, const void *data, size_t datalen)
{
  gpg_error_t err;
  char *hostport = NULL;
  char *request = NULL;
  estream_t fp = NULL;
  struct put_post_parm_s parm;
  char *armored = NULL;
  int reselect;
  char *httphost = NULL;
  unsigned int httpflags;
  unsigned int tries = SEND_REQUEST_RETRIES;

  parm.datastring = NULL;

  err = armor_data (&armored, data, datalen);
  if (err)
    goto leave;

  parm.datastring = http_escape_string (armored, EXTRA_ESCAPE_CHARS);
  if (!parm.datastring)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  xfree (armored);
  armored = NULL;

  /* Build the request string.  */
  reselect = 0;
 again:
  xfree (hostport); hostport = NULL;
  xfree (httphost); httphost = NULL;
  err = make_host_part (ctrl, uri->scheme, uri->host, uri->port, reselect,
                        &hostport, &httpflags, &httphost);
  if (err)
    goto leave;

  xfree (request);
  request = strconcat (hostport, "/pks/add", NULL);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Send the request.  */
  err = send_request (ctrl, request, hostport, httphost, 0,
                      put_post_cb, &parm, &fp);
  if (handle_send_request_error (err, request, &tries))
    {
      reselect = 1;
      goto again;
    }
  if (err)
    goto leave;

 leave:
  es_fclose (fp);
  xfree (parm.datastring);
  xfree (armored);
  xfree (request);
  xfree (hostport);
  xfree (httphost);
  return err;
}
