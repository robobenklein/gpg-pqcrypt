/* asshelp.c - Helper functions for Assuan
 * Copyright (C) 2002, 2004, 2007, 2009, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
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
 * This file is distributed in the hope that it will be useful,
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
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "i18n.h"
#include "util.h"
#include "exechelp.h"
#include "sysutils.h"
#include "status.h"
#include "asshelp.h"

/* The type we use for lock_agent_spawning.  */
#ifdef HAVE_W32_SYSTEM
# define lock_spawn_t HANDLE
#else
# define lock_spawn_t dotlock_t
#endif

/* The time we wait until the agent or the dirmngr are ready for
   operation after we started them before giving up.  */
#ifdef HAVE_W32CE_SYSTEM
# define SECS_TO_WAIT_FOR_AGENT 30
# define SECS_TO_WAIT_FOR_DIRMNGR 30
#else
# define SECS_TO_WAIT_FOR_AGENT 5
# define SECS_TO_WAIT_FOR_DIRMNGR 5
#endif

/* A bitfield that specifies the assuan categories to log.  This is
   identical to the default log handler of libassuan.  We need to do
   it ourselves because we use a custom log handler and want to use
   the same assuan variables to select the categories to log. */
static int log_cats;
#define TEST_LOG_CAT(x) (!! (log_cats & (1 << (x - 1))))


static int
my_libassuan_log_handler (assuan_context_t ctx, void *hook,
                          unsigned int cat, const char *msg)
{
  unsigned int dbgval;

  (void)ctx;

  if (! TEST_LOG_CAT (cat))
    return 0;

  dbgval = hook? *(unsigned int*)hook : 0;
  if (!(dbgval & 1024))
    return 0; /* Assuan debugging is not enabled.  */

  if (msg)
    log_string (GPGRT_LOG_DEBUG, msg);

  return 1;
}


/* Setup libassuan to use our own logging functions.  Should be used
   early at startup.  */
void
setup_libassuan_logging (unsigned int *debug_var_address)
{
  char *flagstr;

  flagstr = getenv ("ASSUAN_DEBUG");
  if (flagstr)
    log_cats = atoi (flagstr);
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
  assuan_set_log_cb (my_libassuan_log_handler, debug_var_address);
}

/* Change the Libassuan log categories to those given by NEWCATS.
   NEWCATS is 0 the default category of ASSUAN_LOG_CONTROL is
   selected.  Note, that setup_libassuan_logging overrides the values
   given here.  */
void
set_libassuan_log_cats (unsigned int newcats)
{
  if (newcats)
    log_cats = newcats;
  else /* Default to log the control channel.  */
    log_cats = (1 << (ASSUAN_LOG_CONTROL - 1));
}



static gpg_error_t
send_one_option (assuan_context_t ctx, gpg_err_source_t errsource,
                 const char *name, const char *value, int use_putenv)
{
  gpg_error_t err;
  char *optstr;

  (void)errsource;

  if (!value || !*value)
    err = 0;  /* Avoid sending empty strings.  */
  else if (asprintf (&optstr, "OPTION %s%s=%s",
                     use_putenv? "putenv=":"", name, value) < 0)
    err = gpg_error_from_syserror ();
  else
    {
      err = assuan_transact (ctx, optstr, NULL, NULL, NULL, NULL, NULL, NULL);
      xfree (optstr);
    }

  return err;
}


/* Send the assuan commands pertaining to the pinentry environment.  The
   OPT_* arguments are optional and may be used to override the
   defaults taken from the current locale. */
gpg_error_t
send_pinentry_environment (assuan_context_t ctx,
                           gpg_err_source_t errsource,
                           const char *opt_lc_ctype,
                           const char *opt_lc_messages,
                           session_env_t session_env)

{
  gpg_error_t err = 0;
#if defined(HAVE_SETLOCALE)
  char *old_lc = NULL;
#endif
  char *dft_lc = NULL;
  const char *dft_ttyname;
  int iterator;
  const char *name, *assname, *value;
  int is_default;

  iterator = 0;
  while ((name = session_env_list_stdenvnames (&iterator, &assname)))
    {
      value = session_env_getenv_or_default (session_env, name, NULL);
      if (!value)
        continue;

      if (assname)
        err = send_one_option (ctx, errsource, assname, value, 0);
      else
        {
          err = send_one_option (ctx, errsource, name, value, 1);
          if (gpg_err_code (err) == GPG_ERR_UNKNOWN_OPTION)
            err = 0;  /* Server too old; can't pass the new envvars.  */
        }
      if (err)
        return err;
    }


  dft_ttyname = session_env_getenv_or_default (session_env, "GPG_TTY",
                                               &is_default);
  if (dft_ttyname && !is_default)
    dft_ttyname = NULL;  /* We need the default value.  */

  /* Send the value for LC_CTYPE.  */
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  old_lc = setlocale (LC_CTYPE, NULL);
  if (old_lc)
    {
      old_lc = xtrystrdup (old_lc);
      if (!old_lc)
        return gpg_error_from_syserror ();
    }
  dft_lc = setlocale (LC_CTYPE, "");
#endif
  if (opt_lc_ctype || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-ctype",
                             opt_lc_ctype ? opt_lc_ctype : dft_lc, 0);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      xfree (old_lc);
    }
#endif
  if (err)
    return err;

  /* Send the value for LC_MESSAGES.  */
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  old_lc = setlocale (LC_MESSAGES, NULL);
  if (old_lc)
    {
      old_lc = xtrystrdup (old_lc);
      if (!old_lc)
        return gpg_error_from_syserror ();
    }
  dft_lc = setlocale (LC_MESSAGES, "");
#endif
  if (opt_lc_messages || (dft_ttyname && dft_lc))
    {
      err = send_one_option (ctx, errsource, "lc-messages",
                             opt_lc_messages ? opt_lc_messages : dft_lc, 0);
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      xfree (old_lc);
    }
#endif
  if (err)
    return err;

  return 0;
}


/* Lock a spawning process.  The caller needs to provide the address
   of a variable to store the lock information and the name or the
   process.  */
static gpg_error_t
lock_spawning (lock_spawn_t *lock, const char *homedir, const char *name,
               int verbose)
{
#ifdef HAVE_W32_SYSTEM
  int waitrc;
  int timeout = (!strcmp (name, "agent")
                 ? SECS_TO_WAIT_FOR_AGENT
                 : SECS_TO_WAIT_FOR_DIRMNGR);

  (void)homedir; /* Not required. */

  *lock = CreateMutexW
    (NULL, FALSE,
     !strcmp (name, "agent")?   L"spawn_"GNUPG_NAME"_agent_sentinel":
     !strcmp (name, "dirmngr")? L"spawn_"GNUPG_NAME"_dirmngr_sentinel":
     /*                    */   L"spawn_"GNUPG_NAME"_unknown_sentinel");
  if (!*lock)
    {
      log_error ("failed to create the spawn_%s mutex: %s\n",
                 name, w32_strerror (-1));
      return gpg_error (GPG_ERR_GENERAL);
    }

 retry:
  waitrc = WaitForSingleObject (*lock, 1000);
  if (waitrc == WAIT_OBJECT_0)
    return 0;

  if (waitrc == WAIT_TIMEOUT && timeout)
    {
      timeout--;
      if (verbose)
        log_info ("another process is trying to start the %s ... (%ds)\n",
                  name, timeout);
      goto retry;
    }
  if (waitrc == WAIT_TIMEOUT)
    log_info ("error waiting for the spawn_%s mutex: timeout\n", name);
  else
    log_info ("error waiting for the spawn_%s mutex: (code=%d) %s\n",
              name, waitrc, w32_strerror (-1));
  return gpg_error (GPG_ERR_GENERAL);
#else /*!HAVE_W32_SYSTEM*/
  char *fname;

  (void)verbose;

  *lock = NULL;

  fname = make_absfilename_try
    (homedir,
     !strcmp (name, "agent")?   "gnupg_spawn_agent_sentinel":
     !strcmp (name, "dirmngr")? "gnupg_spawn_dirmngr_sentinel":
     /*                    */   "gnupg_spawn_unknown_sentinel",
     NULL);
  if (!fname)
    return gpg_error_from_syserror ();

  *lock = dotlock_create (fname, 0);
  xfree (fname);
  if (!*lock)
    return gpg_error_from_syserror ();

  /* FIXME: We should use a timeout of 5000 here - however
     make_dotlock does not yet support values other than -1 and 0.  */
  if (dotlock_take (*lock, -1))
    return gpg_error_from_syserror ();

  return 0;
#endif /*!HAVE_W32_SYSTEM*/
}


/* Unlock the spawning process.  */
static void
unlock_spawning (lock_spawn_t *lock, const char *name)
{
  if (*lock)
    {
#ifdef HAVE_W32_SYSTEM
      if (!ReleaseMutex (*lock))
        log_error ("failed to release the spawn_%s mutex: %s\n",
                   name, w32_strerror (-1));
      CloseHandle (*lock);
#else /*!HAVE_W32_SYSTEM*/
      (void)name;
      dotlock_destroy (*lock);
#endif /*!HAVE_W32_SYSTEM*/
      *lock = NULL;
    }
}

/* Try to connect to the agent via socket or start it if it is not
   running and AUTOSTART is set.  Handle the server's initial
   greeting.  Returns a new assuan context at R_CTX or an error
   code. */
gpg_error_t
start_new_gpg_agent (assuan_context_t *r_ctx,
                     gpg_err_source_t errsource,
                     const char *homedir,
                     const char *agent_program,
                     const char *opt_lc_ctype,
                     const char *opt_lc_messages,
                     session_env_t session_env,
                     int autostart, int verbose, int debug,
                     gpg_error_t (*status_cb)(ctrl_t, int, ...),
                     ctrl_t status_cb_arg)
{
  gpg_error_t err;
  assuan_context_t ctx;
  int did_success_msg = 0;
  char *sockname;
  const char *argv[6];

  *r_ctx = NULL;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("error allocating assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  sockname = make_absfilename (homedir, GPG_AGENT_SOCK_NAME, NULL);
  err = assuan_socket_connect (ctx, sockname, 0, 0);
  if (err && autostart)
    {
      char *abs_homedir;
      lock_spawn_t lock;
      char *program = NULL;
      const char *program_arg = NULL;
      char *p;
      const char *s;
      int i;

      /* With no success start a new server.  */
      if (!agent_program || !*agent_program)
        agent_program = gnupg_module_name (GNUPG_MODULE_NAME_AGENT);
      else if ((s=strchr (agent_program, '|')) && s[1] == '-' && s[2]=='-')
        {
          /* Hack to insert an additional option on the command line.  */
          program = xtrystrdup (agent_program);
          if (!program)
            {
              gpg_error_t tmperr = gpg_err_make (errsource,
                                                 gpg_err_code_from_syserror ());
              xfree (sockname);
              assuan_release (ctx);
              return tmperr;
            }
          p = strchr (program, '|');
          *p++ = 0;
          program_arg = p;
        }

      if (verbose)
        log_info (_("no running gpg-agent - starting '%s'\n"),
                  agent_program);

      if (status_cb)
        status_cb (status_cb_arg, STATUS_PROGRESS,
                   "starting_agent ? 0 0", NULL);

      /* We better pass an absolute home directory to the agent just
         in case gpg-agent does not convert the passed name to an
         absolute one (which it should do).  */
      abs_homedir = make_absfilename_try (homedir, NULL);
      if (!abs_homedir)
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error building filename: %s\n",gpg_strerror (tmperr));
          xfree (sockname);
          assuan_release (ctx);
          xfree (program);
          return tmperr;
        }

      if (fflush (NULL))
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error flushing pending output: %s\n",
                     strerror (errno));
          xfree (sockname);
          assuan_release (ctx);
          xfree (abs_homedir);
          xfree (program);
          return tmperr;
        }

      /* If the agent has been configured for use with a standard
         socket, an environment variable is not required and thus
         we we can savely start the agent here.  */
      i = 0;
      argv[i++] = "--homedir";
      argv[i++] = abs_homedir;
      argv[i++] = "--use-standard-socket";
      if (program_arg)
        argv[i++] = program_arg;
      argv[i++] = "--daemon";
      argv[i++] = NULL;

      if (!(err = lock_spawning (&lock, homedir, "agent", verbose))
          && assuan_socket_connect (ctx, sockname, 0, 0))
        {
          err = gnupg_spawn_process_detached (program? program : agent_program,
                                              argv, NULL);
          if (err)
            log_error ("failed to start agent '%s': %s\n",
                       agent_program, gpg_strerror (err));
          else
            {
              for (i=0; i < SECS_TO_WAIT_FOR_AGENT; i++)
                {
                  if (verbose)
                    log_info (_("waiting for the agent to come up ... (%ds)\n"),
                              SECS_TO_WAIT_FOR_AGENT - i);
                  gnupg_sleep (1);
                  err = assuan_socket_connect (ctx, sockname, 0, 0);
                  if (!err)
                    {
                      if (verbose)
                        {
                          log_info (_("connection to agent established\n"));
                          did_success_msg = 1;
                        }
                      break;
                    }
                }
            }
        }

      unlock_spawning (&lock, "agent");
      xfree (abs_homedir);
      xfree (program);
    }
  xfree (sockname);
  if (err)
    {
      if (autostart || gpg_err_code (err) != GPG_ERR_ASS_CONNECT_FAILED)
        log_error ("can't connect to the agent: %s\n", gpg_strerror (err));
      assuan_release (ctx);
      return gpg_err_make (errsource, GPG_ERR_NO_AGENT);
    }

  if (debug && !did_success_msg)
    log_debug (_("connection to agent established\n"));

  err = assuan_transact (ctx, "RESET",
                         NULL, NULL, NULL, NULL, NULL, NULL);
  if (!err)
    {
      err = send_pinentry_environment (ctx, errsource,
                                       opt_lc_ctype, opt_lc_messages,
                                       session_env);
      if (gpg_err_code (err) == GPG_ERR_FORBIDDEN
          && gpg_err_source (err) == GPG_ERR_SOURCE_GPGAGENT)
        {
          /* Check whether we are in restricted mode.  */
          if (!assuan_transact (ctx, "GETINFO restricted",
                                NULL, NULL, NULL, NULL, NULL, NULL))
            {
              if (verbose)
                log_info (_("connection to agent is in restricted mode\n"));
              err = 0;
            }
        }
    }
  if (err)
    {
      assuan_release (ctx);
      return err;
    }

  *r_ctx = ctx;
  return 0;
}


/* Try to connect to the dirmngr via a socket.  On platforms
   supporting it, start it up if needed and if AUTOSTART is true.
   Returns a new assuan context at R_CTX or an error code. */
gpg_error_t
start_new_dirmngr (assuan_context_t *r_ctx,
                   gpg_err_source_t errsource,
                   const char *homedir,
                   const char *dirmngr_program,
                   int autostart,
                   int verbose, int debug,
                   gpg_error_t (*status_cb)(ctrl_t, int, ...),
                   ctrl_t status_cb_arg)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *sockname;
  int did_success_msg = 0;

  *r_ctx = NULL;

  err = assuan_new (&ctx);
  if (err)
    {
      log_error ("error allocating assuan context: %s\n", gpg_strerror (err));
      return err;
    }

  sockname = dirmngr_user_socket_name ();
  if (sockname)
    {
      /* First try the local socket name and only if that fails try
         the system socket.  */
      err = assuan_socket_connect (ctx, sockname, 0, 0);
      if (err)
        sockname = dirmngr_sys_socket_name ();
    }
  else
    sockname = dirmngr_sys_socket_name ();

  err = assuan_socket_connect (ctx, sockname, 0, 0);

#ifdef USE_DIRMNGR_AUTO_START
  if (err && autostart)
    {
      lock_spawn_t lock;
      const char *argv[4];
      int try_system_daemon = 0;
      char *abs_homedir;

      /* No connection: Try start a new Dirmngr.  On Windows this will
         fail because the Dirmngr is expected to be a system service.
         However on WinCE we don't distinguish users and thus we can
         start it.  */

      /* We prefer to start it as a user daemon.  */
      sockname = dirmngr_user_socket_name ();
      if (!sockname)
        {
          sockname = dirmngr_sys_socket_name ();
          try_system_daemon = 1;
        }

      if (!dirmngr_program || !*dirmngr_program)
        dirmngr_program = gnupg_module_name (GNUPG_MODULE_NAME_DIRMNGR);

      if (verbose)
        log_info (_("no running Dirmngr - starting '%s'\n"),
                  dirmngr_program);

      if (status_cb)
        status_cb (status_cb_arg, STATUS_PROGRESS,
                   "starting_dirmngr ? 0 0", NULL);

      abs_homedir = make_absfilename (homedir, NULL);
      if (!abs_homedir)
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error building filename: %s\n",gpg_strerror (tmperr));
          assuan_release (ctx);
          return tmperr;
        }

      if (fflush (NULL))
        {
          gpg_error_t tmperr = gpg_err_make (errsource,
                                             gpg_err_code_from_syserror ());
          log_error ("error flushing pending output: %s\n",
                     strerror (errno));
          assuan_release (ctx);
          return tmperr;
        }

      argv[0] = "--daemon";
      if (try_system_daemon)
        argv[1] = NULL;
      else
        { /* Try starting as user daemon - dirmngr does this if the
             home directory is given on the command line.  */
          argv[1] = "--homedir";
          argv[2] = abs_homedir;
          argv[3] = NULL;
        }

      /* On the use of HOMEDIR for locking: Under Windows HOMEDIR is
         not used thus it does not matter.  Under Unix we should
         TRY_SYSTEM_DAEMON should never be true because
         dirmngr_user_socket_name() won't return NULL.  */

      if (!(err = lock_spawning (&lock, homedir, "dirmngr", verbose))
          && assuan_socket_connect (ctx, sockname, 0, 0))
        {
          err = gnupg_spawn_process_detached (dirmngr_program, argv, NULL);
          if (err)
            log_error ("failed to start the dirmngr '%s': %s\n",
                       dirmngr_program, gpg_strerror (err));
          else
            {
              int i;

              for (i=0; i < SECS_TO_WAIT_FOR_DIRMNGR; i++)
                {
                  if (verbose)
                    log_info (_("waiting for the dirmngr "
                                "to come up ... (%ds)\n"),
                              SECS_TO_WAIT_FOR_DIRMNGR - i);
                  gnupg_sleep (1);
                  err = assuan_socket_connect (ctx, sockname, 0, 0);
                  if (!err)
                    {
                      if (verbose)
                        {
                          log_info (_("connection to the dirmngr"
                                      " established\n"));
                          did_success_msg = 1;
                        }
                      break;
                    }
                }
            }
        }

      unlock_spawning (&lock, "dirmngr");
      xfree (abs_homedir);
    }
#else
  (void)homedir;
  (void)dirmngr_program;
  (void)verbose;
  (void)status_cb;
  (void)status_cb_arg;
#endif /*USE_DIRMNGR_AUTO_START*/

  if (err)
    {
      if (autostart || gpg_err_code (err) != GPG_ERR_ASS_CONNECT_FAILED)
        log_error ("connecting dirmngr at '%s' failed: %s\n",
                   sockname, gpg_strerror (err));
      assuan_release (ctx);
      return gpg_err_make (errsource, GPG_ERR_NO_DIRMNGR);
    }

  if (debug && !did_success_msg)
    log_debug (_("connection to the dirmngr established\n"));

  *r_ctx = ctx;
  return 0;
}
