/* scdaemon.c  -  The GnuPG Smartcard Daemon
 * Copyright (C) 2001-2002, 2004-2005, 2007-2009 Free Software Foundation, Inc.
 * Copyright (C) 2001-2002, 2004-2005, 2007-2014 Werner Koch
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
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#ifndef HAVE_W32_SYSTEM
#include <sys/socket.h>
#include <sys/un.h>
#endif /*HAVE_W32_SYSTEM*/
#include <unistd.h>
#include <signal.h>
#include <npth.h>

#define GNUPG_COMMON_NEED_AFLOCAL
#include "scdaemon.h"
#include <ksba.h>
#include <gcrypt.h>

#include <assuan.h> /* malloc hooks */

#include "i18n.h"
#include "sysutils.h"
#include "app-common.h"
#include "iso7816.h"
#include "apdu.h"
#include "ccid-driver.h"
#include "gc-opt-flags.h"
#include "asshelp.h"
#include "../common/init.h"

#ifndef ENAMETOOLONG
# define ENAMETOOLONG EINVAL
#endif

enum cmd_and_opt_values
{ aNull = 0,
  oCsh		  = 'c',
  oQuiet	  = 'q',
  oSh		  = 's',
  oVerbose	  = 'v',

  oNoVerbose = 500,
  aGPGConfList,
  aGPGConfTest,
  oOptions,
  oDebug,
  oDebugAll,
  oDebugLevel,
  oDebugWait,
  oDebugAllowCoreDump,
  oDebugCCIDDriver,
  oDebugLogTid,
  oDebugAssuanLogCats,
  oNoGreeting,
  oNoOptions,
  oHomedir,
  oNoDetach,
  oNoGrab,
  oLogFile,
  oServer,
  oMultiServer,
  oDaemon,
  oBatch,
  oReaderPort,
  oCardTimeout,
  octapiDriver,
  opcscDriver,
  oDisableCCID,
  oDisableOpenSC,
  oDisablePinpad,
  oAllowAdmin,
  oDenyAdmin,
  oDisableApplication,
  oEnablePinpadVarlen,
  oDebugDisableTicker
};



static ARGPARSE_OPTS opts[] = {
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_group (301, N_("@Options:\n ")),

  ARGPARSE_s_n (oServer,"server", N_("run in server mode (foreground)")),
  ARGPARSE_s_n (oMultiServer, "multi-server",
                N_("run in multi server mode (foreground)")),
  ARGPARSE_s_n (oDaemon, "daemon", N_("run in daemon mode (background)")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet", N_("be somewhat more quiet")),
  ARGPARSE_s_n (oSh,	"sh", N_("sh-style command output")),
  ARGPARSE_s_n (oCsh,	"csh", N_("csh-style command output")),
  ARGPARSE_s_s (oOptions, "options", N_("|FILE|read options from FILE")),
  ARGPARSE_s_s (oDebug,	"debug", "@"),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level" ,
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),
  ARGPARSE_s_n (oDebugCCIDDriver, "debug-ccid-driver", "@"),
  ARGPARSE_s_n (oDebugDisableTicker, "debug-disable-ticker", "@"),
  ARGPARSE_s_n (oDebugLogTid, "debug-log-tid", "@"),
  ARGPARSE_p_u (oDebugAssuanLogCats, "debug-assuan-log-cats", "@"),
  ARGPARSE_s_n (oNoDetach, "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_s (oLogFile,  "log-file", N_("|FILE|write a log to FILE")),
  ARGPARSE_s_s (oReaderPort, "reader-port",
                N_("|N|connect to reader at port N")),
  ARGPARSE_s_s (octapiDriver, "ctapi-driver",
                N_("|NAME|use NAME as ct-API driver")),
  ARGPARSE_s_s (opcscDriver, "pcsc-driver",
                N_("|NAME|use NAME as PC/SC driver")),
  ARGPARSE_s_n (oDisableCCID, "disable-ccid",
#ifdef HAVE_LIBUSB
                                    N_("do not use the internal CCID driver")
#else
                                    "@"
#endif
                /* end --disable-ccid */),
  ARGPARSE_s_u (oCardTimeout, "card-timeout",
                N_("|N|disconnect the card after N seconds of inactivity")),

  ARGPARSE_s_n (oDisablePinpad, "disable-pinpad",
                N_("do not use a reader's pinpad")),
  ARGPARSE_ignore (300, "disable-keypad"),

  ARGPARSE_s_n (oAllowAdmin, "allow-admin", "@"),
  ARGPARSE_s_n (oDenyAdmin, "deny-admin",
                N_("deny the use of admin card commands")),
  ARGPARSE_s_s (oDisableApplication, "disable-application", "@"),
  ARGPARSE_s_n (oEnablePinpadVarlen, "enable-pinpad-varlen",
                N_("use variable length input for pinpad")),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_COMMAND_VALUE, "command"  },
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_CARD_IO_VALUE, "cardio"  },
    { DBG_READER_VALUE , "reader"  },
    { 0, NULL }
  };


/* The card driver we use by default for PC/SC.  */
#if defined(HAVE_W32_SYSTEM) || defined(__CYGWIN__)
#define DEFAULT_PCSC_DRIVER "winscard.dll"
#elif defined(__APPLE__)
#define DEFAULT_PCSC_DRIVER "/System/Library/Frameworks/PCSC.framework/PCSC"
#elif defined(__GLIBC__)
#define DEFAULT_PCSC_DRIVER "libpcsclite.so.1"
#else
#define DEFAULT_PCSC_DRIVER "libpcsclite.so"
#endif

/* The timer tick used for housekeeping stuff.  We poll every 500ms to
   let the user immediately know a status change.

   This is not too good for power saving but given that there is no
   easy way to block on card status changes it is the best we can do.
   For PC/SC we could in theory use an extra thread to wait for status
   changes but that requires a native thread because there is no way
   to make the underlying PC/SC card change function block using a Npth
   mechanism.  Given that a native thread could only be used under W32
   we don't do that at all.  */
#define TIMERTICK_INTERVAL_SEC     (0)
#define TIMERTICK_INTERVAL_USEC    (500000)

/* Flag to indicate that a shutdown was requested. */
static int shutdown_pending;

/* It is possible that we are currently running under setuid permissions */
static int maybe_setuid = 1;

/* Flag telling whether we are running as a pipe server.  */
static int pipe_server;

/* Name of the communication socket */
static char *socket_name;
/* Name of the redirected socket or NULL.  */
static char *redir_socket_name;

/* We need to keep track of the server's nonces (these are dummies for
   POSIX systems). */
static assuan_sock_nonce_t socket_nonce;

/* Debug flag to disable the ticker.  The ticker is in fact not
   disabled but it won't perform any ticker specific actions. */
static int ticker_disabled;



static char *create_socket_name (char *standard_name);
static gnupg_fd_t create_server_socket (const char *name,
                                        char **r_redir_name,
                                        assuan_sock_nonce_t *nonce);

static void *start_connection_thread (void *arg);
static void handle_connections (int listen_fd);

/* Pth wrapper function definitions. */
ASSUAN_SYSTEM_NPTH_IMPL;

static int active_connections;


static char *
make_libversion (const char *libname, const char *(*getfnc)(const char*))
{
  const char *s;
  char *result;

  if (maybe_setuid)
    {
      gcry_control (GCRYCTL_INIT_SECMEM, 0, 0);  /* Drop setuid. */
      maybe_setuid = 0;
    }
  s = getfnc (NULL);
  result = xmalloc (strlen (libname) + 1 + strlen (s) + 1);
  strcpy (stpcpy (stpcpy (result, libname), " "), s);
  return result;
}


static const char *
my_strusage (int level)
{
  static char *ver_gcry, *ver_ksba;
  const char *p;

  switch (level)
    {
    case 11: p = "@SCDAEMON@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;
    case 21:
      if (!ver_ksba)
        ver_ksba = make_libversion ("libksba", ksba_check_version);
      p = ver_ksba;
      break;
    case 1:
    case 40: p =  _("Usage: @SCDAEMON@ [options] (-h for help)");
      break;
    case 41: p =  _("Syntax: scdaemon [options] [command [args]]\n"
                    "Smartcard daemon for @GNUPG@\n");
    break;

    default: p = NULL;
    }
  return p;
}


static int
tid_log_callback (unsigned long *rvalue)
{
  int len = sizeof (*rvalue);
  npth_t thread;

  thread = npth_self ();
  if (sizeof (thread) < len)
    len = sizeof (thread);
  memcpy (rvalue, &thread, len);

  return 2; /* Use use hex representation.  */
}


/* Setup the debugging.  With a LEVEL of NULL only the active debug
   flags are propagated to the subsystems.  With LEVEL set, a specific
   set of debug flags is set; thus overriding all flags already
   set. */
static void
set_debug (const char *level)
{
  int numok = (level && digitp (level));
  int numlvl = numok? atoi (level) : 0;

  if (!level)
    ;
  else if (!strcmp (level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE;
  else if (!strcmp (level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE|DBG_COMMAND_VALUE;
  else if (!strcmp (level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE|DBG_COMMAND_VALUE
                 |DBG_CACHE_VALUE|DBG_CARD_IO_VALUE);
  else if (!strcmp (level, "guru") || numok)
    {
      opt.debug = ~0;
      /* Unless the "guru" string has been used we don't want to allow
         hashing debugging.  The rationale is that people tend to
         select the highest debug value and would then clutter their
         disk with debug files which may reveal confidential data.  */
      if (numok)
        opt.debug &= ~(DBG_HASHING_VALUE);
    }
  else
    {
      log_error (_("invalid debug-level '%s' given\n"), level);
      scd_exit(2);
    }


  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug && opt.quiet)
    opt.quiet = 0;

  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}



static void
cleanup (void)
{
  if (socket_name && *socket_name)
    {
      char *name;
      char *p;

      name = redir_socket_name? redir_socket_name : socket_name;

      gnupg_remove (name);
      p = strrchr (name, '/');
      if (p)
        {
          *p = 0;
          rmdir (name);
          *p = '/';
        }
      *socket_name = 0;
    }
}



int
main (int argc, char **argv )
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  FILE *configfp = NULL;
  char *configname = NULL;
  const char *shell;
  unsigned int configlineno;
  int parse_debug = 0;
  const char *debug_level = NULL;
  int default_config =1;
  int greeting = 0;
  int nogreeting = 0;
  int multi_server = 0;
  int is_daemon = 0;
  int nodetach = 0;
  int csh_style = 0;
  char *logfile = NULL;
  int debug_wait = 0;
  int gpgconf_list = 0;
  const char *config_filename = NULL;
  int allow_coredump = 0;
  struct assuan_malloc_hooks malloc_hooks;
  int res;
  npth_t pipecon_handler;

  early_system_init ();
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
  /* Please note that we may running SUID(ROOT), so be very CAREFUL
     when adding any stuff between here and the call to INIT_SECMEM()
     somewhere after the option parsing */
  log_set_prefix ("scdaemon", 1|4);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  npth_init ();

  /* Check that the libraries are suitable.  Do it here because
     the option parsing may need services of the library */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    {
      log_fatal (_("%s is too old (need %s, have %s)\n"), "libgcrypt",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
    }

  ksba_set_malloc_hooks (gcry_malloc, gcry_realloc, gcry_free);

  malloc_hooks.malloc = gcry_malloc;
  malloc_hooks.realloc = gcry_realloc;
  malloc_hooks.free = gcry_free;
  assuan_set_malloc_hooks (&malloc_hooks);
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  assuan_sock_init ();
  setup_libassuan_logging (&opt.debug);

  setup_libgcrypt_logging ();
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  disable_core_dumps ();

  /* Set default options. */
  opt.allow_admin = 1;
  opt.pcsc_driver = DEFAULT_PCSC_DRIVER;

  shell = getenv ("SHELL");
  if (shell && strlen (shell) >= 3 && !strcmp (shell+strlen (shell)-3, "csh") )
    csh_style = 1;

  opt.homedir = default_homedir ();

  /* Check whether we have a config file on the commandline */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
      else if (pargs.r_opt == oOptions)
        { /* yes there is one, so we do not try the default one, but
	     read the option file when it is encountered at the
	     commandline */
          default_config = 0;
	}
	else if (pargs.r_opt == oNoOptions)
          default_config = 0; /* --no-options */
	else if (pargs.r_opt == oHomedir)
          opt.homedir = pargs.r.ret_str;
    }

  /* initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /*
     Now we are working under our real uid
  */


  if (default_config)
    configname = make_filename (opt.homedir, SCDAEMON_NAME EXTSEP_S "conf",
                                NULL );


  argc = orig_argc;
  argv = orig_argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags=  1;  /* do not remove the args */
 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            {
              if( parse_debug )
                log_info (_("Note: no default option file '%s'\n"),
                          configname );
	    }
          else
            {
              log_error (_("option file '%s': %s\n"),
                         configname, strerror(errno) );
              exit(2);
	    }
          xfree (configname);
          configname = NULL;
	}
      if (parse_debug && configname )
        log_info (_("reading options from '%s'\n"), configname );
      default_config = 0;
    }

  while (optfile_parse( configfp, configname, &configlineno, &pargs, opts) )
    {
      switch (pargs.r_opt)
        {
        case aGPGConfList: gpgconf_list = 1; break;
        case aGPGConfTest: gpgconf_list = 2; break;
        case oQuiet: opt.quiet = 1; break;
        case oVerbose: opt.verbose++; break;
        case oBatch: opt.batch=1; break;

        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
          break;
        case oDebugAll: opt.debug = ~0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: debug_wait = pargs.r.ret_int; break;
        case oDebugAllowCoreDump:
          enable_core_dumps ();
          allow_coredump = 1;
          break;
        case oDebugCCIDDriver:
#ifdef HAVE_LIBUSB
          ccid_set_debug_level (ccid_set_debug_level (-1)+1);
#endif /*HAVE_LIBUSB*/
          break;
        case oDebugDisableTicker: ticker_disabled = 1; break;
        case oDebugLogTid:
          log_set_pid_suffix_cb (tid_log_callback);
          break;
        case oDebugAssuanLogCats:
          set_libassuan_log_cats (pargs.r.ret_ulong);
          break;

        case oOptions:
          /* config files may not be nested (silently ignore them) */
          if (!configfp)
            {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
          break;
        case oNoGreeting: nogreeting = 1; break;
        case oNoVerbose: opt.verbose = 0; break;
        case oNoOptions: break; /* no-options */
        case oHomedir: opt.homedir = pargs.r.ret_str; break;
        case oNoDetach: nodetach = 1; break;
        case oLogFile: logfile = pargs.r.ret_str; break;
        case oCsh: csh_style = 1; break;
        case oSh: csh_style = 0; break;
        case oServer: pipe_server = 1; break;
        case oMultiServer: pipe_server = 1; multi_server = 1; break;
        case oDaemon: is_daemon = 1; break;

        case oReaderPort: opt.reader_port = pargs.r.ret_str; break;
        case octapiDriver: opt.ctapi_driver = pargs.r.ret_str; break;
        case opcscDriver: opt.pcsc_driver = pargs.r.ret_str; break;
        case oDisableCCID: opt.disable_ccid = 1; break;
        case oDisableOpenSC: break;

        case oDisablePinpad: opt.disable_pinpad = 1; break;

        case oAllowAdmin: /* Dummy because allow is now the default.  */
          break;
        case oDenyAdmin: opt.allow_admin = 0; break;

        case oCardTimeout: opt.card_timeout = pargs.r.ret_ulong; break;

        case oDisableApplication:
          add_to_strlist (&opt.disabled_applications, pargs.r.ret_str);
          break;

	case oEnablePinpadVarlen: opt.enable_pinpad_varlen = 1; break;

        default:
          pargs.err = configfp? ARGPARSE_PRINT_WARNING:ARGPARSE_PRINT_ERROR;
          break;
	}
    }
  if (configfp)
    {
      fclose( configfp );
      configfp = NULL;
      /* Keep a copy of the config name for use by --gpgconf-list. */
      config_filename = configname;
      configname = NULL;
      goto next_pass;
    }
  xfree (configname);
  configname = NULL;
  if (log_get_errorcount(0))
    exit(2);
  if (nogreeting )
    greeting = 0;

  if (greeting)
    {
      es_fprintf (es_stderr, "%s %s; %s\n",
                  strusage(11), strusage(13), strusage(14) );
      es_fprintf (es_stderr, "%s\n", strusage(15) );
    }
#ifdef IS_DEVELOPMENT_VERSION
  log_info ("NOTE: this is a development version!\n");
#endif

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
    }

  if (atexit (cleanup))
    {
      log_error ("atexit failed\n");
      cleanup ();
      exit (1);
    }

  set_debug (debug_level);

  initialize_module_command ();

  if (gpgconf_list == 2)
    scd_exit (0);
  if (gpgconf_list)
    {
      /* List options and default values in the GPG Conf format.  */
      char *filename = NULL;
      char *filename_esc;

      if (config_filename)
	filename = xstrdup (config_filename);
      else
        filename = make_filename (opt.homedir, SCDAEMON_NAME EXTSEP_S "conf",
                                  NULL);
      filename_esc = percent_escape (filename, NULL);

      es_printf ("%s-%s.conf:%lu:\"%s\n",
                 GPGCONF_NAME, SCDAEMON_NAME,
                 GC_OPT_FLAG_DEFAULT, filename_esc);
      xfree (filename_esc);
      xfree (filename);

      es_printf ("verbose:%lu:\n"
                 "quiet:%lu:\n"
                 "debug-level:%lu:\"none:\n"
                 "log-file:%lu:\n",
                 GC_OPT_FLAG_NONE,
                 GC_OPT_FLAG_NONE,
                 GC_OPT_FLAG_DEFAULT,
                 GC_OPT_FLAG_NONE );

      es_printf ("reader-port:%lu:\n", GC_OPT_FLAG_NONE );
      es_printf ("ctapi-driver:%lu:\n", GC_OPT_FLAG_NONE );
      es_printf ("pcsc-driver:%lu:\"%s:\n",
              GC_OPT_FLAG_DEFAULT, DEFAULT_PCSC_DRIVER );
#ifdef HAVE_LIBUSB
      es_printf ("disable-ccid:%lu:\n", GC_OPT_FLAG_NONE );
#endif
      es_printf ("deny-admin:%lu:\n", GC_OPT_FLAG_NONE );
      es_printf ("disable-pinpad:%lu:\n", GC_OPT_FLAG_NONE );
      es_printf ("card-timeout:%lu:%d:\n", GC_OPT_FLAG_DEFAULT, 0);
      es_printf ("enable-pinpad-varlen:%lu:\n", GC_OPT_FLAG_NONE );

      scd_exit (0);
    }

  /* Now start with logging to a file if this is desired.  */
  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
    }

  if (debug_wait && pipe_server)
    {
      log_debug ("waiting for debugger - my pid is %u .....\n",
                 (unsigned int)getpid());
      gnupg_sleep (debug_wait);
      log_debug ("... okay\n");
    }

  if (pipe_server)
    {
      /* This is the simple pipe based server */
      ctrl_t ctrl;
      npth_attr_t tattr;
      int fd = -1;

#ifndef HAVE_W32_SYSTEM
      {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction (SIGPIPE, &sa, NULL);
      }
#endif

      /* If --debug-allow-core-dump has been given we also need to
         switch the working directory to a place where we can actually
         write. */
      if (allow_coredump)
        {
          if (chdir("/tmp"))
            log_debug ("chdir to '/tmp' failed: %s\n", strerror (errno));
          else
            log_debug ("changed working directory to '/tmp'\n");
        }

      /* In multi server mode we need to listen on an additional
         socket.  Create that socket now before starting the handler
         for the pipe connection.  This allows that handler to send
         back the name of that socket. */
      if (multi_server)
        {
          socket_name = create_socket_name (SCDAEMON_SOCK_NAME);
          fd = FD2INT(create_server_socket (socket_name,
                                            &redir_socket_name, &socket_nonce));
        }

      res = npth_attr_init (&tattr);
      if (res)
	{
          log_error ("error allocating thread attributes: %s\n",
                     strerror (res));
          scd_exit (2);
        }
      npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

      ctrl = xtrycalloc (1, sizeof *ctrl);
      if ( !ctrl )
        {
          log_error ("error allocating connection control data: %s\n",
                     strerror (errno) );
          scd_exit (2);
        }
      ctrl->thread_startup.fd = GNUPG_INVALID_FD;
      res = npth_create (&pipecon_handler, &tattr, start_connection_thread, ctrl);
      if (res)
        {
          log_error ("error spawning pipe connection handler: %s\n",
                     strerror (res) );
          xfree (ctrl);
          scd_exit (2);
        }
      npth_setname_np (pipecon_handler, "pipe-connection");
      npth_attr_destroy (&tattr);

      /* We run handle_connection to wait for the shutdown signal and
         to run the ticker stuff.  */
      handle_connections (fd);
      if (fd != -1)
        close (fd);
    }
  else if (!is_daemon)
    {
      log_info (_("please use the option '--daemon'"
                  " to run the program in the background\n"));
    }
  else
    { /* Regular server mode */
      int fd;
#ifndef HAVE_W32_SYSTEM
      pid_t pid;
      int i;
#endif

      /* Create the socket.  */
      socket_name = create_socket_name (SCDAEMON_SOCK_NAME);
      fd = FD2INT (create_server_socket (socket_name,
                                         &redir_socket_name, &socket_nonce));


      fflush (NULL);
#ifdef HAVE_W32_SYSTEM
      (void)csh_style;
      (void)nodetach;
#else
      pid = fork ();
      if (pid == (pid_t)-1)
        {
          log_fatal ("fork failed: %s\n", strerror (errno) );
          exit (1);
        }
      else if (pid)
        { /* we are the parent */
          char *infostr;

          close (fd);

          /* create the info string: <name>:<pid>:<protocol_version> */
          if (gpgrt_asprintf (&infostr, "SCDAEMON_INFO=%s:%lu:1",
                              socket_name, (ulong) pid) < 0)
            {
              log_error ("out of core\n");
              kill (pid, SIGTERM);
              exit (1);
            }
          *socket_name = 0; /* don't let cleanup() remove the socket -
                               the child should do this from now on */
          if (argc)
            { /* run the program given on the commandline */
              if (putenv (infostr))
                {
                  log_error ("failed to set environment: %s\n",
                             strerror (errno) );
                  kill (pid, SIGTERM );
                  exit (1);
                }
              execvp (argv[0], argv);
              log_error ("failed to run the command: %s\n", strerror (errno));
              kill (pid, SIGTERM);
              exit (1);
            }
          else
            {
              /* Print the environment string, so that the caller can use
                 shell's eval to set it */
              if (csh_style)
                {
                  *strchr (infostr, '=') = ' ';
                  es_printf ( "setenv %s;\n", infostr);
                }
              else
                {
                  es_printf ( "%s; export SCDAEMON_INFO;\n", infostr);
                }
              xfree (infostr);
              exit (0);
            }
          /* NOTREACHED */
        } /* end parent */

      /* This is the child. */

      /* Detach from tty and put process into a new session. */
      if (!nodetach )
        {
          /* Close stdin, stdout and stderr unless it is the log stream. */
          for (i=0; i <= 2; i++)
            {
              if ( log_test_fd (i) && i != fd)
                close (i);
            }
          if (setsid() == -1)
            {
              log_error ("setsid() failed: %s\n", strerror(errno) );
              cleanup ();
              exit (1);
            }
        }

      {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset (&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction (SIGPIPE, &sa, NULL);
      }

      if (chdir("/"))
        {
          log_error ("chdir to / failed: %s\n", strerror (errno));
          exit (1);
        }

#endif /*!HAVE_W32_SYSTEM*/

      handle_connections (fd);

      close (fd);
    }

  return 0;
}

void
scd_exit (int rc)
{
  apdu_prepare_exit ();
#if 0
#warning no update_random_seed_file
  update_random_seed_file();
#endif
#if 0
  /* at this time a bit annoying */
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
#endif
  gcry_control (GCRYCTL_TERM_SECMEM );
  rc = rc? rc : log_get_errorcount(0)? 2 : 0;
  exit (rc);
}


static void
scd_init_default_ctrl (ctrl_t ctrl)
{
  (void)ctrl;
}

static void
scd_deinit_default_ctrl (ctrl_t ctrl)
{
  if (!ctrl)
    return;
  xfree (ctrl->in_data.value);
  ctrl->in_data.value = NULL;
  ctrl->in_data.valuelen = 0;
}


/* Return the name of the socket to be used to connect to this
   process.  If no socket is available, return NULL. */
const char *
scd_get_socket_name ()
{
  if (socket_name && *socket_name)
    return socket_name;
  return NULL;
}


#ifndef HAVE_W32_SYSTEM
static void
handle_signal (int signo)
{
  switch (signo)
    {
    case SIGHUP:
      log_info ("SIGHUP received - "
                "re-reading configuration and resetting cards\n");
/*       reread_configuration (); */
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      app_dump_state ();
      break;

    case SIGUSR2:
      log_info ("SIGUSR2 received - no action defined\n");
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %i running threads\n",
                  active_connections);
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", strusage(11), strusage(13) );
          cleanup ();
          scd_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", strusage(11), strusage(13));
      cleanup ();
      scd_exit (0);
      break;

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}
#endif /*!HAVE_W32_SYSTEM*/


static void
handle_tick (void)
{
  if (!ticker_disabled)
    scd_update_reader_status_file ();
}


/* Create a name for the socket.  We check for valid characters as
   well as against a maximum allowed length for a unix domain socket
   is done.  The function terminates the process in case of an error.
   Retunrs: Pointer to an allcoated string with the absolute name of
   the socket used.  */
static char *
create_socket_name (char *standard_name)
{
  char *name;

  name = make_filename (opt.homedir, standard_name, NULL);
  if (strchr (name, PATHSEP_C))
    {
      log_error (("'%s' are not allowed in the socket name\n"), PATHSEP_S);
      scd_exit (2);
    }
  return name;
}



/* Create a Unix domain socket with NAME.  Returns the file descriptor
   or terminates the process in case of an error.  If the socket has
   been redirected the name of the real socket is stored as a malloced
   string at R_REDIR_NAME. */
static gnupg_fd_t
create_server_socket (const char *name, char **r_redir_name,
                      assuan_sock_nonce_t *nonce)
{
  struct sockaddr *addr;
  struct sockaddr_un *unaddr;
  socklen_t len;
  gnupg_fd_t fd;
  int rc;

  xfree (*r_redir_name);
  *r_redir_name = NULL;

  fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0);
  if (fd == GNUPG_INVALID_FD)
    {
      log_error (_("can't create socket: %s\n"), strerror (errno));
      scd_exit (2);
    }

  unaddr = xmalloc (sizeof (*unaddr));
  addr = (struct sockaddr*)unaddr;

#if ASSUAN_VERSION_NUMBER >= 0x020104 /* >= 2.1.4 */
  {
    int redirected;

    if (assuan_sock_set_sockaddr_un (name, addr, &redirected))
      {
        if (errno == ENAMETOOLONG)
          log_error (_("socket name '%s' is too long\n"), name);
        else
          log_error ("error preparing socket '%s': %s\n",
                     name, gpg_strerror (gpg_error_from_syserror ()));
        scd_exit (2);
      }
    if (redirected)
      {
        *r_redir_name = xstrdup (unaddr->sun_path);
        if (opt.verbose)
          log_info ("redirecting socket '%s' to '%s'\n", name, *r_redir_name);
      }
  }
#else /* Assuan < 2.1.4 */
  memset (unaddr, 0, sizeof *unaddr);
  unaddr->sun_family = AF_UNIX;
  if (strlen (name) + 1 >= sizeof (unaddr->sun_path))
    {
      log_error (_("socket name '%s' is too long\n"), name);
      scd_exit (2);
    }
  strcpy (unaddr->sun_path, name);
#endif /* Assuan < 2.1.4 */

  len = SUN_LEN (unaddr);

  rc = assuan_sock_bind (fd, addr, len);
  if (rc == -1 && errno == EADDRINUSE)
    {
      gnupg_remove (unaddr->sun_path);
      rc = assuan_sock_bind (fd, addr, len);
    }
  if (rc != -1
      && (rc=assuan_sock_get_nonce (addr, len, nonce)))
    log_error (_("error getting nonce for the socket\n"));
 if (rc == -1)
    {
      log_error (_("error binding socket to '%s': %s\n"),
		 unaddr->sun_path,
                 gpg_strerror (gpg_error_from_syserror ()));
      assuan_sock_close (fd);
      scd_exit (2);
    }

  if (listen (FD2INT(fd), 5 ) == -1)
    {
      log_error (_("listen() failed: %s\n"),
                 gpg_strerror (gpg_error_from_syserror ()));
      assuan_sock_close (fd);
      scd_exit (2);
    }

  if (opt.verbose)
    log_info (_("listening on socket '%s'\n"), unaddr->sun_path);

  return fd;
}



/* This is the standard connection thread's main function.  */
static void *
start_connection_thread (void *arg)
{
  ctrl_t ctrl = arg;

  if (ctrl->thread_startup.fd != GNUPG_INVALID_FD
      && assuan_sock_check_nonce (ctrl->thread_startup.fd, &socket_nonce))
    {
      log_info (_("error reading nonce on fd %d: %s\n"),
                FD2INT(ctrl->thread_startup.fd), strerror (errno));
      assuan_sock_close (ctrl->thread_startup.fd);
      xfree (ctrl);
      return NULL;
    }

  scd_init_default_ctrl (ctrl);
  if (opt.verbose)
    log_info (_("handler for fd %d started\n"),
              FD2INT(ctrl->thread_startup.fd));

  /* If this is a pipe server, we request a shutdown if the command
     handler asked for it.  With the next ticker event and given that
     no other connections are running the shutdown will then
     happen.  */
  if (scd_command_handler (ctrl, FD2INT(ctrl->thread_startup.fd))
      && pipe_server)
    shutdown_pending = 1;

  if (opt.verbose)
    log_info (_("handler for fd %d terminated\n"),
              FD2INT (ctrl->thread_startup.fd));

  scd_deinit_default_ctrl (ctrl);
  xfree (ctrl);
  return NULL;
}


/* Connection handler loop.  Wait for connection requests and spawn a
   thread after accepting a connection.  LISTEN_FD is allowed to be -1
   in which case this code will only do regular timeouts and handle
   signals. */
static void
handle_connections (int listen_fd)
{
  npth_attr_t tattr;
  struct sockaddr_un paddr;
  socklen_t plen;
  fd_set fdset, read_fdset;
  int ret;
  int fd;
  int nfd;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int saved_errno;
#ifndef HAVE_W32_SYSTEM
  int signo;
#endif

  ret = npth_attr_init(&tattr);
  /* FIXME: Check error.  */
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_DETACHED);

#ifndef HAVE_W32_SYSTEM
  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();
#endif

  FD_ZERO (&fdset);
  nfd = 0;
  if (listen_fd != -1)
    {
      FD_SET (listen_fd, &fdset);
      nfd = listen_fd;
    }

  npth_clock_gettime (&curtime);
  timeout.tv_sec = TIMERTICK_INTERVAL_SEC;
  timeout.tv_nsec = TIMERTICK_INTERVAL_USEC * 1000;
  npth_timeradd (&curtime, &timeout, &abstime);
  /* We only require abstime here.  The others will be reused.  */

  for (;;)
    {
      if (shutdown_pending)
        {
          if (active_connections == 0)
            break; /* ready */

          /* Do not accept anymore connections but wait for existing
             connections to terminate. We do this by clearing out all
             file descriptors to wait for, so that the select will be
             used to just wait on a signal or timeout event. */
          FD_ZERO (&fdset);
          listen_fd = -1;
	}

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Timeout.  */
	  handle_tick ();
	  timeout.tv_sec = TIMERTICK_INTERVAL_SEC;
	  timeout.tv_nsec = TIMERTICK_INTERVAL_USEC * 1000;
	  npth_timeradd (&curtime, &timeout, &abstime);
	}
      npth_timersub (&abstime, &curtime, &timeout);

      /* POSIX says that fd_set should be implemented as a structure,
         thus a simple assignment is fine to copy the entire set.  */
      read_fdset = fdset;

#ifndef HAVE_W32_SYSTEM
      ret = npth_pselect (nfd+1, &read_fdset, NULL, NULL, &timeout, npth_sigev_sigmask());
      saved_errno = errno;

      while (npth_sigev_get_pending(&signo))
	handle_signal (signo);
#else
      ret = npth_eselect (nfd+1, &read_fdset, NULL, NULL, &timeout, NULL, NULL);
      saved_errno = errno;
#endif

      if (ret == -1 && saved_errno != EINTR)
	{
          log_error (_("npth_pselect failed: %s - waiting 1s\n"),
                     strerror (saved_errno));
          npth_sleep (1);
	  continue;
	}

      if (ret <= 0)
	/* Timeout.  Will be handled when calculating the next timeout.  */
	continue;

      if (listen_fd != -1 && FD_ISSET (listen_fd, &read_fdset))
	{
          ctrl_t ctrl;

          plen = sizeof paddr;
	  fd = npth_accept (listen_fd, (struct sockaddr *)&paddr, &plen);
	  if (fd == -1)
	    {
	      log_error ("accept failed: %s\n", strerror (errno));
	    }
          else if ( !(ctrl = xtrycalloc (1, sizeof *ctrl)) )
            {
              log_error ("error allocating connection control data: %s\n",
                         strerror (errno) );
              close (fd);
            }
          else
            {
              char threadname[50];
	      npth_t thread;

              snprintf (threadname, sizeof threadname-1, "conn fd=%d", fd);
              threadname[sizeof threadname -1] = 0;
              ctrl->thread_startup.fd = INT2FD (fd);
              ret = npth_create (&thread, &tattr, start_connection_thread, ctrl);
	      if (ret)
                {
                  log_error ("error spawning connection handler: %s\n",
                             strerror (ret));
                  xfree (ctrl);
                  close (fd);
                }
              else
		npth_setname_np (thread, threadname);
            }
          fd = -1;
	}
    }

  cleanup ();
  log_info (_("%s %s stopped\n"), strusage(11), strusage(13));
  npth_attr_destroy (&tattr);
}
