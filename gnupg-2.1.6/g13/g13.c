/* g13.c - Disk Key management with GnuPG
 * Copyright (C) 2009 Free Software Foundation, Inc.
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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <npth.h>

#include "g13.h"

#include <gcrypt.h>
#include <assuan.h>

#include "i18n.h"
#include "sysutils.h"
#include "gc-opt-flags.h"
#include "asshelp.h"
#include "../common/init.h"
#include "keyblob.h"
#include "server.h"
#include "runner.h"
#include "create.h"
#include "mount.h"
#include "mountinfo.h"


enum cmd_and_opt_values {
  aNull = 0,
  oQuiet	= 'q',
  oVerbose	= 'v',
  oRecipient	= 'r',

  aGPGConfList  = 500,
  aGPGConfTest,
  aCreate,
  aMount,
  aUmount,
  aServer,

  oOptions,
  oDebug,
  oDebugLevel,
  oDebugAll,
  oDebugNone,
  oDebugWait,
  oDebugAllowCoreDump,
  oLogFile,
  oNoLogFile,
  oAuditLog,

  oOutput,

  oAgentProgram,
  oGpgProgram,

  oDisplay,
  oTTYname,
  oTTYtype,
  oLCctype,
  oLCmessages,
  oXauthority,

  oStatusFD,
  oLoggerFD,

  oNoVerbose,
  oNoSecmemWarn,
  oNoGreeting,
  oNoTTY,
  oNoOptions,
  oHomedir,
  oWithColons,
  oDryRun,
  oNoDetach,

  oNoRandomSeedFile,
  oFakedSystemTime
 };


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aCreate, "create", N_("Create a new file system container")),
  ARGPARSE_c (aMount,  "mount",  N_("Mount a file system container") ),
  ARGPARSE_c (aUmount, "umount", N_("Unmount a file system container") ),
  ARGPARSE_c (aServer, "server", N_("Run in server mode")),

  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@"),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@"),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	"quiet",  N_("be somewhat more quiet")),
  ARGPARSE_s_n (oNoTTY, "no-tty", N_("don't use the terminal at all")),
  ARGPARSE_s_n (oNoDetach, "no-detach", N_("do not detach from the console")),
  ARGPARSE_s_s (oLogFile, "log-file",  N_("|FILE|write log output to FILE")),
  ARGPARSE_s_n (oNoLogFile, "no-log-file", "@"),
  ARGPARSE_s_i (oLoggerFD, "logger-fd", "@"),

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),

  ARGPARSE_s_s (oOptions, "options", N_("|FILE|read options from FILE")),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level",
                N_("|LEVEL|set the debugging level to LEVEL")),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugNone, "debug-none", "@"),
  ARGPARSE_s_i (oDebugWait, "debug-wait", "@"),
  ARGPARSE_s_n (oDebugAllowCoreDump, "debug-allow-core-dump", "@"),

  ARGPARSE_s_i (oStatusFD, "status-fd",
                N_("|FD|write status info to this FD")),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
  )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " blurb\n"
                          " blurb\n")),

  /* Hidden options. */
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),
  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_s_n (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oGpgProgram, "gpg-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display", "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname", "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype", "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype", "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages", "@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),

  /* Command aliases.  */

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_MOUNT_VALUE  , "mount"  },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_IPC_VALUE    , "ipc"     },
    { 0, NULL }
  };


/* The timer tick interval used by the idle task.  */
#define TIMERTICK_INTERVAL_SEC     (1)


/* Global variable to keep an error count. */
int g13_errors_seen = 0;

/* It is possible that we are currently running under setuid permissions.  */
static int maybe_setuid = 1;

/* Helper to implement --debug-level and --debug.  */
static const char *debug_level;
static unsigned int debug_value;

/* Flag to indicate that a shutdown was requested.  */
static int shutdown_pending;

/* The thread id of the idle task.  */
static npth_t idle_task_thread;



static void set_cmd (enum cmd_and_opt_values *ret_cmd,
                     enum cmd_and_opt_values new_cmd );

static void emergency_cleanup (void);
static void start_idle_task (void);
static void join_idle_task (void);


/* Begin NPth wrapper functions. */
ASSUAN_SYSTEM_NPTH_IMPL;


static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case 11: p = "@G13@ (@GNUPG@)";
      break;
    case 13: p = VERSION; break;
    case 17: p = PRINTABLE_OS_NAME; break;
    case 19: p = _("Please report bugs to <" PACKAGE_BUGREPORT ">.\n");
      break;
    case 1:
    case 40: p = _("Usage: @G13@ [options] [files] (-h for help)");
      break;
    case 41:
      p = _("Syntax: @G13@ [options] [files]\n"
            "Create, mount or unmount an encrypted file system container\n");
      break;

    case 31: p = "\nHome: "; break;
    case 32: p = opt.homedir; break;

    default: p = NULL; break;
    }
  return p;
}


static void
wrong_args (const char *text)
{
  fprintf (stderr, _("usage: %s [options] "), G13_NAME);
  fputs (text, stderr);
  putc ('\n', stderr);
  g13_exit (2);
}


/* Setup the debugging.  With a DEBUG_LEVEL of NULL only the active
   debug flags are propagated to the subsystems.  With DEBUG_LEVEL
   set, a specific set of debug flags is set; and individual debugging
   flags will be added on top.  */
static void
set_debug (void)
{
  int numok = (debug_level && digitp (debug_level));
  int numlvl = numok? atoi (debug_level) : 0;

  if (!debug_level)
    ;
  else if (!strcmp (debug_level, "none") || (numok && numlvl < 1))
    opt.debug = 0;
  else if (!strcmp (debug_level, "basic") || (numok && numlvl <= 2))
    opt.debug = DBG_IPC_VALUE|DBG_MOUNT_VALUE;
  else if (!strcmp (debug_level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_IPC_VALUE|DBG_MOUNT_VALUE;
  else if (!strcmp (debug_level, "expert") || (numok && numlvl <= 8))
    opt.debug = (DBG_IPC_VALUE|DBG_MOUNT_VALUE|DBG_CRYPTO_VALUE);
  else if (!strcmp (debug_level, "guru") || numok)
    {
      opt.debug = ~0;
      /* if (numok) */
      /*   opt.debug &= ~(DBG_HASHING_VALUE); */
    }
  else
    {
      log_error (_("invalid debug-level '%s' given\n"), debug_level);
      g13_exit(2);
    }

  opt.debug |= debug_value;

  if (opt.debug && !opt.verbose)
    opt.verbose = 1;
  if (opt.debug)
    opt.quiet = 0;

  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}



static void
set_cmd (enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd)
{
  enum cmd_and_opt_values cmd = *ret_cmd;

  if (!cmd || cmd == new_cmd)
    cmd = new_cmd;
  else
    {
      log_error (_("conflicting commands\n"));
      g13_exit (2);
    }

  *ret_cmd = cmd;
}


int
main ( int argc, char **argv)
{
  ARGPARSE_ARGS pargs;
  int orig_argc;
  char **orig_argv;
  gpg_error_t err = 0;
  /* const char *fname; */
  int may_coredump;
  FILE *configfp = NULL;
  char *configname = NULL;
  unsigned configlineno;
  int parse_debug = 0;
  int no_more_options = 0;
  int default_config =1;
  char *logfile = NULL;
  int greeting = 0;
  int nogreeting = 0;
  /* int debug_wait = 0; */
  int use_random_seed = 1;
  /* int nodetach = 0; */
  /* int nokeysetup = 0; */
  enum cmd_and_opt_values cmd = 0;
  struct server_control_s ctrl;
  strlist_t recipients = NULL;

  /*mtrace();*/

  early_system_init ();
  gnupg_reopen_std (G13_NAME);
  set_strusage (my_strusage);
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  log_set_prefix (G13_NAME, 1);

  /* Make sure that our subsystems are ready.  */
  i18n_init ();
  init_common_subsystems (&argc, &argv);

  npth_init ();

  /* Check that the Libgcrypt is suitable.  */
  if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
    log_fatal (_("%s is too old (need %s, have %s)\n"), "libgcrypt",
               NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );

  /* Take extra care of the random pool.  */
  gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

  may_coredump = disable_core_dumps ();

  gnupg_init_signals (0, emergency_cleanup);

  dotlock_create (NULL, 0); /* Register locking cleanup.  */

  opt.session_env = session_env_new ();
  if (!opt.session_env)
    log_fatal ("error allocating session environment block: %s\n",
               strerror (errno));

  opt.homedir = default_homedir ();

  /* First check whether we have a config file on the commandline.  */
  orig_argc = argc;
  orig_argv = argv;
  pargs.argc = &argc;
  pargs.argv = &argv;
  pargs.flags= 1|(1<<6);  /* Do not remove the args, ignore version.  */
  while (arg_parse( &pargs, opts))
    {
      if (pargs.r_opt == oDebug || pargs.r_opt == oDebugAll)
        parse_debug++;
      else if (pargs.r_opt == oOptions)
        { /* Yes, there is one, so we do not try the default one but
             read the config file when it is encountered at the
             commandline.  */
          default_config = 0;
	}
      else if (pargs.r_opt == oNoOptions)
        default_config = 0; /* --no-options */
      else if (pargs.r_opt == oHomedir)
        opt.homedir = pargs.r.ret_str;
    }

  /* Initialize the secure memory. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  maybe_setuid = 0;

  /*
     Now we are now working under our real uid
  */

  /* Setup malloc hooks. */
  {
    struct assuan_malloc_hooks malloc_hooks;

    malloc_hooks.malloc = gcry_malloc;
    malloc_hooks.realloc = gcry_realloc;
    malloc_hooks.free = gcry_free;
    assuan_set_malloc_hooks (&malloc_hooks);
  }

  /* Prepare libassuan.  */
  assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
  assuan_set_system_hooks (ASSUAN_SYSTEM_NPTH);
  setup_libassuan_logging (&opt.debug);

  /* Setup a default control structure for command line mode.  */
  memset (&ctrl, 0, sizeof ctrl);
  g13_init_default_ctrl (&ctrl);
  ctrl.no_server = 1;
  ctrl.status_fd = -1; /* No status output. */

  /* Set the default option file */
  if (default_config )
    configname = make_filename (opt.homedir, G13_NAME".conf", NULL);

  argc        = orig_argc;
  argv        = orig_argv;
  pargs.argc  = &argc;
  pargs.argv  = &argv;
  pargs.flags =  1;  /* Do not remove the args.  */

 next_pass:
  if (configname)
    {
      configlineno = 0;
      configfp = fopen (configname, "r");
      if (!configfp)
        {
          if (default_config)
            {
              if (parse_debug)
                log_info (_("NOTE: no default option file '%s'\n"), configname);
            }
          else
            {
              log_error (_("option file '%s': %s\n"),
                         configname, strerror(errno));
              g13_exit(2);
            }
          xfree (configname);
          configname = NULL;
        }
      if (parse_debug && configname)
        log_info (_("reading options from '%s'\n"), configname);
      default_config = 0;
    }

  while (!no_more_options
         && optfile_parse (configfp, configname, &configlineno, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
	case aGPGConfList:
	case aGPGConfTest:
          set_cmd (&cmd, pargs.r_opt);
          nogreeting = 1;
          /* nokeysetup = 1; */
          break;

        case aServer:
        case aMount:
        case aUmount:
          /* nokeysetup = 1; */
        case aCreate:
          set_cmd (&cmd, pargs.r_opt);
          break;

        case oOutput: opt.outfile = pargs.r.ret_str; break;

        case oQuiet: opt.quiet = 1; break;
        case oNoGreeting: nogreeting = 1; break;
        case oNoTTY:  break;

        case oDryRun: opt.dry_run = 1; break;

        case oVerbose:
          opt.verbose++;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;
        case oNoVerbose:
          opt.verbose = 0;
          gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
          break;

        case oLogFile: logfile = pargs.r.ret_str; break;
        case oNoLogFile: logfile = NULL; break;

        case oNoDetach: /*nodetach = 1; */break;

        case oDebug:
          if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
            {
              pargs.r_opt = ARGPARSE_INVALID_ARG;
              pargs.err = ARGPARSE_PRINT_ERROR;
            }
            break;
        case oDebugAll: debug_value = ~0; break;
        case oDebugNone: debug_value = 0; break;
        case oDebugLevel: debug_level = pargs.r.ret_str; break;
        case oDebugWait: /*debug_wait = pargs.r.ret_int; */break;
        case oDebugAllowCoreDump:
          may_coredump = enable_core_dumps ();
          break;

        case oStatusFD: ctrl.status_fd = pargs.r.ret_int; break;
        case oLoggerFD: log_set_fd (pargs.r.ret_int ); break;

        case oNoOptions: break; /* no-options */
        case oOptions:
          /* Config files may not be nested (silently ignore them).  */
          if (!configfp)
            {
              xfree(configname);
              configname = xstrdup (pargs.r.ret_str);
              goto next_pass;
	    }
          break;

        case oHomedir: opt.homedir = pargs.r.ret_str; break;

        case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
        case oGpgProgram: opt.gpg_program = pargs.r.ret_str;  break;
        case oDisplay: opt.display = xstrdup (pargs.r.ret_str); break;
        case oTTYname: opt.ttyname = xstrdup (pargs.r.ret_str); break;
        case oTTYtype: opt.ttytype = xstrdup (pargs.r.ret_str); break;
        case oLCctype: opt.lc_ctype = xstrdup (pargs.r.ret_str); break;
        case oLCmessages: opt.lc_messages = xstrdup (pargs.r.ret_str); break;
        case oXauthority: opt.xauthority = xstrdup (pargs.r.ret_str); break;

        case oFakedSystemTime:
          {
            time_t faked_time = isotime2epoch (pargs.r.ret_str);
            if (faked_time == (time_t)(-1))
              faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
            gnupg_set_time (faked_time, 0);
          }
          break;

        case oNoSecmemWarn: gcry_control (GCRYCTL_DISABLE_SECMEM_WARN); break;

        case oNoRandomSeedFile: use_random_seed = 0; break;

        case oRecipient: /* Store the encryption key.  */
          add_to_strlist (&recipients, pargs.r.ret_str);
          break;


        default:
          pargs.err = configfp? ARGPARSE_PRINT_WARNING:ARGPARSE_PRINT_ERROR;
          break;
	}
    }

  if (configfp)
    {
      fclose (configfp);
      configfp = NULL;
      /* Keep a copy of the config filename. */
      opt.config_filename = configname;
      configname = NULL;
      goto next_pass;
    }
  xfree (configname);
  configname = NULL;

  if (!opt.config_filename)
    opt.config_filename = make_filename (opt.homedir, G13_NAME".conf", NULL);

  if (log_get_errorcount(0))
    g13_exit(2);

  /* Now that we have the options parsed we need to update the default
     control structure.  */
  g13_init_default_ctrl (&ctrl);

  if (nogreeting)
    greeting = 0;

  if (greeting)
    {
      fprintf (stderr, "%s %s; %s\n",
               strusage(11), strusage(13), strusage(14) );
      fprintf (stderr, "%s\n", strusage(15) );
    }

  if (may_coredump && !opt.quiet)
    log_info (_("WARNING: program may create a core file!\n"));

  /* Print a warning if an argument looks like an option.  */
  if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
    {
      int i;

      for (i=0; i < argc; i++)
        if (argv[i][0] == '-' && argv[i][1] == '-')
          log_info (_("NOTE: '%s' is not considered an option\n"), argv[i]);
    }


  if (logfile)
    {
      log_set_file (logfile);
      log_set_prefix (NULL, 1|2|4);
    }

  if (gnupg_faked_time_p ())
    {
      gnupg_isotime_t tbuf;

      log_info (_("WARNING: running with faked system time: "));
      gnupg_get_isotime (tbuf);
      dump_isotime (tbuf);
      log_printf ("\n");
    }

  /* Print any pending secure memory warnings.  */
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  /* Setup the debug flags for all subsystems.  */
  set_debug ();

  /* Install a regular exit handler to make real sure that the secure
     memory gets wiped out.  */
  if (atexit (emergency_cleanup))
    {
      log_error ("atexit failed\n");
      g13_exit (2);
    }

  /* Terminate if we found any error until now.  */
  if (log_get_errorcount(0))
    g13_exit (2);

  /* Set the standard GnuPG random seed file.  */
  if (use_random_seed)
    {
      char *p = make_filename (opt.homedir, "random_seed", NULL);
      gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
      xfree(p);
    }

  /* Store given filename into FNAME. */
  /* fname = argc? *argv : NULL; */

  /* Parse all given encryption keys.  This does a lookup of the keys
     and stops if any of the given keys was not found. */
#if 0 /* Currently not implemented.  */
  if (!nokeysetup)
    {
      strlist_t sl;
      int failed = 0;

      for (sl = recipients; sl; sl = sl->next)
        if (check_encryption_key ())
          failed = 1;
      if (failed)
        g13_exit (1);
    }
#endif /*0*/

  /* Dispatch command.  */
  err = 0;
  switch (cmd)
    {
    case aGPGConfList:
      { /* List options and default values in the GPG Conf format.  */
	char *config_filename_esc = percent_escape (opt.config_filename, NULL);

        printf ("gpgconf-g13.conf:%lu:\"%s\n",
                GC_OPT_FLAG_DEFAULT, config_filename_esc);
        xfree (config_filename_esc);

        printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("quiet:%lu:\n", GC_OPT_FLAG_NONE);
	printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
	printf ("log-file:%lu:\n", GC_OPT_FLAG_NONE);
      }
      break;
    case aGPGConfTest:
      /* This is merely a dummy command to test whether the
         configuration file is valid.  */
      break;

    case aServer:
      {
        start_idle_task ();
        ctrl.no_server = 0;
        err = g13_server (&ctrl);
        if (err)
          log_error ("server exited with error: %s <%s>\n",
                     gpg_strerror (err), gpg_strsource (err));
        else
          shutdown_pending++;
      }
      break;

    case aCreate: /* Create a new container. */
      {
        if (argc != 1)
          wrong_args ("--create filename");
        start_idle_task ();
        err = g13_create_container (&ctrl, argv[0], recipients);
        if (err)
          log_error ("error creating a new container: %s <%s>\n",
                     gpg_strerror (err), gpg_strsource (err));
        else
          shutdown_pending++;
      }
      break;

    case aMount: /* Mount a container. */
      {
        if (argc != 1 && argc != 2 )
          wrong_args ("--mount filename [mountpoint]");
        start_idle_task ();
        err = g13_mount_container (&ctrl, argv[0], argc == 2?argv[1]:NULL);
        if (err)
          log_error ("error mounting container '%s': %s <%s>\n",
                     *argv, gpg_strerror (err), gpg_strsource (err));
      }
      break;

    default:
      log_error (_("invalid command (there is no implicit command)\n"));
      break;
    }

  if (!err)
    join_idle_task ();

  /* Cleanup.  */
  g13_exit (0);
  return 8; /*NOTREACHED*/
}


/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM );
}


void
g13_exit (int rc)
{
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      gcry_control( GCRYCTL_DUMP_MEMORY_STATS );
      gcry_control( GCRYCTL_DUMP_RANDOM_STATS );
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );
  emergency_cleanup ();
  rc = rc? rc : log_get_errorcount(0)? 2 : g13_errors_seen? 1 : 0;
  exit (rc);
}


/* Store defaults into the per-connection CTRL object.  */
void
g13_init_default_ctrl (struct server_control_s *ctrl)
{
  ctrl->conttype = CONTTYPE_ENCFS;
}


/* This function is called for each signal we catch.  It is run in the
   main context or the one of a NPth thread and thus it is not
   restricted in what it may do.  */
static void
handle_signal (int signo)
{
  switch (signo)
    {
#ifndef HAVE_W32_SYSTEM
    case SIGHUP:
      log_info ("SIGHUP received - re-reading configuration\n");
      /* Fixme:  Not yet implemented.  */
      break;

    case SIGUSR1:
      log_info ("SIGUSR1 received - printing internal information:\n");
      /* Fixme: We need to see how to integrate pth dumping into our
         logging system.  */
      /* pth_ctrl (PTH_CTRL_DUMPSTATE, log_get_stream ()); */
      mountinfo_dump_all ();
      break;

    case SIGUSR2:
      log_info ("SIGUSR2 received - no action defined\n");
      break;

    case SIGTERM:
      if (!shutdown_pending)
        log_info ("SIGTERM received - shutting down ...\n");
      else
        log_info ("SIGTERM received - still %u runners active\n",
                  runner_get_threads ());
      shutdown_pending++;
      if (shutdown_pending > 2)
        {
          log_info ("shutdown forced\n");
          log_info ("%s %s stopped\n", strusage(11), strusage(13) );
          g13_exit (0);
	}
      break;

    case SIGINT:
      log_info ("SIGINT received - immediate shutdown\n");
      log_info( "%s %s stopped\n", strusage(11), strusage(13));
      g13_exit (0);
      break;
#endif /*!HAVE_W32_SYSTEM*/

    default:
      log_info ("signal %d received - no action defined\n", signo);
    }
}


/* This ticker function is called about every TIMERTICK_INTERVAL_SEC
   seconds. */
static void
handle_tick (void)
{
  /* log_debug ("TICK\n"); */
}


/* The idle task.  We use a separate thread to do idle stuff and to
   catch signals.  */
static void *
idle_task (void *dummy_arg)
{
  int signo;           /* The number of a raised signal is stored here.  */
  int saved_errno;
  struct timespec abstime;
  struct timespec curtime;
  struct timespec timeout;
  int ret;

  (void)dummy_arg;

  /* Create the event to catch the signals. */
#ifndef HAVE_W32_SYSTEM
  npth_sigev_init ();
  npth_sigev_add (SIGHUP);
  npth_sigev_add (SIGUSR1);
  npth_sigev_add (SIGUSR2);
  npth_sigev_add (SIGINT);
  npth_sigev_add (SIGTERM);
  npth_sigev_fini ();
#endif

  npth_clock_gettime (&abstime);
  abstime.tv_sec += TIMERTICK_INTERVAL_SEC;

  for (;;)
    {
      /* The shutdown flag allows us to terminate the idle task.  */
      if (shutdown_pending)
        {
          runner_cancel_all ();

          if (!runner_get_threads ())
            break; /* ready */
	}

      npth_clock_gettime (&curtime);
      if (!(npth_timercmp (&curtime, &abstime, <)))
	{
	  /* Timeout.  */
	  handle_tick ();
	  npth_clock_gettime (&abstime);
	  abstime.tv_sec += TIMERTICK_INTERVAL_SEC;
	}
      npth_timersub (&abstime, &curtime, &timeout);

#ifndef HAVE_W32_SYSTEM
      ret = npth_pselect (0, NULL, NULL, NULL, &timeout, npth_sigev_sigmask());
      saved_errno = errno;

      while (npth_sigev_get_pending(&signo))
	handle_signal (signo);
#else
      ret = npth_eselect (0, NULL, NULL, NULL, &timeout, NULL, NULL);
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
	/* Interrupt or timeout.  Will be handled when calculating the
	   next timeout.  */
	continue;

      /* Here one would add processing of file descriptors.  */
    }

  log_info (_("%s %s stopped\n"), strusage(11), strusage(13));
  return NULL;
}


/* Start the idle task.   */
static void
start_idle_task (void)
{
  npth_attr_t tattr;
  npth_t thread;
  sigset_t sigs;       /* The set of signals we want to catch.  */
  int err;

#ifndef HAVE_W32_SYSTEM
  /* These signals should always go to the idle task, so they need to
     be blocked everywhere else.  We assume start_idle_task is called
     from the main thread before any other threads are created.  */
  sigemptyset (&sigs);
  sigaddset (&sigs, SIGHUP);
  sigaddset (&sigs, SIGUSR1);
  sigaddset (&sigs, SIGUSR2);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGTERM);
  npth_sigmask (SIG_BLOCK, &sigs, NULL);
#endif

  npth_attr_init (&tattr);
  npth_attr_setdetachstate (&tattr, NPTH_CREATE_JOINABLE);

  err = npth_create (&thread, &tattr, idle_task, NULL);
  if (err)
    {
      log_fatal ("error starting idle task: %s\n", strerror (err));
      return; /*NOTREACHED*/
    }
  npth_setname_np (thread, "idle-task");
  idle_task_thread = thread;
  npth_attr_destroy (&tattr);
}


/* Wait for the idle task to finish.  */
static void
join_idle_task (void)
{
  int err;

  /* FIXME: This assumes that a valid pthread_t is non-null.  That is
     not guaranteed.  */
  if (idle_task_thread)
    {
      err = npth_join (idle_task_thread, NULL);
      if (err)
        log_error ("waiting for idle task thread failed: %s\n",
                   strerror (err));
    }
}
