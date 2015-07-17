/* gpg.c - The GnuPG utility (main for gpg)
 * Copyright (C) 1998-2011 Free Software Foundation, Inc.
 * Copyright (C) 1997-2014 Werner Koch
 * Copyright (C) 2015 g10 Code GmbH
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#ifdef HAVE_STAT
#include <sys/stat.h> /* for stat() */
#endif
#include <fcntl.h>
#ifdef HAVE_W32_SYSTEM
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#endif

#define INCLUDED_BY_MAIN_MODULE 1
#include "gpg.h"
#include <assuan.h>
#include "../common/iobuf.h"
#include "util.h"
#include "packet.h"
#include "membuf.h"
#include "main.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "filter.h"
#include "ttyio.h"
#include "i18n.h"
#include "sysutils.h"
#include "status.h"
#include "keyserver-internal.h"
#include "exec.h"
#include "gc-opt-flags.h"
#include "asshelp.h"
#include "call-dirmngr.h"
#include "../common/init.h"
#include "../common/shareddefs.h"

#if defined(HAVE_DOSISH_SYSTEM) || defined(__CYGWIN__)
#define MY_O_BINARY  O_BINARY
#ifndef S_IRGRP
# define S_IRGRP 0
# define S_IWGRP 0
#endif
#else
#define MY_O_BINARY  0
#endif


enum cmd_and_opt_values
  {
    aNull = 0,
    oArmor	  = 'a',
    aDetachedSign = 'b',
    aSym	  = 'c',
    aDecrypt	  = 'd',
    aEncr	  = 'e',
    oInteractive  = 'i',
    aListKeys	  = 'k',
    oDryRun	  = 'n',
    oOutput	  = 'o',
    oQuiet	  = 'q',
    oRecipient	  = 'r',
    oHiddenRecipient = 'R',
    aSign	  = 's',
    oTextmodeShort= 't',
    oLocalUser	  = 'u',
    oVerbose	  = 'v',
    oCompress	  = 'z',
    oSetNotation  = 'N',
    aListSecretKeys = 'K',
    oBatch	  = 500,
    oMaxOutput,
    oSigNotation,
    oCertNotation,
    oShowNotation,
    oNoShowNotation,
    aEncrFiles,
    aEncrSym,
    aDecryptFiles,
    aClearsign,
    aStore,
    aQuickKeygen,
    aFullKeygen,
    aKeygen,
    aSignEncr,
    aSignEncrSym,
    aSignSym,
    aSignKey,
    aLSignKey,
    aQuickSignKey,
    aQuickLSignKey,
    aQuickAddUid,
    aListConfig,
    aListGcryptConfig,
    aGPGConfList,
    aGPGConfTest,
    aListPackets,
    aEditKey,
    aDeleteKeys,
    aDeleteSecretKeys,
    aDeleteSecretAndPublicKeys,
    aImport,
    aFastImport,
    aVerify,
    aVerifyFiles,
    aListSigs,
    aSendKeys,
    aRecvKeys,
    aLocateKeys,
    aSearchKeys,
    aRefreshKeys,
    aFetchKeys,
    aExport,
    aExportSecret,
    aExportSecretSub,
    aCheckKeys,
    aGenRevoke,
    aDesigRevoke,
    aPrimegen,
    aPrintMD,
    aPrintMDs,
    aCheckTrustDB,
    aUpdateTrustDB,
    aFixTrustDB,
    aListTrustDB,
    aListTrustPath,
    aExportOwnerTrust,
    aImportOwnerTrust,
    aDeArmor,
    aEnArmor,
    aGenRandom,
    aRebuildKeydbCaches,
    aCardStatus,
    aCardEdit,
    aChangePIN,
    aPasswd,
    aServer,

    oTextmode,
    oNoTextmode,
    oExpert,
    oNoExpert,
    oDefSigExpire,
    oAskSigExpire,
    oNoAskSigExpire,
    oDefCertExpire,
    oAskCertExpire,
    oNoAskCertExpire,
    oDefCertLevel,
    oMinCertLevel,
    oAskCertLevel,
    oNoAskCertLevel,
    oFingerprint,
    oWithFingerprint,
    oWithICAOSpelling,
    oWithKeygrip,
    oWithSecret,
    oAnswerYes,
    oAnswerNo,
    oKeyring,
    oPrimaryKeyring,
    oSecretKeyring,
    oShowKeyring,
    oDefaultKey,
    oDefRecipient,
    oDefRecipientSelf,
    oNoDefRecipient,
    oTrySecretKey,
    oOptions,
    oDebug,
    oDebugLevel,
    oDebugAll,
    oDebugIOLBF,
    oStatusFD,
    oStatusFile,
    oAttributeFD,
    oAttributeFile,
    oEmitVersion,
    oNoEmitVersion,
    oCompletesNeeded,
    oMarginalsNeeded,
    oMaxCertDepth,
    oLoadExtension,
    oGnuPG,
    oRFC2440,
    oRFC4880,
    oOpenPGP,
    oPGP6,
    oPGP7,
    oPGP8,
    oRFC2440Text,
    oNoRFC2440Text,
    oCipherAlgo,
    oDigestAlgo,
    oCertDigestAlgo,
    oCompressAlgo,
    oCompressLevel,
    oBZ2CompressLevel,
    oBZ2DecompressLowmem,
    oPassphrase,
    oPassphraseFD,
    oPassphraseFile,
    oPassphraseRepeat,
    oPinentryMode,
    oCommandFD,
    oCommandFile,
    oQuickRandom,
    oNoVerbose,
    oTrustDBName,
    oNoSecmemWarn,
    oRequireSecmem,
    oNoRequireSecmem,
    oNoPermissionWarn,
    oNoMDCWarn,
    oNoArmor,
    oNoDefKeyring,
    oNoGreeting,
    oNoTTY,
    oNoOptions,
    oNoBatch,
    oHomedir,
    oWithColons,
    oWithKeyData,
    oWithSigList,
    oWithSigCheck,
    oSkipVerify,
    oSkipHiddenRecipients,
    oNoSkipHiddenRecipients,
    oAlwaysTrust,
    oTrustModel,
    oForceOwnertrust,
    oSetFilename,
    oForYourEyesOnly,
    oNoForYourEyesOnly,
    oSetPolicyURL,
    oSigPolicyURL,
    oCertPolicyURL,
    oShowPolicyURL,
    oNoShowPolicyURL,
    oSigKeyserverURL,
    oUseEmbeddedFilename,
    oNoUseEmbeddedFilename,
    oComment,
    oDefaultComment,
    oNoComments,
    oThrowKeyids,
    oNoThrowKeyids,
    oShowPhotos,
    oNoShowPhotos,
    oPhotoViewer,
    oForceMDC,
    oNoForceMDC,
    oDisableMDC,
    oNoDisableMDC,
    oS2KMode,
    oS2KDigest,
    oS2KCipher,
    oS2KCount,
    oDisplayCharset,
    oNotDashEscaped,
    oEscapeFrom,
    oNoEscapeFrom,
    oLockOnce,
    oLockMultiple,
    oLockNever,
    oKeyServer,
    oKeyServerOptions,
    oImportOptions,
    oExportOptions,
    oListOptions,
    oVerifyOptions,
    oTempDir,
    oExecPath,
    oEncryptTo,
    oHiddenEncryptTo,
    oNoEncryptTo,
    oLoggerFD,
    oLoggerFile,
    oUtf8Strings,
    oNoUtf8Strings,
    oDisableCipherAlgo,
    oDisablePubkeyAlgo,
    oAllowNonSelfsignedUID,
    oNoAllowNonSelfsignedUID,
    oAllowFreeformUID,
    oNoAllowFreeformUID,
    oAllowSecretKeyImport,
    oEnableSpecialFilenames,
    oNoLiteral,
    oSetFilesize,
    oHonorHttpProxy,
    oFastListMode,
    oListOnly,
    oIgnoreTimeConflict,
    oIgnoreValidFrom,
    oIgnoreCrcError,
    oIgnoreMDCError,
    oShowSessionKey,
    oOverrideSessionKey,
    oNoRandomSeedFile,
    oAutoKeyRetrieve,
    oNoAutoKeyRetrieve,
    oUseAgent,
    oNoUseAgent,
    oGpgAgentInfo,
    oMergeOnly,
    oTryAllSecrets,
    oTrustedKey,
    oNoExpensiveTrustChecks,
    oFixedListMode,
    oLegacyListMode,
    oNoSigCache,
    oNoSigCreateCheck,
    oAutoCheckTrustDB,
    oNoAutoCheckTrustDB,
    oPreservePermissions,
    oDefaultPreferenceList,
    oDefaultKeyserverURL,
    oPersonalCipherPreferences,
    oPersonalDigestPreferences,
    oPersonalCompressPreferences,
    oAgentProgram,
    oDirmngrProgram,
    oDisplay,
    oTTYname,
    oTTYtype,
    oLCctype,
    oLCmessages,
    oXauthority,
    oGroup,
    oUnGroup,
    oNoGroups,
    oStrict,
    oNoStrict,
    oMangleDosFilenames,
    oNoMangleDosFilenames,
    oEnableProgressFilter,
    oMultifile,
    oKeyidFormat,
    oExitOnStatusWriteError,
    oLimitCardInsertTries,
    oReaderPort,
    octapiDriver,
    opcscDriver,
    oDisableCCID,
    oRequireCrossCert,
    oNoRequireCrossCert,
    oAutoKeyLocate,
    oNoAutoKeyLocate,
    oAllowMultisigVerification,
    oEnableLargeRSA,
    oDisableLargeRSA,
    oEnableDSA2,
    oDisableDSA2,
    oAllowMultipleMessages,
    oNoAllowMultipleMessages,
    oAllowWeakDigestAlgos,
    oFakedSystemTime,
    oNoAutostart,
    oPrintPKARecords,

    oNoop
  };


static ARGPARSE_OPTS opts[] = {

  ARGPARSE_group (300, N_("@Commands:\n ")),

  ARGPARSE_c (aSign, "sign", N_("make a signature")),
  ARGPARSE_c (aClearsign, "clearsign", N_("make a clear text signature")),
  ARGPARSE_c (aDetachedSign, "detach-sign", N_("make a detached signature")),
  ARGPARSE_c (aEncr, "encrypt",   N_("encrypt data")),
  ARGPARSE_c (aEncrFiles, "encrypt-files", "@"),
  ARGPARSE_c (aSym, "symmetric", N_("encryption only with symmetric cipher")),
  ARGPARSE_c (aStore, "store",     "@"),
  ARGPARSE_c (aDecrypt, "decrypt",   N_("decrypt data (default)")),
  ARGPARSE_c (aDecryptFiles, "decrypt-files", "@"),
  ARGPARSE_c (aVerify, "verify"   , N_("verify a signature")),
  ARGPARSE_c (aVerifyFiles, "verify-files" , "@" ),
  ARGPARSE_c (aListKeys, "list-keys", N_("list keys")),
  ARGPARSE_c (aListKeys, "list-public-keys", "@" ),
  ARGPARSE_c (aListSigs, "list-sigs", N_("list keys and signatures")),
  ARGPARSE_c (aCheckKeys, "check-sigs",N_("list and check key signatures")),
  ARGPARSE_c (oFingerprint, "fingerprint", N_("list keys and fingerprints")),
  ARGPARSE_c (aListSecretKeys, "list-secret-keys", N_("list secret keys")),
  ARGPARSE_c (aKeygen,	    "gen-key",
              N_("generate a new key pair")),
  ARGPARSE_c (aQuickKeygen, "quick-gen-key" ,
              N_("quickly generate a new key pair")),
  ARGPARSE_c (aQuickAddUid,  "quick-adduid",
              N_("quickly add a new user-id")),
  ARGPARSE_c (aFullKeygen,  "full-gen-key" ,
              N_("full featured key pair generation")),
  ARGPARSE_c (aGenRevoke, "gen-revoke",N_("generate a revocation certificate")),
  ARGPARSE_c (aDeleteKeys,"delete-keys",
              N_("remove keys from the public keyring")),
  ARGPARSE_c (aDeleteSecretKeys, "delete-secret-keys",
              N_("remove keys from the secret keyring")),
  ARGPARSE_c (aQuickSignKey,  "quick-sign-key" ,
              N_("quickly sign a key")),
  ARGPARSE_c (aQuickLSignKey, "quick-lsign-key",
              N_("quickly sign a key locally")),
  ARGPARSE_c (aSignKey,  "sign-key"   ,N_("sign a key")),
  ARGPARSE_c (aLSignKey, "lsign-key"  ,N_("sign a key locally")),
  ARGPARSE_c (aEditKey,  "edit-key"   ,N_("sign or edit a key")),
  ARGPARSE_c (aEditKey,  "key-edit"   ,"@"),
  ARGPARSE_c (aPasswd,   "passwd",     N_("change a passphrase")),
  ARGPARSE_c (aDesigRevoke, "desig-revoke","@" ),
  ARGPARSE_c (aExport, "export"           , N_("export keys") ),
  ARGPARSE_c (aSendKeys, "send-keys"     , N_("export keys to a key server") ),
  ARGPARSE_c (aRecvKeys, "recv-keys"     , N_("import keys from a key server") ),
  ARGPARSE_c (aSearchKeys, "search-keys" ,
              N_("search for keys on a key server") ),
  ARGPARSE_c (aRefreshKeys, "refresh-keys",
              N_("update all keys from a keyserver")),
  ARGPARSE_c (aLocateKeys, "locate-keys", "@"),
  ARGPARSE_c (aFetchKeys, "fetch-keys" , "@" ),
  ARGPARSE_c (aExportSecret, "export-secret-keys" , "@" ),
  ARGPARSE_c (aExportSecretSub, "export-secret-subkeys" , "@" ),
  ARGPARSE_c (aImport, "import", N_("import/merge keys")),
  ARGPARSE_c (aFastImport, "fast-import", "@"),
#ifdef ENABLE_CARD_SUPPORT
  ARGPARSE_c (aCardStatus,  "card-status", N_("print the card status")),
  ARGPARSE_c (aCardEdit,   "card-edit",  N_("change data on a card")),
  ARGPARSE_c (aChangePIN,  "change-pin", N_("change a card's PIN")),
#endif
  ARGPARSE_c (aListConfig, "list-config", "@"),
  ARGPARSE_c (aListGcryptConfig, "list-gcrypt-config", "@"),
  ARGPARSE_c (aGPGConfList, "gpgconf-list", "@" ),
  ARGPARSE_c (aGPGConfTest, "gpgconf-test", "@" ),
  ARGPARSE_c (aListPackets, "list-packets","@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aExportOwnerTrust, "export-ownertrust", "@"),
  ARGPARSE_c (aImportOwnerTrust, "import-ownertrust", "@"),
  ARGPARSE_c (aUpdateTrustDB,"update-trustdb",
              N_("update the trust database")),
  ARGPARSE_c (aCheckTrustDB, "check-trustdb", "@"),
  ARGPARSE_c (aFixTrustDB, "fix-trustdb", "@"),
#endif

  ARGPARSE_c (aDeArmor, "dearmor", "@"),
  ARGPARSE_c (aDeArmor, "dearmour", "@"),
  ARGPARSE_c (aEnArmor, "enarmor", "@"),
  ARGPARSE_c (aEnArmor, "enarmour", "@"),
  ARGPARSE_c (aPrintMD, "print-md", N_("print message digests")),
  ARGPARSE_c (aPrimegen, "gen-prime", "@" ),
  ARGPARSE_c (aGenRandom,"gen-random", "@" ),
  ARGPARSE_c (aServer,   "server",  N_("run in server mode")),

  ARGPARSE_group (301, N_("@\nOptions:\n ")),

  ARGPARSE_s_n (oArmor, "armor", N_("create ascii armored output")),
  ARGPARSE_s_n (oArmor, "armour", "@"),

  ARGPARSE_s_s (oRecipient, "recipient", N_("|USER-ID|encrypt for USER-ID")),
  ARGPARSE_s_s (oHiddenRecipient, "hidden-recipient", "@"),
  ARGPARSE_s_s (oRecipient, "remote-user", "@"),  /* (old option name) */
  ARGPARSE_s_s (oDefRecipient, "default-recipient", "@"),
  ARGPARSE_s_n (oDefRecipientSelf,  "default-recipient-self", "@"),
  ARGPARSE_s_n (oNoDefRecipient, "no-default-recipient", "@"),

  ARGPARSE_s_s (oTempDir,  "temp-directory", "@"),
  ARGPARSE_s_s (oExecPath, "exec-path", "@"),
  ARGPARSE_s_s (oEncryptTo,      "encrypt-to", "@"),
  ARGPARSE_s_n (oNoEncryptTo, "no-encrypt-to", "@"),
  ARGPARSE_s_s (oHiddenEncryptTo, "hidden-encrypt-to", "@"),
  ARGPARSE_s_s (oLocalUser, "local-user",
                N_("|USER-ID|use USER-ID to sign or decrypt")),

  ARGPARSE_s_s (oTrySecretKey, "try-secret-key", "@"),

  ARGPARSE_s_i (oCompress, NULL,
                N_("|N|set compress level to N (0 disables)")),
  ARGPARSE_s_i (oCompressLevel, "compress-level", "@"),
  ARGPARSE_s_i (oBZ2CompressLevel, "bzip2-compress-level", "@"),
  ARGPARSE_s_n (oBZ2DecompressLowmem, "bzip2-decompress-lowmem", "@"),

  ARGPARSE_s_n (oTextmodeShort, NULL, "@"),
  ARGPARSE_s_n (oTextmode,      "textmode", N_("use canonical text mode")),
  ARGPARSE_s_n (oNoTextmode, "no-textmode", "@"),

  ARGPARSE_s_n (oExpert,      "expert", "@"),
  ARGPARSE_s_n (oNoExpert, "no-expert", "@"),

  ARGPARSE_s_s (oDefSigExpire, "default-sig-expire", "@"),
  ARGPARSE_s_n (oAskSigExpire,      "ask-sig-expire", "@"),
  ARGPARSE_s_n (oNoAskSigExpire, "no-ask-sig-expire", "@"),
  ARGPARSE_s_s (oDefCertExpire, "default-cert-expire", "@"),
  ARGPARSE_s_n (oAskCertExpire,      "ask-cert-expire", "@"),
  ARGPARSE_s_n (oNoAskCertExpire, "no-ask-cert-expire", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-level", "@"),
  ARGPARSE_s_i (oMinCertLevel, "min-cert-level", "@"),
  ARGPARSE_s_n (oAskCertLevel,      "ask-cert-level", "@"),
  ARGPARSE_s_n (oNoAskCertLevel, "no-ask-cert-level", "@"),

  ARGPARSE_s_s (oOutput, "output", N_("|FILE|write output to FILE")),
  ARGPARSE_p_u (oMaxOutput, "max-output", "@"),

  ARGPARSE_s_n (oVerbose, "verbose", N_("verbose")),
  ARGPARSE_s_n (oQuiet,	  "quiet",   "@"),
  ARGPARSE_s_n (oNoTTY,   "no-tty",  "@"),

  ARGPARSE_s_n (oForceMDC, "force-mdc", "@"),
  ARGPARSE_s_n (oNoForceMDC, "no-force-mdc", "@"),
  ARGPARSE_s_n (oDisableMDC, "disable-mdc", "@"),
  ARGPARSE_s_n (oNoDisableMDC, "no-disable-mdc", "@"),

  ARGPARSE_s_n (oDryRun, "dry-run", N_("do not make any changes")),
  ARGPARSE_s_n (oInteractive, "interactive", N_("prompt before overwriting")),

  ARGPARSE_s_n (oBatch, "batch", "@"),
  ARGPARSE_s_n (oAnswerYes, "yes", "@"),
  ARGPARSE_s_n (oAnswerNo, "no", "@"),
  ARGPARSE_s_s (oKeyring, "keyring", "@"),
  ARGPARSE_s_s (oPrimaryKeyring, "primary-keyring", "@"),
  ARGPARSE_s_s (oSecretKeyring, "secret-keyring", "@"),
  ARGPARSE_s_n (oShowKeyring, "show-keyring", "@"),
  ARGPARSE_s_s (oDefaultKey, "default-key", "@"),

  ARGPARSE_s_s (oKeyServer, "keyserver", "@"),
  ARGPARSE_s_s (oKeyServerOptions, "keyserver-options", "@"),
  ARGPARSE_s_s (oImportOptions, "import-options", "@"),
  ARGPARSE_s_s (oExportOptions, "export-options", "@"),
  ARGPARSE_s_s (oListOptions,   "list-options", "@"),
  ARGPARSE_s_s (oVerifyOptions, "verify-options", "@"),

  ARGPARSE_s_s (oDisplayCharset, "display-charset", "@"),
  ARGPARSE_s_s (oDisplayCharset, "charset", "@"),
  ARGPARSE_s_s (oOptions, "options", "@"),

  ARGPARSE_s_s (oDebug, "debug", "@"),
  ARGPARSE_s_s (oDebugLevel, "debug-level", "@"),
  ARGPARSE_s_n (oDebugAll, "debug-all", "@"),
  ARGPARSE_s_n (oDebugIOLBF, "debug-iolbf", "@"),
  ARGPARSE_s_i (oStatusFD, "status-fd", "@"),
  ARGPARSE_s_s (oStatusFile, "status-file", "@"),
  ARGPARSE_s_i (oAttributeFD, "attribute-fd", "@"),
  ARGPARSE_s_s (oAttributeFile, "attribute-file", "@"),

  ARGPARSE_s_i (oCompletesNeeded, "completes-needed", "@"),
  ARGPARSE_s_i (oMarginalsNeeded, "marginals-needed", "@"),
  ARGPARSE_s_i (oMaxCertDepth,	"max-cert-depth", "@" ),
  ARGPARSE_s_s (oTrustedKey, "trusted-key", "@"),

  ARGPARSE_s_s (oLoadExtension, "load-extension", "@"),  /* Dummy.  */

  ARGPARSE_s_n (oGnuPG, "gnupg",   "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp2", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp6", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp7", "@"),
  ARGPARSE_s_n (oGnuPG, "no-pgp8", "@"),
  ARGPARSE_s_n (oRFC2440, "rfc2440", "@"),
  ARGPARSE_s_n (oRFC4880, "rfc4880", "@"),
  ARGPARSE_s_n (oOpenPGP, "openpgp", N_("use strict OpenPGP behavior")),
  ARGPARSE_s_n (oPGP6, "pgp6", "@"),
  ARGPARSE_s_n (oPGP7, "pgp7", "@"),
  ARGPARSE_s_n (oPGP8, "pgp8", "@"),

  ARGPARSE_s_n (oRFC2440Text,      "rfc2440-text", "@"),
  ARGPARSE_s_n (oNoRFC2440Text, "no-rfc2440-text", "@"),
  ARGPARSE_s_i (oS2KMode, "s2k-mode", "@"),
  ARGPARSE_s_s (oS2KDigest, "s2k-digest-algo", "@"),
  ARGPARSE_s_s (oS2KCipher, "s2k-cipher-algo", "@"),
  ARGPARSE_s_i (oS2KCount, "s2k-count", "@"),
  ARGPARSE_s_s (oCipherAlgo, "cipher-algo", "@"),
  ARGPARSE_s_s (oDigestAlgo, "digest-algo", "@"),
  ARGPARSE_s_s (oCertDigestAlgo, "cert-digest-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo,"compress-algo", "@"),
  ARGPARSE_s_s (oCompressAlgo, "compression-algo", "@"), /* Alias */
  ARGPARSE_s_n (oThrowKeyids, "throw-keyids", "@"),
  ARGPARSE_s_n (oNoThrowKeyids, "no-throw-keyids", "@"),
  ARGPARSE_s_n (oShowPhotos,   "show-photos", "@"),
  ARGPARSE_s_n (oNoShowPhotos, "no-show-photos", "@"),
  ARGPARSE_s_s (oPhotoViewer,  "photo-viewer", "@"),
  ARGPARSE_s_s (oSetNotation,  "set-notation", "@"),
  ARGPARSE_s_s (oSigNotation,  "sig-notation", "@"),
  ARGPARSE_s_s (oCertNotation, "cert-notation", "@"),

  ARGPARSE_group (302, N_(
  "@\n(See the man page for a complete listing of all commands and options)\n"
		      )),

  ARGPARSE_group (303, N_("@\nExamples:\n\n"
    " -se -r Bob [file]          sign and encrypt for user Bob\n"
    " --clearsign [file]         make a clear text signature\n"
    " --detach-sign [file]       make a detached signature\n"
    " --list-keys [names]        show keys\n"
    " --fingerprint [names]      show fingerprints\n")),

  /* More hidden commands and options. */
  ARGPARSE_c (aPrintMDs, "print-mds", "@"), /* old */
#ifndef NO_TRUST_MODELS
  ARGPARSE_c (aListTrustDB, "list-trustdb", "@"),
#endif

  /* Not yet used:
     ARGPARSE_c (aListTrustPath, "list-trust-path", "@"), */
  ARGPARSE_c (aDeleteSecretAndPublicKeys,
              "delete-secret-and-public-keys", "@"),
  ARGPARSE_c (aRebuildKeydbCaches, "rebuild-keydb-caches", "@"),

  ARGPARSE_s_s (oPassphrase,      "passphrase", "@"),
  ARGPARSE_s_i (oPassphraseFD,    "passphrase-fd", "@"),
  ARGPARSE_s_s (oPassphraseFile,  "passphrase-file", "@"),
  ARGPARSE_s_i (oPassphraseRepeat,"passphrase-repeat", "@"),
  ARGPARSE_s_s (oPinentryMode,    "pinentry-mode", "@"),
  ARGPARSE_s_i (oCommandFD, "command-fd", "@"),
  ARGPARSE_s_s (oCommandFile, "command-file", "@"),
  ARGPARSE_s_n (oQuickRandom, "debug-quick-random", "@"),
  ARGPARSE_s_n (oNoVerbose, "no-verbose", "@"),

#ifndef NO_TRUST_MODELS
  ARGPARSE_s_s (oTrustDBName, "trustdb-name", "@"),
  ARGPARSE_s_n (oAutoCheckTrustDB, "auto-check-trustdb", "@"),
  ARGPARSE_s_n (oNoAutoCheckTrustDB, "no-auto-check-trustdb", "@"),
  ARGPARSE_s_s (oForceOwnertrust, "force-ownertrust", "@"),
#endif

  ARGPARSE_s_n (oNoSecmemWarn, "no-secmem-warning", "@"),
  ARGPARSE_s_n (oRequireSecmem, "require-secmem", "@"),
  ARGPARSE_s_n (oNoRequireSecmem, "no-require-secmem", "@"),
  ARGPARSE_s_n (oNoPermissionWarn, "no-permission-warning", "@"),
  ARGPARSE_s_n (oNoMDCWarn, "no-mdc-warning", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armor", "@"),
  ARGPARSE_s_n (oNoArmor, "no-armour", "@"),
  ARGPARSE_s_n (oNoDefKeyring, "no-default-keyring", "@"),
  ARGPARSE_s_n (oNoGreeting, "no-greeting", "@"),
  ARGPARSE_s_n (oNoOptions, "no-options", "@"),
  ARGPARSE_s_s (oHomedir, "homedir", "@"),
  ARGPARSE_s_n (oNoBatch, "no-batch", "@"),
  ARGPARSE_s_n (oWithColons, "with-colons", "@"),
  ARGPARSE_s_n (oWithKeyData,"with-key-data", "@"),
  ARGPARSE_s_n (oWithSigList,"with-sig-list", "@"),
  ARGPARSE_s_n (oWithSigCheck,"with-sig-check", "@"),
  ARGPARSE_s_n (aListKeys, "list-key", "@"),   /* alias */
  ARGPARSE_s_n (aListSigs, "list-sig", "@"),   /* alias */
  ARGPARSE_s_n (aCheckKeys, "check-sig", "@"), /* alias */
  ARGPARSE_s_n (oSkipVerify, "skip-verify", "@"),
  ARGPARSE_s_n (oSkipHiddenRecipients, "skip-hidden-recipients", "@"),
  ARGPARSE_s_n (oNoSkipHiddenRecipients, "no-skip-hidden-recipients", "@"),
  ARGPARSE_s_i (oDefCertLevel, "default-cert-check-level", "@"), /* old */
  ARGPARSE_s_n (oAlwaysTrust, "always-trust", "@"),
  ARGPARSE_s_s (oTrustModel, "trust-model", "@"),
  ARGPARSE_s_s (oSetFilename, "set-filename", "@"),
  ARGPARSE_s_n (oForYourEyesOnly, "for-your-eyes-only", "@"),
  ARGPARSE_s_n (oNoForYourEyesOnly, "no-for-your-eyes-only", "@"),
  ARGPARSE_s_s (oSetPolicyURL,  "set-policy-url", "@"),
  ARGPARSE_s_s (oSigPolicyURL,  "sig-policy-url", "@"),
  ARGPARSE_s_s (oCertPolicyURL, "cert-policy-url", "@"),
  ARGPARSE_s_n (oShowPolicyURL,      "show-policy-url", "@"),
  ARGPARSE_s_n (oNoShowPolicyURL, "no-show-policy-url", "@"),
  ARGPARSE_s_s (oSigKeyserverURL, "sig-keyserver-url", "@"),
  ARGPARSE_s_n (oShowNotation,      "show-notation", "@"),
  ARGPARSE_s_n (oNoShowNotation, "no-show-notation", "@"),
  ARGPARSE_s_s (oComment, "comment", "@"),
  ARGPARSE_s_n (oDefaultComment, "default-comment", "@"),
  ARGPARSE_s_n (oNoComments, "no-comments", "@"),
  ARGPARSE_s_n (oEmitVersion,      "emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-emit-version", "@"),
  ARGPARSE_s_n (oNoEmitVersion, "no-version", "@"), /* alias */
  ARGPARSE_s_n (oNotDashEscaped, "not-dash-escaped", "@"),
  ARGPARSE_s_n (oEscapeFrom,      "escape-from-lines", "@"),
  ARGPARSE_s_n (oNoEscapeFrom, "no-escape-from-lines", "@"),
  ARGPARSE_s_n (oLockOnce,     "lock-once", "@"),
  ARGPARSE_s_n (oLockMultiple, "lock-multiple", "@"),
  ARGPARSE_s_n (oLockNever,    "lock-never", "@"),
  ARGPARSE_s_i (oLoggerFD,   "logger-fd", "@"),
  ARGPARSE_s_s (oLoggerFile, "log-file", "@"),
  ARGPARSE_s_s (oLoggerFile, "logger-file", "@"),  /* 1.4 compatibility.  */
  ARGPARSE_s_n (oUseEmbeddedFilename,      "use-embedded-filename", "@"),
  ARGPARSE_s_n (oNoUseEmbeddedFilename, "no-use-embedded-filename", "@"),
  ARGPARSE_s_n (oUtf8Strings,      "utf8-strings", "@"),
  ARGPARSE_s_n (oNoUtf8Strings, "no-utf8-strings", "@"),
  ARGPARSE_s_n (oWithFingerprint, "with-fingerprint", "@"),
  ARGPARSE_s_n (oWithICAOSpelling, "with-icao-spelling", "@"),
  ARGPARSE_s_n (oWithKeygrip,     "with-keygrip", "@"),
  ARGPARSE_s_n (oWithSecret,      "with-secret", "@"),
  ARGPARSE_s_s (oDisableCipherAlgo,  "disable-cipher-algo", "@"),
  ARGPARSE_s_s (oDisablePubkeyAlgo,  "disable-pubkey-algo", "@"),
  ARGPARSE_s_n (oAllowNonSelfsignedUID,      "allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oNoAllowNonSelfsignedUID, "no-allow-non-selfsigned-uid", "@"),
  ARGPARSE_s_n (oAllowFreeformUID,      "allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoAllowFreeformUID, "no-allow-freeform-uid", "@"),
  ARGPARSE_s_n (oNoLiteral, "no-literal", "@"),
  ARGPARSE_p_u (oSetFilesize, "set-filesize", "@"),
  ARGPARSE_s_n (oFastListMode, "fast-list-mode", "@"),
  ARGPARSE_s_n (oFixedListMode, "fixed-list-mode", "@"),
  ARGPARSE_s_n (oLegacyListMode, "legacy-list-mode", "@"),
  ARGPARSE_s_n (oListOnly, "list-only", "@"),
  ARGPARSE_s_n (oPrintPKARecords, "print-pka-records", "@"),
  ARGPARSE_s_n (oIgnoreTimeConflict, "ignore-time-conflict", "@"),
  ARGPARSE_s_n (oIgnoreValidFrom,    "ignore-valid-from", "@"),
  ARGPARSE_s_n (oIgnoreCrcError, "ignore-crc-error", "@"),
  ARGPARSE_s_n (oIgnoreMDCError, "ignore-mdc-error", "@"),
  ARGPARSE_s_n (oShowSessionKey, "show-session-key", "@"),
  ARGPARSE_s_s (oOverrideSessionKey, "override-session-key", "@"),
  ARGPARSE_s_n (oNoRandomSeedFile,  "no-random-seed-file", "@"),
  ARGPARSE_s_n (oAutoKeyRetrieve, "auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoAutoKeyRetrieve, "no-auto-key-retrieve", "@"),
  ARGPARSE_s_n (oNoSigCache,         "no-sig-cache", "@"),
  ARGPARSE_s_n (oNoSigCreateCheck,   "no-sig-create-check", "@"),
  ARGPARSE_s_n (oMergeOnly,	  "merge-only", "@" ),
  ARGPARSE_s_n (oAllowSecretKeyImport, "allow-secret-key-import", "@"),
  ARGPARSE_s_n (oTryAllSecrets,  "try-all-secrets", "@"),
  ARGPARSE_s_n (oEnableSpecialFilenames, "enable-special-filenames", "@"),
  ARGPARSE_s_n (oNoExpensiveTrustChecks, "no-expensive-trust-checks", "@"),
  ARGPARSE_s_n (oPreservePermissions, "preserve-permissions", "@"),
  ARGPARSE_s_s (oDefaultPreferenceList,  "default-preference-list", "@"),
  ARGPARSE_s_s (oDefaultKeyserverURL,  "default-keyserver-url", "@"),
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-preferences","@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-preferences","@"),
  ARGPARSE_s_s (oPersonalCompressPreferences,
                                         "personal-compress-preferences", "@"),
  ARGPARSE_s_s (oFakedSystemTime, "faked-system-time", "@"),

  /* Aliases.  I constantly mistype these, and assume other people do
     as well. */
  ARGPARSE_s_s (oPersonalCipherPreferences, "personal-cipher-prefs", "@"),
  ARGPARSE_s_s (oPersonalDigestPreferences, "personal-digest-prefs", "@"),
  ARGPARSE_s_s (oPersonalCompressPreferences, "personal-compress-prefs", "@"),

  ARGPARSE_s_s (oAgentProgram, "agent-program", "@"),
  ARGPARSE_s_s (oDirmngrProgram, "dirmngr-program", "@"),
  ARGPARSE_s_s (oDisplay,    "display",    "@"),
  ARGPARSE_s_s (oTTYname,    "ttyname",    "@"),
  ARGPARSE_s_s (oTTYtype,    "ttytype",    "@"),
  ARGPARSE_s_s (oLCctype,    "lc-ctype",   "@"),
  ARGPARSE_s_s (oLCmessages, "lc-messages","@"),
  ARGPARSE_s_s (oXauthority, "xauthority", "@"),
  ARGPARSE_s_s (oGroup,      "group",      "@"),
  ARGPARSE_s_s (oUnGroup,    "ungroup",    "@"),
  ARGPARSE_s_n (oNoGroups,   "no-groups",  "@"),
  ARGPARSE_s_n (oStrict,     "strict",     "@"),
  ARGPARSE_s_n (oNoStrict,   "no-strict",  "@"),
  ARGPARSE_s_n (oMangleDosFilenames,      "mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oNoMangleDosFilenames, "no-mangle-dos-filenames", "@"),
  ARGPARSE_s_n (oEnableProgressFilter, "enable-progress-filter", "@"),
  ARGPARSE_s_n (oMultifile, "multifile", "@"),
  ARGPARSE_s_s (oKeyidFormat, "keyid-format", "@"),
  ARGPARSE_s_n (oExitOnStatusWriteError, "exit-on-status-write-error", "@"),
  ARGPARSE_s_i (oLimitCardInsertTries, "limit-card-insert-tries", "@"),

  ARGPARSE_s_n (oAllowMultisigVerification,
                "allow-multisig-verification", "@"),
  ARGPARSE_s_n (oEnableLargeRSA, "enable-large-rsa", "@"),
  ARGPARSE_s_n (oDisableLargeRSA, "disable-large-rsa", "@"),
  ARGPARSE_s_n (oEnableDSA2, "enable-dsa2", "@"),
  ARGPARSE_s_n (oDisableDSA2, "disable-dsa2", "@"),
  ARGPARSE_s_n (oAllowMultipleMessages,      "allow-multiple-messages", "@"),
  ARGPARSE_s_n (oNoAllowMultipleMessages, "no-allow-multiple-messages", "@"),
  ARGPARSE_s_n (oAllowWeakDigestAlgos, "allow-weak-digest-algos", "@"),

  /* These two are aliases to help users of the PGP command line
     product use gpg with minimal pain.  Many commands are common
     already as they seem to have borrowed commands from us.  Now I'm
     returning the favor. */
  ARGPARSE_s_s (oLocalUser, "sign-with", "@"),
  ARGPARSE_s_s (oRecipient, "user", "@"),

  ARGPARSE_s_n (oRequireCrossCert, "require-backsigs", "@"),
  ARGPARSE_s_n (oRequireCrossCert, "require-cross-certification", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-backsigs", "@"),
  ARGPARSE_s_n (oNoRequireCrossCert, "no-require-cross-certification", "@"),

  /* New options.  Fixme: Should go more to the top.  */
  ARGPARSE_s_s (oAutoKeyLocate, "auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutoKeyLocate, "no-auto-key-locate", "@"),
  ARGPARSE_s_n (oNoAutostart, "no-autostart", "@"),

  /* Dummy options with warnings.  */
  ARGPARSE_s_n (oUseAgent,      "use-agent", "@"),
  ARGPARSE_s_n (oNoUseAgent, "no-use-agent", "@"),
  ARGPARSE_s_s (oGpgAgentInfo, "gpg-agent-info", "@"),
  ARGPARSE_s_s (oReaderPort, "reader-port", "@"),
  ARGPARSE_s_s (octapiDriver, "ctapi-driver", "@"),
  ARGPARSE_s_s (opcscDriver, "pcsc-driver", "@"),
  ARGPARSE_s_n (oDisableCCID, "disable-ccid", "@"),
  ARGPARSE_s_n (oHonorHttpProxy, "honor-http-proxy", "@"),

  /* Dummy options.  */
  ARGPARSE_s_n (oNoop, "sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "no-sk-comments", "@"),
  ARGPARSE_s_n (oNoop, "compress-keys", "@"),
  ARGPARSE_s_n (oNoop, "compress-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v3-sigs", "@"),
  ARGPARSE_s_n (oNoop, "force-v4-certs", "@"),
  ARGPARSE_s_n (oNoop, "no-force-v4-certs", "@"),

  ARGPARSE_end ()
};


/* The list of supported debug flags.  */
static struct debug_flags_s debug_flags [] =
  {
    { DBG_PACKET_VALUE , "packet"  },
    { DBG_MPI_VALUE    , "mpi"     },
    { DBG_CRYPTO_VALUE , "crypto"  },
    { DBG_FILTER_VALUE , "filter"  },
    { DBG_IOBUF_VALUE  , "iobuf"   },
    { DBG_MEMORY_VALUE , "memory"  },
    { DBG_CACHE_VALUE  , "cache"   },
    { DBG_MEMSTAT_VALUE, "memstat" },
    { DBG_TRUST_VALUE  , "trust"   },
    { DBG_HASHING_VALUE, "hashing" },
    { DBG_CARD_IO_VALUE, "cardio"  },
    { DBG_IPC_VALUE    , "ipc"     },
    { DBG_CLOCK_VALUE  , "clock"   },
    { DBG_LOOKUP_VALUE , "lookup"  },
    { DBG_EXTPROG_VALUE, "extprog" },
    { 0, NULL }
  };


#ifdef ENABLE_SELINUX_HACKS
#define ALWAYS_ADD_KEYRINGS 1
#else
#define ALWAYS_ADD_KEYRINGS 0
#endif


int g10_errors_seen = 0;

static int utf8_strings = 0;
static int maybe_setuid = 1;

static char *build_list( const char *text, char letter,
			 const char *(*mapf)(int), int (*chkf)(int) );
static void set_cmd( enum cmd_and_opt_values *ret_cmd,
			enum cmd_and_opt_values new_cmd );
static void print_mds( const char *fname, int algo );
static void add_notation_data( const char *string, int which );
static void add_policy_url( const char *string, int which );
static void add_keyserver_url( const char *string, int which );
static void emergency_cleanup (void);


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


static int
build_list_pk_test_algo (int algo)
{
  /* Show only one "RSA" string.  If RSA_E or RSA_S is available RSA
     is also available.  */
  if (algo == PUBKEY_ALGO_RSA_E
      || algo == PUBKEY_ALGO_RSA_S)
    return GPG_ERR_DIGEST_ALGO;

  return openpgp_pk_test_algo (algo);
}

static const char *
build_list_pk_algo_name (int algo)
{
  return openpgp_pk_algo_name (algo);
}

static int
build_list_cipher_test_algo (int algo)
{
  return openpgp_cipher_test_algo (algo);
}

static const char *
build_list_cipher_algo_name (int algo)
{
  return openpgp_cipher_algo_name (algo);
}

static int
build_list_md_test_algo (int algo)
{
  /* By default we do not accept MD5 based signatures.  To avoid
     confusion we do not announce support for it either.  */
  if (algo == DIGEST_ALGO_MD5)
    return GPG_ERR_DIGEST_ALGO;

  return openpgp_md_test_algo (algo);
}

static const char *
build_list_md_algo_name (int algo)
{
  return openpgp_md_algo_name (algo);
}


static const char *
my_strusage( int level )
{
  static char *digests, *pubkeys, *ciphers, *zips, *ver_gcry;
  const char *p;

    switch( level ) {
      case 11: p = "@GPG@ (@GNUPG@)";
	break;
      case 13: p = VERSION; break;
      case 17: p = PRINTABLE_OS_NAME; break;
      case 19: p = _("Please report bugs to <@EMAIL@>.\n"); break;

    case 20:
      if (!ver_gcry)
        ver_gcry = make_libversion ("libgcrypt", gcry_check_version);
      p = ver_gcry;
      break;

#ifdef IS_DEVELOPMENT_VERSION
      case 25:
	p="NOTE: THIS IS A DEVELOPMENT VERSION!";
	break;
      case 26:
	p="It is only intended for test purposes and should NOT be";
	break;
      case 27:
	p="used in a production environment or with production keys!";
	break;
#endif

      case 1:
      case 40:	p =
	    _("Usage: @GPG@ [options] [files] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: @GPG@ [options] [files]\n"
	      "Sign, check, encrypt or decrypt\n"
	      "Default operation depends on the input data\n");
	break;

      case 31: p = "\nHome: "; break;
#ifndef __riscos__
      case 32: p = opt.homedir; break;
#else /* __riscos__ */
      case 32: p = make_filename(opt.homedir, NULL); break;
#endif /* __riscos__ */
      case 33: p = _("\nSupported algorithms:\n"); break;
      case 34:
	if (!pubkeys)
            pubkeys = build_list (_("Pubkey: "), 1,
                                  build_list_pk_algo_name,
                                  build_list_pk_test_algo );
	p = pubkeys;
	break;
      case 35:
	if( !ciphers )
	    ciphers = build_list(_("Cipher: "), 'S',
                                 build_list_cipher_algo_name,
                                 build_list_cipher_test_algo );
	p = ciphers;
	break;
      case 36:
	if( !digests )
	    digests = build_list(_("Hash: "), 'H',
                                 build_list_md_algo_name,
                                 build_list_md_test_algo );
	p = digests;
	break;
      case 37:
	if( !zips )
	    zips = build_list(_("Compression: "),'Z',
                              compress_algo_to_string,
                              check_compress_algo);
	p = zips;
	break;

      default:	p = NULL;
    }
    return p;
}


static char *
build_list (const char *text, char letter,
	    const char * (*mapf)(int), int (*chkf)(int))
{
  membuf_t mb;
  int indent;
  int i, j, len;
  const char *s;
  char *string;

  if (maybe_setuid)
    gcry_control (GCRYCTL_INIT_SECMEM, 0, 0);  /* Drop setuid. */

  indent = utf8_charcount (text);
  len = 0;
  init_membuf (&mb, 512);

  for (i=0; i <= 110; i++ )
    {
      if (!chkf (i) && (s = mapf (i)))
        {
          if (mb.len - len > 60)
            {
              put_membuf_str (&mb, ",\n");
              len = mb.len;
              for (j=0; j < indent; j++)
                put_membuf_str (&mb, " ");
	    }
          else if (mb.len)
            put_membuf_str (&mb, ", ");
          else
            put_membuf_str (&mb, text);

          put_membuf_str (&mb, s);
          if (opt.verbose && letter)
            {
              char num[20];
              if (letter == 1)
                snprintf (num, sizeof num, " (%d)", i);
              else
                snprintf (num, sizeof num, " (%c%d)", letter, i);
              put_membuf_str (&mb, num);
            }
	}
    }
  if (mb.len)
    put_membuf_str (&mb, "\n");
  put_membuf (&mb, "", 1);

  string = get_membuf (&mb, NULL);
  return xrealloc (string, strlen (string)+1);
}


static void
wrong_args( const char *text)
{
  es_fprintf (es_stderr, _("usage: %s [options] %s\n"), GPG_NAME, text);
  g10_exit(2);
}


static char *
make_username( const char *string )
{
    char *p;
    if( utf8_strings )
	p = xstrdup(string);
    else
	p = native_to_utf8( string );
    return p;
}


static void
set_opt_session_env (const char *name, const char *value)
{
  gpg_error_t err;

  err = session_env_setenv (opt.session_env, name, value);
  if (err)
    log_fatal ("error setting session environment: %s\n",
               gpg_strerror (err));
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
    opt.debug = DBG_MEMSTAT_VALUE;
  else if (!strcmp (level, "advanced") || (numok && numlvl <= 5))
    opt.debug = DBG_MEMSTAT_VALUE|DBG_TRUST_VALUE|DBG_EXTPROG_VALUE;
  else if (!strcmp (level, "expert")  || (numok && numlvl <= 8))
    opt.debug = (DBG_MEMSTAT_VALUE|DBG_TRUST_VALUE|DBG_EXTPROG_VALUE
                 |DBG_CACHE_VALUE|DBG_LOOKUP|DBG_FILTER_VALUE|DBG_PACKET_VALUE);
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
      g10_exit (2);
    }

  if (opt.debug & DBG_MEMORY_VALUE )
    memory_debug_mode = 1;
  if (opt.debug & DBG_MEMSTAT_VALUE )
    memory_stat_debug_mode = 1;
  if (opt.debug & DBG_MPI_VALUE)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 2);
  if (opt.debug & DBG_CRYPTO_VALUE )
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1);
  if (opt.debug & DBG_IOBUF_VALUE )
    iobuf_debug_mode = 1;
  gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);

  if (opt.debug)
    parse_debug_flag (NULL, &opt.debug, debug_flags);
}



/* We need the home directory also in some other directories, so make
   sure that both variables are always in sync. */
static void
set_homedir (const char *dir)
{
  if (!dir)
    dir = "";
  opt.homedir = dir;
}


/* We set the screen dimensions for UI purposes.  Do not allow screens
   smaller than 80x24 for the sake of simplicity. */
static void
set_screen_dimensions(void)
{
#ifndef HAVE_W32_SYSTEM
  char *str;

  str=getenv("COLUMNS");
  if(str)
    opt.screen_columns=atoi(str);

  str=getenv("LINES");
  if(str)
    opt.screen_lines=atoi(str);
#endif

  if(opt.screen_columns<80 || opt.screen_columns>255)
    opt.screen_columns=80;

  if(opt.screen_lines<24 || opt.screen_lines>255)
    opt.screen_lines=24;
}


/* Helper to open a file FNAME either for reading or writing to be
   used with --status-file etc functions.  Not generally useful but it
   avoids the riscos specific functions and well some Windows people
   might like it too.  Prints an error message and returns -1 on
   error.  On success the file descriptor is returned.  */
static int
open_info_file (const char *fname, int for_write, int binary)
{
#ifdef __riscos__
  return riscos_fdopenfile (fname, for_write);
#elif defined (ENABLE_SELINUX_HACKS)
  /* We can't allow these even when testing for a secured filename
     because files to be secured might not yet been secured.  This is
     similar to the option file but in that case it is unlikely that
     sensitive information may be retrieved by means of error
     messages.  */
  (void)fname;
  (void)for_write;
  (void)binary;
  return -1;
#else
  int fd;

  if (binary)
    binary = MY_O_BINARY;

/*   if (is_secured_filename (fname)) */
/*     { */
/*       fd = -1; */
/*       gpg_err_set_errno (EPERM); */
/*     } */
/*   else */
/*     { */
      do
        {
          if (for_write)
            fd = open (fname, O_CREAT | O_TRUNC | O_WRONLY | binary,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
          else
            fd = open (fname, O_RDONLY | binary);
        }
      while (fd == -1 && errno == EINTR);
/*     } */
  if ( fd == -1)
    log_error ( for_write? _("can't create '%s': %s\n")
                         : _("can't open '%s': %s\n"), fname, strerror(errno));

  return fd;
#endif
}

static void
set_cmd( enum cmd_and_opt_values *ret_cmd, enum cmd_and_opt_values new_cmd )
{
    enum cmd_and_opt_values cmd = *ret_cmd;

    if( !cmd || cmd == new_cmd )
	cmd = new_cmd;
    else if( cmd == aSign && new_cmd == aEncr )
	cmd = aSignEncr;
    else if( cmd == aEncr && new_cmd == aSign )
	cmd = aSignEncr;
    else if( cmd == aSign && new_cmd == aSym )
	cmd = aSignSym;
    else if( cmd == aSym && new_cmd == aSign )
	cmd = aSignSym;
    else if( cmd == aSym && new_cmd == aEncr )
	cmd = aEncrSym;
    else if( cmd == aEncr && new_cmd == aSym )
	cmd = aEncrSym;
    else if (cmd == aSignEncr && new_cmd == aSym)
        cmd = aSignEncrSym;
    else if (cmd == aSignSym && new_cmd == aEncr)
        cmd = aSignEncrSym;
    else if (cmd == aEncrSym && new_cmd == aSign)
        cmd = aSignEncrSym;
    else if(	( cmd == aSign	   && new_cmd == aClearsign )
	     || ( cmd == aClearsign && new_cmd == aSign )  )
	cmd = aClearsign;
    else {
	log_error(_("conflicting commands\n"));
	g10_exit(2);
    }

    *ret_cmd = cmd;
}


static void
add_group(char *string)
{
  char *name,*value;
  struct groupitem *item;

  /* Break off the group name */
  name=strsep(&string,"=");
  if(string==NULL)
    {
      log_error(_("no = sign found in group definition '%s'\n"),name);
      return;
    }

  trim_trailing_ws(name,strlen(name));

  /* Does this group already exist? */
  for(item=opt.grouplist;item;item=item->next)
    if(strcasecmp(item->name,name)==0)
      break;

  if(!item)
    {
      item=xmalloc(sizeof(struct groupitem));
      item->name=name;
      item->next=opt.grouplist;
      item->values=NULL;
      opt.grouplist=item;
    }

  /* Break apart the values */
  while ((value= strsep(&string," \t")))
    {
      if (*value)
        add_to_strlist2(&item->values,value,utf8_strings);
    }
}


static void
rm_group(char *name)
{
  struct groupitem *item,*last=NULL;

  trim_trailing_ws(name,strlen(name));

  for(item=opt.grouplist;item;last=item,item=item->next)
    {
      if(strcasecmp(item->name,name)==0)
	{
	  if(last)
	    last->next=item->next;
	  else
	    opt.grouplist=item->next;

	  free_strlist(item->values);
	  xfree(item);
	  break;
	}
    }
}


/* We need to check three things.

   0) The homedir.  It must be x00, a directory, and owned by the
   user.

   1) The options/gpg.conf file.  Okay unless it or its containing
   directory is group or other writable or not owned by us.  Disable
   exec in this case.

   2) Extensions.  Same as #1.

   Returns true if the item is unsafe. */
static int
check_permissions (const char *path, int item)
{
#if defined(HAVE_STAT) && !defined(HAVE_DOSISH_SYSTEM)
  static int homedir_cache=-1;
  char *tmppath,*dir;
  struct stat statbuf,dirbuf;
  int homedir=0,ret=0,checkonly=0;
  int perm=0,own=0,enc_dir_perm=0,enc_dir_own=0;

  if(opt.no_perm_warn)
    return 0;

  assert(item==0 || item==1 || item==2);

  /* extensions may attach a path */
  if(item==2 && path[0]!=DIRSEP_C)
    {
      if(strchr(path,DIRSEP_C))
	tmppath=make_filename(path,NULL);
      else
	tmppath=make_filename(gnupg_libdir (),path,NULL);
    }
  else
    tmppath=xstrdup(path);

  /* If the item is located in the homedir, but isn't the homedir,
     don't continue if we already checked the homedir itself.  This is
     to avoid user confusion with an extra options file warning which
     could be rectified if the homedir itself had proper
     permissions. */
  if(item!=0 && homedir_cache>-1
     && ascii_strncasecmp(opt.homedir,tmppath,strlen(opt.homedir))==0)
    {
      ret=homedir_cache;
      goto end;
    }

  /* It's okay if the file or directory doesn't exist */
  if(stat(tmppath,&statbuf)!=0)
    {
      ret=0;
      goto end;
    }

  /* Now check the enclosing directory.  Theoretically, we could walk
     this test up to the root directory /, but for the sake of sanity,
     I'm stopping at one level down. */
  dir=make_dirname(tmppath);

  if(stat(dir,&dirbuf)!=0 || !S_ISDIR(dirbuf.st_mode))
    {
      /* Weird error */
      ret=1;
      goto end;
    }

  xfree(dir);

  /* Assume failure */
  ret=1;

  if(item==0)
    {
      /* The homedir must be x00, a directory, and owned by the user. */

      if(S_ISDIR(statbuf.st_mode))
	{
	  if(statbuf.st_uid==getuid())
	    {
	      if((statbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
		ret=0;
	      else
		perm=1;
	    }
	  else
	    own=1;

	  homedir_cache=ret;
	}
    }
  else if(item==1 || item==2)
    {
      /* The options or extension file.  Okay unless it or its
	 containing directory is group or other writable or not owned
	 by us or root. */

      if(S_ISREG(statbuf.st_mode))
	{
	  if(statbuf.st_uid==getuid() || statbuf.st_uid==0)
	    {
	      if((statbuf.st_mode & (S_IWGRP|S_IWOTH))==0)
		{
		  /* it's not writable, so make sure the enclosing
                     directory is also not writable */
		  if(dirbuf.st_uid==getuid() || dirbuf.st_uid==0)
		    {
		      if((dirbuf.st_mode & (S_IWGRP|S_IWOTH))==0)
			ret=0;
		      else
			enc_dir_perm=1;
		    }
		  else
		    enc_dir_own=1;
		}
	      else
		{
		  /* it's writable, so the enclosing directory had
                     better not let people get to it. */
		  if(dirbuf.st_uid==getuid() || dirbuf.st_uid==0)
		    {
		      if((dirbuf.st_mode & (S_IRWXG|S_IRWXO))==0)
			ret=0;
		      else
			perm=enc_dir_perm=1; /* unclear which one to fix! */
		    }
		  else
		    enc_dir_own=1;
		}
	    }
	  else
	    own=1;
	}
    }
  else
    BUG();

  if(!checkonly)
    {
      if(own)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe ownership on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe ownership on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe ownership on"
		       " extension '%s'\n"),tmppath);
	}
      if(perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe permissions on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe permissions on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe permissions on"
		       " extension '%s'\n"),tmppath);
	}
      if(enc_dir_own)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory ownership on"
		       " extension '%s'\n"),tmppath);
	}
      if(enc_dir_perm)
	{
	  if(item==0)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " homedir '%s'\n"),tmppath);
	  else if(item==1)
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " configuration file '%s'\n"),tmppath);
	  else
	    log_info(_("WARNING: unsafe enclosing directory permissions on"
		       " extension '%s'\n"),tmppath);
	}
    }

 end:
  xfree(tmppath);

  if(homedir)
    homedir_cache=ret;

  return ret;

#else /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
  (void)path;
  (void)item;
  return 0;
#endif /*!(HAVE_STAT && !HAVE_DOSISH_SYSTEM)*/
}


/* Print the OpenPGP defined algo numbers.  */
static void
print_algo_numbers(int (*checker)(int))
{
  int i,first=1;

  for(i=0;i<=110;i++)
    {
      if(!checker(i))
	{
	  if(first)
	    first=0;
	  else
	    es_printf (";");
	  es_printf ("%d",i);
	}
    }
}


static void
print_algo_names(int (*checker)(int),const char *(*mapper)(int))
{
  int i,first=1;

  for(i=0;i<=110;i++)
    {
      if(!checker(i))
	{
	  if(first)
	    first=0;
	  else
	    es_printf (";");
	  es_printf ("%s",mapper(i));
	}
    }
}

/* In the future, we can do all sorts of interesting configuration
   output here.  For now, just give "group" as the Enigmail folks need
   it, and pubkey, cipher, hash, and compress as they may be useful
   for frontends. */
static void
list_config(char *items)
{
  int show_all = !items;
  char *name = NULL;
  const char *s;
  struct groupitem *giter;
  int first, iter;

  if(!opt.with_colons)
    return;

  while(show_all || (name=strsep(&items," ")))
    {
      int any=0;

      if(show_all || ascii_strcasecmp(name,"group")==0)
	{
	  for (giter = opt.grouplist; giter; giter = giter->next)
	    {
	      strlist_t sl;

	      es_fprintf (es_stdout, "cfg:group:");
	      es_write_sanitized (es_stdout, giter->name, strlen(giter->name),
                                  ":", NULL);
	      es_putc (':', es_stdout);

	      for(sl=giter->values; sl; sl=sl->next)
		{
		  es_write_sanitized (es_stdout, sl->d, strlen (sl->d),
                                      ":;", NULL);
		  if(sl->next)
                    es_printf(";");
		}

              es_printf("\n");
	    }

	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"version")==0)
	{
	  es_printf("cfg:version:");
	  es_write_sanitized (es_stdout, VERSION, strlen(VERSION), ":", NULL);
          es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"pubkey")==0)
	{
	  es_printf ("cfg:pubkey:");
	  print_algo_numbers (build_list_pk_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"pubkeyname")==0)
	{
	  es_printf ("cfg:pubkeyname:");
	  print_algo_names (build_list_pk_test_algo,
                            build_list_pk_algo_name);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"cipher")==0)
	{
	  es_printf ("cfg:cipher:");
	  print_algo_numbers (build_list_cipher_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all || !ascii_strcasecmp (name,"ciphername"))
	{
	  es_printf ("cfg:ciphername:");
	  print_algo_names (build_list_cipher_test_algo,
                            build_list_cipher_algo_name);
	  es_printf ("\n");
	  any = 1;
	}

      if(show_all
	 || ascii_strcasecmp(name,"digest")==0
	 || ascii_strcasecmp(name,"hash")==0)
	{
	  es_printf ("cfg:digest:");
	  print_algo_numbers (build_list_md_test_algo);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all
          || !ascii_strcasecmp(name,"digestname")
          || !ascii_strcasecmp(name,"hashname"))
	{
	  es_printf ("cfg:digestname:");
	  print_algo_names (build_list_md_test_algo,
                            build_list_md_algo_name);
	  es_printf ("\n");
	  any=1;
	}

      if(show_all || ascii_strcasecmp(name,"compress")==0)
	{
	  es_printf ("cfg:compress:");
	  print_algo_numbers(check_compress_algo);
	  es_printf ("\n");
	  any=1;
	}

      if (show_all || !ascii_strcasecmp(name,"ccid-reader-id"))
	{
          /* We ignore this for GnuPG 1.4 backward compatibility.  */
	  any=1;
	}

      if (show_all || !ascii_strcasecmp (name,"curve"))
	{
	  es_printf ("cfg:curve:");
          for (iter=0, first=1; (s = openpgp_enum_curves (&iter)); first=0)
            es_printf ("%s%s", first?"":";", s);
	  es_printf ("\n");
	  any=1;
	}

      /* Curve OIDs are rarely useful and thus only printed if requested.  */
      if (name && !ascii_strcasecmp (name,"curveoid"))
	{
	  es_printf ("cfg:curveoid:");
          for (iter=0, first=1; (s = openpgp_enum_curves (&iter)); first = 0)
            {
              s = openpgp_curve_to_oid (s, NULL);
              es_printf ("%s%s", first?"":";", s? s:"[?]");
            }
	  es_printf ("\n");
	  any=1;
	}

      if(show_all)
	break;

      if(!any)
	log_error(_("unknown configuration item '%s'\n"),name);
    }
}


/* List options and default values in the GPG Conf format.  This is a
   new tool distributed with gnupg 1.9.x but we also want some limited
   support in older gpg versions.  The output is the name of the
   configuration file and a list of options available for editing by
   gpgconf.  */
static void
gpgconf_list (const char *configfile)
{
  char *configfile_esc = percent_escape (configfile, NULL);

  es_printf ("%s-%s.conf:%lu:\"%s\n",
             GPGCONF_NAME, GPG_NAME,
             GC_OPT_FLAG_DEFAULT,
             configfile_esc ? configfile_esc : "/dev/null");
  es_printf ("verbose:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("quiet:%lu:\n",   GC_OPT_FLAG_NONE);
  es_printf ("keyserver:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("reader-port:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("default-key:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("encrypt-to:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("try-secret-key:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("auto-key-locate:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("log-file:%lu:\n", GC_OPT_FLAG_NONE);
  es_printf ("debug-level:%lu:\"none:\n", GC_OPT_FLAG_DEFAULT);
  es_printf ("group:%lu:\n", GC_OPT_FLAG_NONE);

  /* The next one is an info only item and should match the macros at
     the top of keygen.c  */
  es_printf ("default_pubkey_algo:%lu:\"%s:\n", GC_OPT_FLAG_DEFAULT,
             "RSA-2048");

  xfree (configfile_esc);
}


static int
parse_subpacket_list(char *list)
{
  char *tok;
  byte subpackets[128],i;
  int count=0;

  if(!list)
    {
      /* No arguments means all subpackets */
      memset(subpackets+1,1,sizeof(subpackets)-1);
      count=127;
    }
  else
    {
      memset(subpackets,0,sizeof(subpackets));

      /* Merge with earlier copy */
      if(opt.show_subpackets)
	{
	  byte *in;

	  for(in=opt.show_subpackets;*in;in++)
	    {
	      if(*in>127 || *in<1)
		BUG();

	      if(!subpackets[*in])
		count++;
	      subpackets[*in]=1;
	    }
	}

      while((tok=strsep(&list," ,")))
	{
	  if(!*tok)
	    continue;

	  i=atoi(tok);
	  if(i>127 || i<1)
	    return 0;

	  if(!subpackets[i])
	    count++;
	  subpackets[i]=1;
	}
    }

  xfree(opt.show_subpackets);
  opt.show_subpackets=xmalloc(count+1);
  opt.show_subpackets[count--]=0;

  for(i=1;i<128 && count>=0;i++)
    if(subpackets[i])
      opt.show_subpackets[count--]=i;

  return 1;
}


static int
parse_list_options(char *str)
{
  char *subpackets=""; /* something that isn't NULL */
  struct parse_options lopts[]=
    {
      {"show-photos",LIST_SHOW_PHOTOS,NULL,
       N_("display photo IDs during key listings")},
      {"show-usage",LIST_SHOW_USAGE,NULL,
       N_("show key usage information during key listings")},
      {"show-policy-urls",LIST_SHOW_POLICY_URLS,NULL,
       N_("show policy URLs during signature listings")},
      {"show-notations",LIST_SHOW_NOTATIONS,NULL,
       N_("show all notations during signature listings")},
      {"show-std-notations",LIST_SHOW_STD_NOTATIONS,NULL,
       N_("show IETF standard notations during signature listings")},
      {"show-standard-notations",LIST_SHOW_STD_NOTATIONS,NULL,
       NULL},
      {"show-user-notations",LIST_SHOW_USER_NOTATIONS,NULL,
       N_("show user-supplied notations during signature listings")},
      {"show-keyserver-urls",LIST_SHOW_KEYSERVER_URLS,NULL,
       N_("show preferred keyserver URLs during signature listings")},
      {"show-uid-validity",LIST_SHOW_UID_VALIDITY,NULL,
       N_("show user ID validity during key listings")},
      {"show-unusable-uids",LIST_SHOW_UNUSABLE_UIDS,NULL,
       N_("show revoked and expired user IDs in key listings")},
      {"show-unusable-subkeys",LIST_SHOW_UNUSABLE_SUBKEYS,NULL,
       N_("show revoked and expired subkeys in key listings")},
      {"show-keyring",LIST_SHOW_KEYRING,NULL,
       N_("show the keyring name in key listings")},
      {"show-sig-expire",LIST_SHOW_SIG_EXPIRE,NULL,
       N_("show expiration dates during signature listings")},
      {"show-sig-subpackets",LIST_SHOW_SIG_SUBPACKETS,NULL,
       NULL},
      {NULL,0,NULL,NULL}
    };

  /* C99 allows for non-constant initializers, but we'd like to
     compile everywhere, so fill in the show-sig-subpackets argument
     here.  Note that if the parse_options array changes, we'll have
     to change the subscript here. */
  lopts[13].value=&subpackets;

  if(parse_options(str,&opt.list_options,lopts,1))
    {
      if(opt.list_options&LIST_SHOW_SIG_SUBPACKETS)
	{
	  /* Unset so users can pass multiple lists in. */
	  opt.list_options&=~LIST_SHOW_SIG_SUBPACKETS;
	  if(!parse_subpacket_list(subpackets))
	    return 0;
	}
      else if(subpackets==NULL && opt.show_subpackets)
	{
	  /* User did 'no-show-subpackets' */
	  xfree(opt.show_subpackets);
	  opt.show_subpackets=NULL;
	}

      return 1;
    }
  else
    return 0;
}


/* Collapses argc/argv into a single string that must be freed */
static char *
collapse_args(int argc,char *argv[])
{
  char *str=NULL;
  int i,first=1,len=0;

  for(i=0;i<argc;i++)
    {
      len+=strlen(argv[i])+2;
      str=xrealloc(str,len);
      if(first)
	{
	  str[0]='\0';
	  first=0;
	}
      else
	strcat(str," ");

      strcat(str,argv[i]);
    }

  return str;
}


#ifndef NO_TRUST_MODELS
static void
parse_trust_model(const char *model)
{
  if(ascii_strcasecmp(model,"pgp")==0)
    opt.trust_model=TM_PGP;
  else if(ascii_strcasecmp(model,"classic")==0)
    opt.trust_model=TM_CLASSIC;
  else if(ascii_strcasecmp(model,"always")==0)
    opt.trust_model=TM_ALWAYS;
  else if(ascii_strcasecmp(model,"direct")==0)
    opt.trust_model=TM_DIRECT;
  else if(ascii_strcasecmp(model,"auto")==0)
    opt.trust_model=TM_AUTO;
  else
    log_error("unknown trust model '%s'\n",model);
}
#endif /*NO_TRUST_MODELS*/


/* This fucntion called to initialized a new control object.  It is
   assumed that this object has been zeroed out before calling this
   function. */
static void
gpg_init_default_ctrl (ctrl_t ctrl)
{
  (void)ctrl;
}


/* This function is called to deinitialize a control object.  It is
   not deallocated. */
static void
gpg_deinit_default_ctrl (ctrl_t ctrl)
{
  gpg_dirmngr_deinit_session_data (ctrl);
}


char *
get_default_configname (void)
{
  char *configname = NULL;
  char *name = xstrdup (GPG_NAME EXTSEP_S "conf-" SAFE_VERSION);
  char *ver = &name[strlen (GPG_NAME EXTSEP_S "conf-")];

  do
    {
      if (configname)
	{
	  char *tok;

	  xfree (configname);
	  configname = NULL;

	  if ((tok = strrchr (ver, SAFE_VERSION_DASH)))
	    *tok='\0';
	  else if ((tok = strrchr (ver, SAFE_VERSION_DOT)))
	    *tok='\0';
	  else
	    break;
	}

      configname = make_filename (opt.homedir, name, NULL);
    }
  while (access (configname, R_OK));

  xfree(name);

  if (! configname)
    configname = make_filename (opt.homedir, GPG_NAME EXTSEP_S "conf", NULL);
  if (! access (configname, R_OK))
    {
      /* Print a warning when both config files are present.  */
      char *p = make_filename (opt.homedir, "options", NULL);
      if (! access (p, R_OK))
	log_info (_("Note: old default options file '%s' ignored\n"), p);
      xfree (p);
    }
  else
    {
      /* Use the old default only if it exists.  */
      char *p = make_filename (opt.homedir, "options", NULL);
      if (!access (p, R_OK))
	{
	  xfree (configname);
	  configname = p;
	}
      else
	xfree (p);
    }

  return configname;
}


int
main (int argc, char **argv)
{
    ARGPARSE_ARGS pargs;
    IOBUF a;
    int rc=0;
    int orig_argc;
    char **orig_argv;
    const char *fname;
    char *username;
    int may_coredump;
    strlist_t sl, remusr= NULL, locusr=NULL;
    strlist_t nrings = NULL;
    armor_filter_context_t *afx = NULL;
    int detached_sig = 0;
    FILE *configfp = NULL;
    char *configname = NULL;
    char *save_configname = NULL;
    char *default_configname = NULL;
    unsigned configlineno;
    int parse_debug = 0;
    int default_config = 1;
    int default_keyring = 1;
    int greeting = 0;
    int nogreeting = 0;
    char *logfile = NULL;
    int use_random_seed = 1;
    enum cmd_and_opt_values cmd = 0;
    const char *debug_level = NULL;
#ifndef NO_TRUST_MODELS
    const char *trustdb_name = NULL;
#endif /*!NO_TRUST_MODELS*/
    char *def_cipher_string = NULL;
    char *def_digest_string = NULL;
    char *compress_algo_string = NULL;
    char *cert_digest_string = NULL;
    char *s2k_cipher_string = NULL;
    char *s2k_digest_string = NULL;
    char *pers_cipher_list = NULL;
    char *pers_digest_list = NULL;
    char *pers_compress_list = NULL;
    int eyes_only=0;
    int multifile=0;
    int pwfd = -1;
    int fpr_maybe_cmd = 0; /* --fingerprint maybe a command.  */
    int any_explicit_recipient = 0;
    int require_secmem=0,got_secmem=0;
    struct assuan_malloc_hooks malloc_hooks;
    ctrl_t ctrl;

#ifdef __riscos__
    opt.lock_once = 1;
#endif /* __riscos__ */


    /* Please note that we may running SUID(ROOT), so be very CAREFUL
       when adding any stuff between here and the call to
       secmem_init() somewhere after the option parsing. */
    early_system_init ();
    gnupg_reopen_std (GPG_NAME);
    trap_unaligned ();
    gnupg_rl_initialize ();
    set_strusage (my_strusage);
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    log_set_prefix (GPG_NAME, 1);

    /* Make sure that our subsystems are ready.  */
    i18n_init();
    init_common_subsystems (&argc, &argv);

    /* Check that the libraries are suitable.  Do it right here because the
       option parsing may need services of the library.  */
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION) )
      {
        log_fatal ( _("libgcrypt is too old (need %s, have %s)\n"),
                    NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL) );
      }

    /* Use our own logging handler for Libcgrypt.  */
    setup_libgcrypt_logging ();

    /* Put random number into secure memory */
    gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);

    may_coredump = disable_core_dumps();

    gnupg_init_signals (0, emergency_cleanup);

    dotlock_create (NULL, 0); /* Register lock file cleanup. */

    opt.autostart = 1;
    opt.session_env = session_env_new ();
    if (!opt.session_env)
      log_fatal ("error allocating session environment block: %s\n",
                 strerror (errno));

    opt.command_fd = -1; /* no command fd */
    opt.compress_level = -1; /* defaults to standard compress level */
    opt.bz2_compress_level = -1; /* defaults to standard compress level */
    /* note: if you change these lines, look at oOpenPGP */
    opt.def_cipher_algo = 0;
    opt.def_digest_algo = 0;
    opt.cert_digest_algo = 0;
    opt.compress_algo = -1; /* defaults to DEFAULT_COMPRESS_ALGO */
    opt.s2k_mode = 3; /* iterated+salted */
    opt.s2k_count = 0; /* Auto-calibrate when needed.  */
    opt.s2k_cipher_algo = DEFAULT_CIPHER_ALGO;
    opt.completes_needed = 1;
    opt.marginals_needed = 3;
    opt.max_cert_depth = 5;
    opt.escape_from = 1;
    opt.flags.require_cross_cert = 1;
    opt.import_options = 0;
    opt.export_options = EXPORT_ATTRIBUTES;
    opt.keyserver_options.import_options = IMPORT_REPAIR_PKS_SUBKEY_BUG;
    opt.keyserver_options.export_options = EXPORT_ATTRIBUTES;
    opt.keyserver_options.options = KEYSERVER_HONOR_PKA_RECORD;
    opt.verify_options = (LIST_SHOW_UID_VALIDITY
                          | VERIFY_SHOW_POLICY_URLS
                          | VERIFY_SHOW_STD_NOTATIONS
                          | VERIFY_SHOW_KEYSERVER_URLS);
    opt.list_options   = LIST_SHOW_UID_VALIDITY;
#ifdef NO_TRUST_MODELS
    opt.trust_model = TM_ALWAYS;
#else
    opt.trust_model = TM_AUTO;
#endif
    opt.mangle_dos_filenames = 0;
    opt.min_cert_level = 2;
    set_screen_dimensions ();
    opt.keyid_format = KF_SHORT;
    opt.def_sig_expire = "0";
    opt.def_cert_expire = "0";
    set_homedir (default_homedir ());
    opt.passphrase_repeat = 1;
    opt.emit_version = 1; /* Limit to the major number.  */

    /* Check whether we have a config file on the command line.  */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= (ARGPARSE_FLAG_KEEP | ARGPARSE_FLAG_NOVERSION);
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == oDebug || pargs.r_opt == oDebugAll )
	    parse_debug++;
	else if (pargs.r_opt == oDebugIOLBF)
            es_setvbuf (es_stdout, NULL, _IOLBF, 0);
	else if( pargs.r_opt == oOptions ) {
	    /* yes there is one, so we do not try the default one, but
	     * read the option file when it is encountered at the commandline
	     */
	    default_config = 0;
	}
	else if( pargs.r_opt == oNoOptions )
          {
	    default_config = 0; /* --no-options */
            opt.no_homedir_creation = 1;
          }
        else if( pargs.r_opt == oHomedir )
	    set_homedir ( pargs.r.ret_str );
	else if( pargs.r_opt == oNoPermissionWarn )
	    opt.no_perm_warn=1;
	else if (pargs.r_opt == oStrict )
	  {
	    /* Not used */
	  }
	else if (pargs.r_opt == oNoStrict )
	  {
	    /* Not used */
	  }
    }

#ifdef HAVE_DOSISH_SYSTEM
    if ( strchr (opt.homedir,'\\') ) {
        char *d, *buf = xmalloc (strlen (opt.homedir)+1);
        const char *s = opt.homedir;
        for (d=buf,s=opt.homedir; *s; s++)
          {
            *d++ = *s == '\\'? '/': *s;
#ifdef HAVE_W32_SYSTEM
            if (s[1] && IsDBCSLeadByte (*s))
              *d++ = *++s;
#endif
          }
        *d = 0;
        set_homedir (buf);
    }
#endif

    /* Initialize the secure memory. */
    if (!gcry_control (GCRYCTL_INIT_SECMEM, SECMEM_BUFFER_SIZE, 0))
      got_secmem = 1;
#if defined(HAVE_GETUID) && defined(HAVE_GETEUID)
    /* There should be no way to get to this spot while still carrying
       setuid privs.  Just in case, bomb out if we are. */
    if ( getuid () != geteuid () )
      BUG ();
#endif
    maybe_setuid = 0;

    /* Okay, we are now working under our real uid */

    /* malloc hooks go here ... */
    malloc_hooks.malloc = gcry_malloc;
    malloc_hooks.realloc = gcry_realloc;
    malloc_hooks.free = gcry_free;
    assuan_set_malloc_hooks (&malloc_hooks);
    assuan_set_gpg_err_source (GPG_ERR_SOURCE_DEFAULT);
    setup_libassuan_logging (&opt.debug);

    /* Try for a version specific config file first */
    default_configname = get_default_configname ();
    if (default_config)
      configname = xstrdup (default_configname);

    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= ARGPARSE_FLAG_KEEP;

    /* By this point we have a homedir, and cannot change it. */
    check_permissions(opt.homedir,0);

  next_pass:
    if( configname ) {
      if(check_permissions(configname,1))
	{
	  /* If any options file is unsafe, then disable any external
	     programs for keyserver calls or photo IDs.  Since the
	     external program to call is set in the options file, a
	     unsafe options file can lead to an arbitrary program
	     being run. */

	  opt.exec_disable=1;
	}

	configlineno = 0;
	configfp = fopen( configname, "r" );
        if (configfp && is_secured_file (fileno (configfp)))
          {
            fclose (configfp);
            configfp = NULL;
            gpg_err_set_errno (EPERM);
          }
	if( !configfp ) {
	    if( default_config ) {
		if( parse_debug )
		    log_info(_("Note: no default option file '%s'\n"),
							    configname );
	    }
	    else {
		log_error(_("option file '%s': %s\n"),
				    configname, strerror(errno) );
		g10_exit(2);
	    }
	    xfree(configname); configname = NULL;
	}
	if( parse_debug && configname )
	    log_info(_("reading options from '%s'\n"), configname );
	default_config = 0;
    }

    while( optfile_parse( configfp, configname, &configlineno,
						&pargs, opts) )
      {
	switch( pargs.r_opt )
	  {
	  case aCheckKeys:
	  case aListConfig:
	  case aListGcryptConfig:
          case aGPGConfList:
          case aGPGConfTest:
	  case aListPackets:
	  case aImport:
	  case aFastImport:
	  case aSendKeys:
	  case aRecvKeys:
	  case aSearchKeys:
	  case aRefreshKeys:
	  case aFetchKeys:
	  case aExport:
#ifdef ENABLE_CARD_SUPPORT
          case aCardStatus:
          case aCardEdit:
          case aChangePIN:
#endif /* ENABLE_CARD_SUPPORT*/
	  case aListKeys:
	  case aLocateKeys:
	  case aListSigs:
	  case aExportSecret:
	  case aExportSecretSub:
	  case aSym:
	  case aClearsign:
	  case aGenRevoke:
	  case aDesigRevoke:
	  case aPrimegen:
	  case aGenRandom:
	  case aPrintMD:
	  case aPrintMDs:
	  case aListTrustDB:
	  case aCheckTrustDB:
	  case aUpdateTrustDB:
	  case aFixTrustDB:
	  case aListTrustPath:
	  case aDeArmor:
	  case aEnArmor:
	  case aSign:
	  case aQuickSignKey:
	  case aQuickLSignKey:
	  case aSignKey:
	  case aLSignKey:
	  case aStore:
	  case aQuickKeygen:
	  case aQuickAddUid:
	  case aExportOwnerTrust:
	  case aImportOwnerTrust:
          case aRebuildKeydbCaches:
            set_cmd (&cmd, pargs.r_opt);
            break;

	  case aKeygen:
	  case aFullKeygen:
	  case aEditKey:
	  case aDeleteSecretKeys:
	  case aDeleteSecretAndPublicKeys:
	  case aDeleteKeys:
          case aPasswd:
            set_cmd (&cmd, pargs.r_opt);
            greeting=1;
            break;

	  case aDetachedSign: detached_sig = 1; set_cmd( &cmd, aSign ); break;

	  case aDecryptFiles: multifile=1; /* fall through */
	  case aDecrypt: set_cmd( &cmd, aDecrypt); break;

	  case aEncrFiles: multifile=1; /* fall through */
	  case aEncr: set_cmd( &cmd, aEncr); break;

	  case aVerifyFiles: multifile=1; /* fall through */
	  case aVerify: set_cmd( &cmd, aVerify); break;

          case aServer:
            set_cmd (&cmd, pargs.r_opt);
            opt.batch = 1;
            break;

	  case oArmor: opt.armor = 1; opt.no_armor=0; break;
	  case oOutput: opt.outfile = pargs.r.ret_str; break;
	  case oMaxOutput: opt.max_output = pargs.r.ret_ulong; break;
	  case oQuiet: opt.quiet = 1; break;
	  case oNoTTY: tty_no_terminal(1); break;
	  case oDryRun: opt.dry_run = 1; break;
	  case oInteractive: opt.interactive = 1; break;
	  case oVerbose:
	    opt.verbose++;
            gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
	    opt.list_options|=LIST_SHOW_UNUSABLE_UIDS;
	    opt.list_options|=LIST_SHOW_UNUSABLE_SUBKEYS;
	    break;

	  case oBatch:
            opt.batch = 1;
            nogreeting = 1;
            break;

          case oUseAgent: /* Dummy. */
            break;

          case oNoUseAgent:
	    obsolete_option (configname, configlineno, "no-use-agent");
            break;
	  case oGpgAgentInfo:
	    obsolete_option (configname, configlineno, "gpg-agent-info");
            break;
          case oReaderPort:
	    obsolete_scdaemon_option (configname, configlineno, "reader-port");
            break;
          case octapiDriver:
	    obsolete_scdaemon_option (configname, configlineno, "ctapi-driver");
            break;
          case opcscDriver:
	    obsolete_scdaemon_option (configname, configlineno, "pcsc-driver");
            break;
          case oDisableCCID:
	    obsolete_scdaemon_option (configname, configlineno, "disable-ccid");
            break;
          case oHonorHttpProxy:
	    obsolete_option (configname, configlineno, "honor-http-proxy");
            break;

	  case oAnswerYes: opt.answer_yes = 1; break;
	  case oAnswerNo: opt.answer_no = 1; break;
	  case oKeyring: append_to_strlist( &nrings, pargs.r.ret_str); break;
	  case oPrimaryKeyring:
	    sl = append_to_strlist (&nrings, pargs.r.ret_str);
	    sl->flags = KEYDB_RESOURCE_FLAG_PRIMARY;
	    break;
	  case oShowKeyring:
	    deprecated_warning(configname,configlineno,"--show-keyring",
			       "--list-options ","show-keyring");
	    opt.list_options|=LIST_SHOW_KEYRING;
	    break;

	  case oDebug:
            if (parse_debug_flag (pargs.r.ret_str, &opt.debug, debug_flags))
              {
                pargs.r_opt = ARGPARSE_INVALID_ARG;
                pargs.err = ARGPARSE_PRINT_ERROR;
              }
            break;

	  case oDebugAll: opt.debug = ~0; break;
          case oDebugLevel: debug_level = pargs.r.ret_str; break;

          case oDebugIOLBF: break; /* Already set in pre-parse step.  */

	  case oStatusFD:
            set_status_fd ( translate_sys2libc_fd_int (pargs.r.ret_int, 1) );
            break;
	  case oStatusFile:
            set_status_fd ( open_info_file (pargs.r.ret_str, 1, 0) );
            break;
	  case oAttributeFD:
            set_attrib_fd ( translate_sys2libc_fd_int (pargs.r.ret_int, 1) );
            break;
	  case oAttributeFile:
            set_attrib_fd ( open_info_file (pargs.r.ret_str, 1, 1) );
            break;
	  case oLoggerFD:
            log_set_fd (translate_sys2libc_fd_int (pargs.r.ret_int, 1));
            break;
          case oLoggerFile:
            logfile = pargs.r.ret_str;
            break;

	  case oWithFingerprint:
            opt.with_fingerprint = 1;
            opt.fingerprint++;
            break;
	  case oWithICAOSpelling:
            opt.with_icao_spelling = 1;
            break;
	  case oFingerprint:
            opt.fingerprint++;
            fpr_maybe_cmd = 1;
            break;

	  case oWithKeygrip:
            opt.with_keygrip = 1;
            break;

	  case oWithSecret:
            opt.with_secret = 1;
            break;

	  case oSecretKeyring:
            /* Ignore this old option.  */
            break;

	  case oOptions:
	    /* config files may not be nested (silently ignore them) */
	    if( !configfp ) {
		xfree(configname);
		configname = xstrdup(pargs.r.ret_str);
		goto next_pass;
	    }
	    break;
	  case oNoArmor: opt.no_armor=1; opt.armor=0; break;
	  case oNoDefKeyring: default_keyring = 0; break;
	  case oNoGreeting: nogreeting = 1; break;
	  case oNoVerbose:
            opt.verbose = 0;
            gcry_control (GCRYCTL_SET_VERBOSITY, (int)opt.verbose);
            opt.list_sigs=0;
            break;
          case oQuickRandom:
            gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
            break;
	  case oEmitVersion: opt.emit_version++; break;
	  case oNoEmitVersion: opt.emit_version=0; break;
	  case oCompletesNeeded: opt.completes_needed = pargs.r.ret_int; break;
	  case oMarginalsNeeded: opt.marginals_needed = pargs.r.ret_int; break;
	  case oMaxCertDepth: opt.max_cert_depth = pargs.r.ret_int; break;

#ifndef NO_TRUST_MODELS
	  case oTrustDBName: trustdb_name = pargs.r.ret_str; break;

#endif /*!NO_TRUST_MODELS*/
	  case oDefaultKey: opt.def_secret_key = pargs.r.ret_str; break;
	  case oDefRecipient:
            if( *pargs.r.ret_str )
              opt.def_recipient = make_username(pargs.r.ret_str);
            break;
	  case oDefRecipientSelf:
            xfree(opt.def_recipient); opt.def_recipient = NULL;
            opt.def_recipient_self = 1;
            break;
	  case oNoDefRecipient:
            xfree(opt.def_recipient); opt.def_recipient = NULL;
            opt.def_recipient_self = 0;
            break;
	  case oNoOptions: opt.no_homedir_creation = 1; break; /* no-options */
	  case oHomedir: break;
	  case oNoBatch: opt.batch = 0; break;

	  case oWithKeyData: opt.with_key_data=1; /*FALLTHRU*/
	  case oWithColons: opt.with_colons=':'; break;

          case oWithSigCheck: opt.check_sigs = 1; /*FALLTHRU*/
          case oWithSigList: opt.list_sigs = 1; break;

	  case oSkipVerify: opt.skip_verify=1; break;

	  case oSkipHiddenRecipients: opt.skip_hidden_recipients = 1; break;
	  case oNoSkipHiddenRecipients: opt.skip_hidden_recipients = 0; break;

	  case aListSecretKeys: set_cmd( &cmd, aListSecretKeys); break;

#ifndef NO_TRUST_MODELS
	    /* There are many programs (like mutt) that call gpg with
	       --always-trust so keep this option around for a long
	       time. */
	  case oAlwaysTrust: opt.trust_model=TM_ALWAYS; break;
	  case oTrustModel:
	    parse_trust_model(pargs.r.ret_str);
	    break;
#endif /*!NO_TRUST_MODELS*/

	  case oForceOwnertrust:
	    log_info(_("Note: %s is not for normal use!\n"),
		     "--force-ownertrust");
	    opt.force_ownertrust=string_to_trust_value(pargs.r.ret_str);
	    if(opt.force_ownertrust==-1)
	      {
		log_error("invalid ownertrust '%s'\n",pargs.r.ret_str);
		opt.force_ownertrust=0;
	      }
	    break;
	  case oLoadExtension:
            /* Dummy so that gpg 1.4 conf files can work. Should
               eventually be removed.  */
	    break;
	  case oOpenPGP:
	  case oRFC4880:
	    /* This is effectively the same as RFC2440, but with
	       "--enable-dsa2 --no-rfc2440-text --escape-from-lines
	       --require-cross-certification". */
	    opt.compliance = CO_RFC4880;
	    opt.flags.dsa2 = 1;
	    opt.flags.require_cross_cert = 1;
	    opt.rfc2440_text = 0;
	    opt.allow_non_selfsigned_uid = 1;
	    opt.allow_freeform_uid = 1;
	    opt.escape_from = 1;
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.cert_digest_algo = 0;
	    opt.compress_algo = -1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
	    break;
	  case oRFC2440:
	    opt.compliance = CO_RFC2440;
	    opt.flags.dsa2 = 0;
	    opt.rfc2440_text = 1;
	    opt.allow_non_selfsigned_uid = 1;
	    opt.allow_freeform_uid = 1;
	    opt.escape_from = 0;
	    opt.not_dash_escaped = 0;
	    opt.def_cipher_algo = 0;
	    opt.def_digest_algo = 0;
	    opt.cert_digest_algo = 0;
	    opt.compress_algo = -1;
            opt.s2k_mode = 3; /* iterated+salted */
	    opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
	    opt.s2k_cipher_algo = CIPHER_ALGO_3DES;
	    break;
	  case oPGP6:  opt.compliance = CO_PGP6;  break;
	  case oPGP7:  opt.compliance = CO_PGP7;  break;
	  case oPGP8:  opt.compliance = CO_PGP8;  break;
	  case oGnuPG: opt.compliance = CO_GNUPG; break;
	  case oRFC2440Text: opt.rfc2440_text=1; break;
	  case oNoRFC2440Text: opt.rfc2440_text=0; break;
 	  case oSetFilename:
            if(utf8_strings)
              opt.set_filename = pargs.r.ret_str;
            else
              opt.set_filename = native_to_utf8(pargs.r.ret_str);
 	    break;
	  case oForYourEyesOnly: eyes_only = 1; break;
	  case oNoForYourEyesOnly: eyes_only = 0; break;
	  case oSetPolicyURL:
	    add_policy_url(pargs.r.ret_str,0);
	    add_policy_url(pargs.r.ret_str,1);
	    break;
	  case oSigPolicyURL: add_policy_url(pargs.r.ret_str,0); break;
	  case oCertPolicyURL: add_policy_url(pargs.r.ret_str,1); break;
          case oShowPolicyURL:
	    deprecated_warning(configname,configlineno,"--show-policy-url",
			       "--list-options ","show-policy-urls");
	    deprecated_warning(configname,configlineno,"--show-policy-url",
			       "--verify-options ","show-policy-urls");
	    opt.list_options|=LIST_SHOW_POLICY_URLS;
	    opt.verify_options|=VERIFY_SHOW_POLICY_URLS;
	    break;
	  case oNoShowPolicyURL:
	    deprecated_warning(configname,configlineno,"--no-show-policy-url",
			       "--list-options ","no-show-policy-urls");
	    deprecated_warning(configname,configlineno,"--no-show-policy-url",
			       "--verify-options ","no-show-policy-urls");
	    opt.list_options&=~LIST_SHOW_POLICY_URLS;
	    opt.verify_options&=~VERIFY_SHOW_POLICY_URLS;
	    break;
	  case oSigKeyserverURL: add_keyserver_url(pargs.r.ret_str,0); break;
	  case oUseEmbeddedFilename:
	    opt.flags.use_embedded_filename=1;
	    break;
	  case oNoUseEmbeddedFilename:
	    opt.flags.use_embedded_filename=0;
	    break;
	  case oComment:
	    if(pargs.r.ret_str[0])
	      append_to_strlist(&opt.comments,pargs.r.ret_str);
	    break;
	  case oDefaultComment:
	    deprecated_warning(configname,configlineno,
			       "--default-comment","--no-comments","");
	    /* fall through */
	  case oNoComments:
	    free_strlist(opt.comments);
	    opt.comments=NULL;
	    break;
	  case oThrowKeyids: opt.throw_keyids = 1; break;
	  case oNoThrowKeyids: opt.throw_keyids = 0; break;
	  case oShowPhotos:
	    deprecated_warning(configname,configlineno,"--show-photos",
			       "--list-options ","show-photos");
	    deprecated_warning(configname,configlineno,"--show-photos",
			       "--verify-options ","show-photos");
	    opt.list_options|=LIST_SHOW_PHOTOS;
	    opt.verify_options|=VERIFY_SHOW_PHOTOS;
	    break;
	  case oNoShowPhotos:
	    deprecated_warning(configname,configlineno,"--no-show-photos",
			       "--list-options ","no-show-photos");
	    deprecated_warning(configname,configlineno,"--no-show-photos",
			       "--verify-options ","no-show-photos");
	    opt.list_options&=~LIST_SHOW_PHOTOS;
	    opt.verify_options&=~VERIFY_SHOW_PHOTOS;
	    break;
	  case oPhotoViewer: opt.photo_viewer = pargs.r.ret_str; break;

	  case oForceMDC: opt.force_mdc = 1; break;
	  case oNoForceMDC: opt.force_mdc = 0; break;
	  case oDisableMDC: opt.disable_mdc = 1; break;
	  case oNoDisableMDC: opt.disable_mdc = 0; break;
	  case oS2KMode:   opt.s2k_mode = pargs.r.ret_int; break;
	  case oS2KDigest: s2k_digest_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCipher: s2k_cipher_string = xstrdup(pargs.r.ret_str); break;
	  case oS2KCount:
	    if (pargs.r.ret_int)
              opt.s2k_count = encode_s2k_iterations (pargs.r.ret_int);
            else
              opt.s2k_count = 0;  /* Auto-calibrate when needed.  */
	    break;
	  case oNoEncryptTo: opt.no_encrypt_to = 1; break;
	  case oEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1;
	    break;
	  case oHiddenEncryptTo: /* store the recipient in the second list */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 1|2;
	    break;
	  case oRecipient: /* store the recipient */
	    add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
            any_explicit_recipient = 1;
	    break;
	  case oHiddenRecipient: /* store the recipient with a flag */
	    sl = add_to_strlist2( &remusr, pargs.r.ret_str, utf8_strings );
	    sl->flags = 2;
            any_explicit_recipient = 1;
	    break;

	  case oTrySecretKey:
	    add_to_strlist2 (&opt.secret_keys_to_try,
                             pargs.r.ret_str, utf8_strings);
	    break;

	  case oTextmodeShort: opt.textmode = 2; break;
	  case oTextmode: opt.textmode=1;  break;
	  case oNoTextmode: opt.textmode=0;  break;
	  case oExpert: opt.expert = 1; break;
	  case oNoExpert: opt.expert = 0; break;
	  case oDefSigExpire:
	    if(*pargs.r.ret_str!='\0')
	      {
		if(parse_expire_string(pargs.r.ret_str)==(u32)-1)
		  log_error(_("'%s' is not a valid signature expiration\n"),
			    pargs.r.ret_str);
		else
		  opt.def_sig_expire=pargs.r.ret_str;
	      }
	    break;
	  case oAskSigExpire: opt.ask_sig_expire = 1; break;
	  case oNoAskSigExpire: opt.ask_sig_expire = 0; break;
	  case oDefCertExpire:
	    if(*pargs.r.ret_str!='\0')
	      {
		if(parse_expire_string(pargs.r.ret_str)==(u32)-1)
		  log_error(_("'%s' is not a valid signature expiration\n"),
			    pargs.r.ret_str);
		else
		  opt.def_cert_expire=pargs.r.ret_str;
	      }
	    break;
	  case oAskCertExpire: opt.ask_cert_expire = 1; break;
	  case oNoAskCertExpire: opt.ask_cert_expire = 0; break;
          case oDefCertLevel: opt.def_cert_level=pargs.r.ret_int; break;
          case oMinCertLevel: opt.min_cert_level=pargs.r.ret_int; break;
	  case oAskCertLevel: opt.ask_cert_level = 1; break;
	  case oNoAskCertLevel: opt.ask_cert_level = 0; break;
	  case oLocalUser: /* store the local users */
	    add_to_strlist2( &locusr, pargs.r.ret_str, utf8_strings );
	    break;
	  case oCompress:
	    /* this is the -z command line option */
	    opt.compress_level = opt.bz2_compress_level = pargs.r.ret_int;
	    break;
	  case oCompressLevel: opt.compress_level = pargs.r.ret_int; break;
	  case oBZ2CompressLevel: opt.bz2_compress_level = pargs.r.ret_int; break;
	  case oBZ2DecompressLowmem: opt.bz2_decompress_lowmem=1; break;
	  case oPassphrase:
	    set_passphrase_from_string(pargs.r.ret_str);
	    break;
	  case oPassphraseFD:
            pwfd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
            break;
	  case oPassphraseFile:
            pwfd = open_info_file (pargs.r.ret_str, 0, 1);
            break;
	  case oPassphraseRepeat:
            opt.passphrase_repeat = pargs.r.ret_int;
            break;

          case oPinentryMode:
	    opt.pinentry_mode = parse_pinentry_mode (pargs.r.ret_str);
	    if (opt.pinentry_mode == -1)
              log_error (_("invalid pinentry mode '%s'\n"), pargs.r.ret_str);
	    break;

	  case oCommandFD:
            opt.command_fd = translate_sys2libc_fd_int (pargs.r.ret_int, 0);
            break;
	  case oCommandFile:
            opt.command_fd = open_info_file (pargs.r.ret_str, 0, 1);
            break;
	  case oCipherAlgo:
            def_cipher_string = xstrdup(pargs.r.ret_str);
            break;
	  case oDigestAlgo:
            def_digest_string = xstrdup(pargs.r.ret_str);
            break;
	  case oCompressAlgo:
	    /* If it is all digits, stick a Z in front of it for
	       later.  This is for backwards compatibility with
	       versions that took the compress algorithm number. */
	    {
	      char *pt=pargs.r.ret_str;
	      while(*pt)
		{
		  if (!isascii (*pt) || !isdigit (*pt))
		    break;

		  pt++;
		}

	      if(*pt=='\0')
		{
		  compress_algo_string=xmalloc(strlen(pargs.r.ret_str)+2);
		  strcpy(compress_algo_string,"Z");
		  strcat(compress_algo_string,pargs.r.ret_str);
		}
	      else
		compress_algo_string = xstrdup(pargs.r.ret_str);
	    }
	    break;
	  case oCertDigestAlgo:
            cert_digest_string = xstrdup(pargs.r.ret_str);
            break;

	  case oNoSecmemWarn:
            gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
            break;

	  case oRequireSecmem: require_secmem=1; break;
	  case oNoRequireSecmem: require_secmem=0; break;
	  case oNoPermissionWarn: opt.no_perm_warn=1; break;
	  case oNoMDCWarn: opt.no_mdc_warn=1; break;
          case oDisplayCharset:
	    if( set_native_charset( pargs.r.ret_str ) )
		log_error(_("'%s' is not a valid character set\n"),
			  pargs.r.ret_str);
	    break;
	  case oNotDashEscaped: opt.not_dash_escaped = 1; break;
	  case oEscapeFrom: opt.escape_from = 1; break;
	  case oNoEscapeFrom: opt.escape_from = 0; break;
	  case oLockOnce: opt.lock_once = 1; break;
	  case oLockNever:
            dotlock_disable ();
            break;
	  case oLockMultiple:
#ifndef __riscos__
	    opt.lock_once = 0;
#else /* __riscos__ */
            riscos_not_implemented("lock-multiple");
#endif /* __riscos__ */
            break;
	  case oKeyServer:
	    {
	      keyserver_spec_t keyserver;
	      keyserver = parse_keyserver_uri (pargs.r.ret_str, 0);
	      if (!keyserver)
		log_error (_("could not parse keyserver URL\n"));
	      else
		{
		  /* We only support a single keyserver.  Later ones
		     override earlier ones.  (Since we parse the
		     config file first and then the command line
		     arguments, the command line takes
		     precedence.)  */
		  if (opt.keyserver)
		    free_keyserver_spec (opt.keyserver);
		  opt.keyserver = keyserver;
		}
	    }
	    break;
	  case oKeyServerOptions:
	    if(!parse_keyserver_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid keyserver options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid keyserver options\n"));
	      }
	    break;
	  case oImportOptions:
	    if(!parse_import_options(pargs.r.ret_str,&opt.import_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid import options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid import options\n"));
	      }
	    break;
	  case oExportOptions:
	    if(!parse_export_options(pargs.r.ret_str,&opt.export_options,1))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid export options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid export options\n"));
	      }
	    break;
	  case oListOptions:
	    if(!parse_list_options(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid list options\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid list options\n"));
	      }
	    break;
	  case oVerifyOptions:
	    {
	      struct parse_options vopts[]=
		{
		  {"show-photos",VERIFY_SHOW_PHOTOS,NULL,
		   N_("display photo IDs during signature verification")},
		  {"show-policy-urls",VERIFY_SHOW_POLICY_URLS,NULL,
		   N_("show policy URLs during signature verification")},
		  {"show-notations",VERIFY_SHOW_NOTATIONS,NULL,
		   N_("show all notations during signature verification")},
		  {"show-std-notations",VERIFY_SHOW_STD_NOTATIONS,NULL,
		   N_("show IETF standard notations during signature verification")},
		  {"show-standard-notations",VERIFY_SHOW_STD_NOTATIONS,NULL,
		   NULL},
		  {"show-user-notations",VERIFY_SHOW_USER_NOTATIONS,NULL,
		   N_("show user-supplied notations during signature verification")},
		  {"show-keyserver-urls",VERIFY_SHOW_KEYSERVER_URLS,NULL,
		   N_("show preferred keyserver URLs during signature verification")},
		  {"show-uid-validity",VERIFY_SHOW_UID_VALIDITY,NULL,
		   N_("show user ID validity during signature verification")},
		  {"show-unusable-uids",VERIFY_SHOW_UNUSABLE_UIDS,NULL,
		   N_("show revoked and expired user IDs in signature verification")},
		  {"show-primary-uid-only",VERIFY_SHOW_PRIMARY_UID_ONLY,NULL,
		   N_("show only the primary user ID in signature verification")},
		  {"pka-lookups",VERIFY_PKA_LOOKUPS,NULL,
		   N_("validate signatures with PKA data")},
		  {"pka-trust-increase",VERIFY_PKA_TRUST_INCREASE,NULL,
		   N_("elevate the trust of signatures with valid PKA data")},
		  {NULL,0,NULL,NULL}
		};

	      if(!parse_options(pargs.r.ret_str,&opt.verify_options,vopts,1))
		{
		  if(configname)
		    log_error(_("%s:%d: invalid verify options\n"),
			      configname,configlineno);
		  else
		    log_error(_("invalid verify options\n"));
		}
	    }
	    break;
	  case oTempDir: opt.temp_dir=pargs.r.ret_str; break;
	  case oExecPath:
	    if(set_exec_path(pargs.r.ret_str))
	      log_error(_("unable to set exec-path to %s\n"),pargs.r.ret_str);
	    else
	      opt.exec_path_set=1;
	    break;
	  case oSetNotation:
	    add_notation_data( pargs.r.ret_str, 0 );
	    add_notation_data( pargs.r.ret_str, 1 );
	    break;
	  case oSigNotation: add_notation_data( pargs.r.ret_str, 0 ); break;
	  case oCertNotation: add_notation_data( pargs.r.ret_str, 1 ); break;
	  case oShowNotation:
	    deprecated_warning(configname,configlineno,"--show-notation",
			       "--list-options ","show-notations");
	    deprecated_warning(configname,configlineno,"--show-notation",
			       "--verify-options ","show-notations");
	    opt.list_options|=LIST_SHOW_NOTATIONS;
	    opt.verify_options|=VERIFY_SHOW_NOTATIONS;
	    break;
	  case oNoShowNotation:
	    deprecated_warning(configname,configlineno,"--no-show-notation",
			       "--list-options ","no-show-notations");
	    deprecated_warning(configname,configlineno,"--no-show-notation",
			       "--verify-options ","no-show-notations");
	    opt.list_options&=~LIST_SHOW_NOTATIONS;
	    opt.verify_options&=~VERIFY_SHOW_NOTATIONS;
	    break;
	  case oUtf8Strings: utf8_strings = 1; break;
	  case oNoUtf8Strings: utf8_strings = 0; break;
	  case oDisableCipherAlgo:
            {
              int algo = string_to_cipher_algo (pargs.r.ret_str);
              gcry_cipher_ctl (NULL, GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
            }
            break;
	  case oDisablePubkeyAlgo:
            {
              int algo = gcry_pk_map_name (pargs.r.ret_str);
              gcry_pk_ctl (GCRYCTL_DISABLE_ALGO, &algo, sizeof algo);
            }
            break;
          case oNoSigCache: opt.no_sig_cache = 1; break;
          case oNoSigCreateCheck: opt.no_sig_create_check = 1; break;
	  case oAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid = 1; break;
	  case oNoAllowNonSelfsignedUID: opt.allow_non_selfsigned_uid=0; break;
	  case oAllowFreeformUID: opt.allow_freeform_uid = 1; break;
	  case oNoAllowFreeformUID: opt.allow_freeform_uid = 0; break;
	  case oNoLiteral: opt.no_literal = 1; break;
	  case oSetFilesize: opt.set_filesize = pargs.r.ret_ulong; break;
	  case oFastListMode: opt.fast_list_mode = 1; break;
	  case oFixedListMode: /* Dummy */ break;
          case oLegacyListMode: opt.legacy_list_mode = 1; break;
	  case oPrintPKARecords: opt.print_pka_records = 1; break;
	  case oListOnly: opt.list_only=1; break;
	  case oIgnoreTimeConflict: opt.ignore_time_conflict = 1; break;
	  case oIgnoreValidFrom: opt.ignore_valid_from = 1; break;
	  case oIgnoreCrcError: opt.ignore_crc_error = 1; break;
	  case oIgnoreMDCError: opt.ignore_mdc_error = 1; break;
	  case oNoRandomSeedFile: use_random_seed = 0; break;
	  case oAutoKeyRetrieve:
	  case oNoAutoKeyRetrieve:
	        if(pargs.r_opt==oAutoKeyRetrieve)
		  opt.keyserver_options.options|=KEYSERVER_AUTO_KEY_RETRIEVE;
		else
		  opt.keyserver_options.options&=~KEYSERVER_AUTO_KEY_RETRIEVE;

		deprecated_warning(configname,configlineno,
			   pargs.r_opt==oAutoKeyRetrieve?"--auto-key-retrieve":
			       "--no-auto-key-retrieve","--keyserver-options ",
			   pargs.r_opt==oAutoKeyRetrieve?"auto-key-retrieve":
			       "no-auto-key-retrieve");
		break;
	  case oShowSessionKey: opt.show_session_key = 1; break;
	  case oOverrideSessionKey:
		opt.override_session_key = pargs.r.ret_str;
		break;
	  case oMergeOnly:
	        deprecated_warning(configname,configlineno,"--merge-only",
				   "--import-options ","merge-only");
		opt.import_options|=IMPORT_MERGE_ONLY;
	    break;
          case oAllowSecretKeyImport: /* obsolete */ break;
	  case oTryAllSecrets: opt.try_all_secrets = 1; break;
          case oTrustedKey: register_trusted_key( pargs.r.ret_str ); break;
          case oEnableSpecialFilenames:
            iobuf_enable_special_filenames (1);
            break;
          case oNoExpensiveTrustChecks: opt.no_expensive_trust_checks=1; break;
          case oAutoCheckTrustDB: opt.no_auto_check_trustdb=0; break;
          case oNoAutoCheckTrustDB: opt.no_auto_check_trustdb=1; break;
          case oPreservePermissions: opt.preserve_permissions=1; break;
          case oDefaultPreferenceList:
	    opt.def_preference_list = pargs.r.ret_str;
	    break;
	  case oDefaultKeyserverURL:
	    {
	      keyserver_spec_t keyserver;
	      keyserver = parse_keyserver_uri (pargs.r.ret_str,1 );
	      if (!keyserver)
		log_error (_("could not parse keyserver URL\n"));
	      else
		free_keyserver_spec (keyserver);

	      opt.def_keyserver_url = pargs.r.ret_str;
	    }
	    break;
          case oPersonalCipherPreferences:
	    pers_cipher_list=pargs.r.ret_str;
	    break;
          case oPersonalDigestPreferences:
	    pers_digest_list=pargs.r.ret_str;
	    break;
          case oPersonalCompressPreferences:
	    pers_compress_list=pargs.r.ret_str;
	    break;
          case oAgentProgram: opt.agent_program = pargs.r.ret_str;  break;
          case oDirmngrProgram: opt.dirmngr_program = pargs.r.ret_str; break;

          case oDisplay:
            set_opt_session_env ("DISPLAY", pargs.r.ret_str);
            break;
          case oTTYname:
            set_opt_session_env ("GPG_TTY", pargs.r.ret_str);
            break;
          case oTTYtype:
            set_opt_session_env ("TERM", pargs.r.ret_str);
            break;
          case oXauthority:
            set_opt_session_env ("XAUTHORITY", pargs.r.ret_str);
            break;

          case oLCctype: opt.lc_ctype = pargs.r.ret_str; break;
          case oLCmessages: opt.lc_messages = pargs.r.ret_str; break;

	  case oGroup: add_group(pargs.r.ret_str); break;
	  case oUnGroup: rm_group(pargs.r.ret_str); break;
	  case oNoGroups:
	    while(opt.grouplist)
	      {
		struct groupitem *iter=opt.grouplist;
		free_strlist(iter->values);
		opt.grouplist=opt.grouplist->next;
		xfree(iter);
	      }
	    break;

	  case oStrict:
	  case oNoStrict:
	    /* Not used */
            break;

          case oMangleDosFilenames: opt.mangle_dos_filenames = 1; break;
          case oNoMangleDosFilenames: opt.mangle_dos_filenames = 0; break;
          case oEnableProgressFilter: opt.enable_progress_filter = 1; break;
	  case oMultifile: multifile=1; break;
	  case oKeyidFormat:
	    if(ascii_strcasecmp(pargs.r.ret_str,"short")==0)
	      opt.keyid_format=KF_SHORT;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"long")==0)
	      opt.keyid_format=KF_LONG;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"0xshort")==0)
	      opt.keyid_format=KF_0xSHORT;
	    else if(ascii_strcasecmp(pargs.r.ret_str,"0xlong")==0)
	      opt.keyid_format=KF_0xLONG;
	    else
	      log_error("unknown keyid-format '%s'\n",pargs.r.ret_str);
	    break;

          case oExitOnStatusWriteError:
            opt.exit_on_status_write_error = 1;
            break;

	  case oLimitCardInsertTries:
            opt.limit_card_insert_tries = pargs.r.ret_int;
            break;

	  case oRequireCrossCert: opt.flags.require_cross_cert=1; break;
	  case oNoRequireCrossCert: opt.flags.require_cross_cert=0; break;

	  case oAutoKeyLocate:
	    if(!parse_auto_key_locate(pargs.r.ret_str))
	      {
		if(configname)
		  log_error(_("%s:%d: invalid auto-key-locate list\n"),
			    configname,configlineno);
		else
		  log_error(_("invalid auto-key-locate list\n"));
	      }
	    break;
	  case oNoAutoKeyLocate:
	    release_akl();
	    break;

	  case oEnableLargeRSA:
#if SECMEM_BUFFER_SIZE >= 65536
            opt.flags.large_rsa=1;
#else
            if (configname)
              log_info("%s:%d: WARNING: gpg not built with large secure "
                         "memory buffer.  Ignoring enable-large-rsa\n",
                        configname,configlineno);
            else
              log_info("WARNING: gpg not built with large secure "
                         "memory buffer.  Ignoring --enable-large-rsa\n");
#endif /* SECMEM_BUFFER_SIZE >= 65536 */
            break;
	  case oDisableLargeRSA: opt.flags.large_rsa=0;
            break;

	  case oEnableDSA2: opt.flags.dsa2=1; break;
	  case oDisableDSA2: opt.flags.dsa2=0; break;

          case oAllowMultisigVerification:
	  case oAllowMultipleMessages:
	    opt.flags.allow_multiple_messages=1;
	    break;

	  case oNoAllowMultipleMessages:
	    opt.flags.allow_multiple_messages=0;
	    break;

          case oAllowWeakDigestAlgos:
            opt.flags.allow_weak_digest_algos = 1;
            break;

          case oFakedSystemTime:
            {
              time_t faked_time = isotime2epoch (pargs.r.ret_str);
              if (faked_time == (time_t)(-1))
                faked_time = (time_t)strtoul (pargs.r.ret_str, NULL, 10);
              gnupg_set_time (faked_time, 0);
            }
            break;

          case oNoAutostart: opt.autostart = 0; break;

	  case oNoop: break;

	  default:
            pargs.err = configfp? ARGPARSE_PRINT_WARNING:ARGPARSE_PRINT_ERROR;
            break;
	  }
      }

    if (configfp)
      {
	fclose( configfp );
	configfp = NULL;
        /* Remember the first config file name. */
        if (!save_configname)
          save_configname = configname;
        else
          xfree(configname);
        configname = NULL;
	goto next_pass;
      }
    xfree(configname); configname = NULL;
    if (log_get_errorcount (0))
      g10_exit(2);

    /* The command --gpgconf-list is pretty simple and may be called
       directly after the option parsing. */
    if (cmd == aGPGConfList)
      {
        gpgconf_list (save_configname ? save_configname : default_configname);
        g10_exit (0);
      }
    xfree (save_configname);
    xfree (default_configname);

    if( nogreeting )
	greeting = 0;

    if( greeting )
      {
	es_fprintf (es_stderr, "%s %s; %s\n",
                    strusage(11), strusage(13), strusage(14) );
	es_fprintf (es_stderr, "%s\n", strusage(15) );
      }
#ifdef IS_DEVELOPMENT_VERSION
    if (!opt.batch)
      {
	const char *s;

	if((s=strusage(25)))
	  log_info("%s\n",s);
	if((s=strusage(26)))
	  log_info("%s\n",s);
	if((s=strusage(27)))
	  log_info("%s\n",s);
      }
#endif

    /* FIXME: We should use logging to a file only in server mode;
       however we have not yet implemetyed that.  Thus we try to get
       away with --batch as indication for logging to file
       required. */
    if (logfile && opt.batch)
      {
        log_set_file (logfile);
        log_set_prefix (NULL, 1|2|4);
      }

    if (opt.verbose > 2)
        log_info ("using character set '%s'\n", get_native_charset ());

    if( may_coredump && !opt.quiet )
	log_info(_("WARNING: program may create a core file!\n"));

    if (eyes_only) {
      if (opt.set_filename)
	  log_info(_("WARNING: %s overrides %s\n"),
		   "--for-your-eyes-only","--set-filename");

      opt.set_filename="_CONSOLE";
    }

    if (opt.no_literal) {
	log_info(_("Note: %s is not for normal use!\n"), "--no-literal");
	if (opt.textmode)
	    log_error(_("%s not allowed with %s!\n"),
		       "--textmode", "--no-literal" );
	if (opt.set_filename)
	    log_error(_("%s makes no sense with %s!\n"),
			eyes_only?"--for-your-eyes-only":"--set-filename",
		        "--no-literal" );
    }


    if (opt.set_filesize)
	log_info(_("Note: %s is not for normal use!\n"), "--set-filesize");
    if( opt.batch )
	tty_batchmode( 1 );

    if (gnupg_faked_time_p ())
      {
        gnupg_isotime_t tbuf;

        log_info (_("WARNING: running with faked system time: "));
        gnupg_get_isotime (tbuf);
        dump_isotime (tbuf);
        log_printf ("\n");
      }

    /* Print a warning if an argument looks like an option.  */
    if (!opt.quiet && !(pargs.flags & ARGPARSE_FLAG_STOP_SEEN))
      {
        int i;

        for (i=0; i < argc; i++)
          if (argv[i][0] == '-' && argv[i][1] == '-')
            log_info (_("Note: '%s' is not considered an option\n"), argv[i]);
      }


    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    if(require_secmem && !got_secmem)
      {
	log_info(_("will not run with insecure memory due to %s\n"),
		 "--require-secmem");
	g10_exit(2);
      }

    set_debug (debug_level);
    if (DBG_CLOCK)
      log_clock ("start");

    /* Do these after the switch(), so they can override settings. */
    if(PGP6)
      {
        /* That does not anymore work becuase we have no more support
           for v3 signatures.  */
	opt.disable_mdc=1;
	opt.escape_from=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP7)
      {
        /* That does not anymore work because we have no more support
           for v3 signatures.  */
	opt.escape_from=1;
	opt.ask_sig_expire=0;
      }
    else if(PGP8)
      {
	opt.escape_from=1;
      }


    if( def_cipher_string ) {
	opt.def_cipher_algo = string_to_cipher_algo (def_cipher_string);
	xfree(def_cipher_string); def_cipher_string = NULL;
	if ( openpgp_cipher_test_algo (opt.def_cipher_algo) )
	    log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( def_digest_string ) {
	opt.def_digest_algo = string_to_digest_algo (def_digest_string);
	xfree(def_digest_string); def_digest_string = NULL;
	if ( openpgp_md_test_algo (opt.def_digest_algo) )
	    log_error(_("selected digest algorithm is invalid\n"));
    }
    if( compress_algo_string ) {
	opt.compress_algo = string_to_compress_algo(compress_algo_string);
	xfree(compress_algo_string); compress_algo_string = NULL;
	if( check_compress_algo(opt.compress_algo) )
          log_error(_("selected compression algorithm is invalid\n"));
    }
    if( cert_digest_string ) {
	opt.cert_digest_algo = string_to_digest_algo (cert_digest_string);
	xfree(cert_digest_string); cert_digest_string = NULL;
	if (openpgp_md_test_algo(opt.cert_digest_algo))
          log_error(_("selected certification digest algorithm is invalid\n"));
    }
    if( s2k_cipher_string ) {
	opt.s2k_cipher_algo = string_to_cipher_algo (s2k_cipher_string);
	xfree(s2k_cipher_string); s2k_cipher_string = NULL;
	if (openpgp_cipher_test_algo (opt.s2k_cipher_algo))
          log_error(_("selected cipher algorithm is invalid\n"));
    }
    if( s2k_digest_string ) {
	opt.s2k_digest_algo = string_to_digest_algo (s2k_digest_string);
	xfree(s2k_digest_string); s2k_digest_string = NULL;
	if (openpgp_md_test_algo(opt.s2k_digest_algo))
          log_error(_("selected digest algorithm is invalid\n"));
    }
    if( opt.completes_needed < 1 )
      log_error(_("completes-needed must be greater than 0\n"));
    if( opt.marginals_needed < 2 )
      log_error(_("marginals-needed must be greater than 1\n"));
    if( opt.max_cert_depth < 1 || opt.max_cert_depth > 255 )
      log_error(_("max-cert-depth must be in the range from 1 to 255\n"));
    if(opt.def_cert_level<0 || opt.def_cert_level>3)
      log_error(_("invalid default-cert-level; must be 0, 1, 2, or 3\n"));
    if( opt.min_cert_level < 1 || opt.min_cert_level > 3 )
      log_error(_("invalid min-cert-level; must be 1, 2, or 3\n"));
    switch( opt.s2k_mode ) {
      case 0:
	log_info(_("Note: simple S2K mode (0) is strongly discouraged\n"));
	break;
      case 1: case 3: break;
      default:
	log_error(_("invalid S2K mode; must be 0, 1 or 3\n"));
    }

    /* This isn't actually needed, but does serve to error out if the
       string is invalid. */
    if(opt.def_preference_list &&
	keygen_set_std_prefs(opt.def_preference_list,0))
      log_error(_("invalid default preferences\n"));

    if(pers_cipher_list &&
       keygen_set_std_prefs(pers_cipher_list,PREFTYPE_SYM))
      log_error(_("invalid personal cipher preferences\n"));

    if(pers_digest_list &&
       keygen_set_std_prefs(pers_digest_list,PREFTYPE_HASH))
      log_error(_("invalid personal digest preferences\n"));

    if(pers_compress_list &&
       keygen_set_std_prefs(pers_compress_list,PREFTYPE_ZIP))
      log_error(_("invalid personal compress preferences\n"));

    /* We don't support all possible commands with multifile yet */
    if(multifile)
      {
	char *cmdname;

	switch(cmd)
	  {
	  case aSign:
	    cmdname="--sign";
	    break;
	  case aClearsign:
	    cmdname="--clearsign";
	    break;
	  case aDetachedSign:
	    cmdname="--detach-sign";
	    break;
	  case aSym:
	    cmdname="--symmetric";
	    break;
	  case aEncrSym:
	    cmdname="--symmetric --encrypt";
	    break;
	  case aStore:
	    cmdname="--store";
	    break;
	  default:
	    cmdname=NULL;
	    break;
	  }

	if(cmdname)
	  log_error(_("%s does not yet work with %s\n"),cmdname,"--multifile");
      }

    if( log_get_errorcount(0) )
	g10_exit(2);

    if(opt.compress_level==0)
      opt.compress_algo=COMPRESS_ALGO_NONE;

    /* Check our chosen algorithms against the list of legal
       algorithms. */

    if(!GNUPG)
      {
	const char *badalg=NULL;
	preftype_t badtype=PREFTYPE_NONE;

	if(opt.def_cipher_algo
	   && !algo_available(PREFTYPE_SYM,opt.def_cipher_algo,NULL))
	  {
	    badalg = openpgp_cipher_algo_name (opt.def_cipher_algo);
	    badtype = PREFTYPE_SYM;
	  }
	else if(opt.def_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.def_digest_algo,NULL))
	  {
	    badalg = gcry_md_algo_name (opt.def_digest_algo);
	    badtype = PREFTYPE_HASH;
	  }
	else if(opt.cert_digest_algo
		&& !algo_available(PREFTYPE_HASH,opt.cert_digest_algo,NULL))
	  {
	    badalg = gcry_md_algo_name (opt.cert_digest_algo);
	    badtype = PREFTYPE_HASH;
	  }
	else if(opt.compress_algo!=-1
		&& !algo_available(PREFTYPE_ZIP,opt.compress_algo,NULL))
	  {
	    badalg = compress_algo_to_string(opt.compress_algo);
	    badtype = PREFTYPE_ZIP;
	  }

	if(badalg)
	  {
	    switch(badtype)
	      {
	      case PREFTYPE_SYM:
		log_info(_("you may not use cipher algorithm '%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      case PREFTYPE_HASH:
		log_info(_("you may not use digest algorithm '%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      case PREFTYPE_ZIP:
		log_info(_("you may not use compression algorithm '%s'"
			   " while in %s mode\n"),
			 badalg,compliance_option_string());
		break;
	      default:
		BUG();
	      }

	    compliance_failure();
	  }
      }

    /* Set the random seed file. */
    if( use_random_seed ) {
	char *p = make_filename(opt.homedir, "random_seed", NULL );
	gcry_control (GCRYCTL_SET_RANDOM_SEED_FILE, p);
        if (!access (p, F_OK))
          register_secured_file (p);
	xfree(p);
    }

    /* If there is no command but the --fingerprint is given, default
       to the --list-keys command.  */
    if (!cmd && fpr_maybe_cmd)
      {
	set_cmd (&cmd, aListKeys);
      }


    if( opt.verbose > 1 )
	set_packet_list_mode(1);

    /* Add the keyrings, but not for some special commands.
       We always need to add the keyrings if we are running under
       SELinux, this is so that the rings are added to the list of
       secured files. */
    if( ALWAYS_ADD_KEYRINGS
        || (cmd != aDeArmor && cmd != aEnArmor && cmd != aGPGConfTest) )
      {
	if (!nrings || default_keyring)  /* Add default ring. */
	    keydb_add_resource ("pubring" EXTSEP_S GPGEXT_GPG,
                                KEYDB_RESOURCE_FLAG_DEFAULT);
	for (sl = nrings; sl; sl = sl->next )
          keydb_add_resource (sl->d, sl->flags);
      }
    FREE_STRLIST(nrings);

    if (opt.pinentry_mode == PINENTRY_MODE_LOOPBACK)
      /* In loopback mode, never ask for the password multiple
	 times.  */
      {
	opt.passphrase_repeat = 0;
      }

    if (cmd == aGPGConfTest)
      g10_exit(0);


    if( pwfd != -1 )  /* Read the passphrase now. */
	read_passphrase_from_fd( pwfd );

    fname = argc? *argv : NULL;

    if(fname && utf8_strings)
      opt.flags.utf8_filename=1;

    ctrl = xcalloc (1, sizeof *ctrl);
    gpg_init_default_ctrl (ctrl);

#ifndef NO_TRUST_MODELS
    switch (cmd)
      {
      case aPrimegen:
      case aPrintMD:
      case aPrintMDs:
      case aGenRandom:
      case aDeArmor:
      case aEnArmor:
	break;
      case aFixTrustDB:
      case aExportOwnerTrust:
        rc = setup_trustdb (0, trustdb_name);
        break;
      case aListTrustDB:
        rc = setup_trustdb (argc? 1:0, trustdb_name);
        break;
      default:
        /* If we are using TM_ALWAYS, we do not need to create the
           trustdb.  */
        rc = setup_trustdb (opt.trust_model != TM_ALWAYS, trustdb_name);
        break;
      }
    if (rc)
      log_error (_("failed to initialize the TrustDB: %s\n"),
                 gpg_strerror (rc));
#endif /*!NO_TRUST_MODELS*/

    switch (cmd)
      {
      case aStore:
      case aSym:
      case aSign:
      case aSignSym:
      case aClearsign:
        if (!opt.quiet && any_explicit_recipient)
          log_info (_("WARNING: recipients (-r) given "
                      "without using public key encryption\n"));
	break;
      default:
        break;
      }


    /* Check for certain command whether we need to migrate a
       secring.gpg to the gpg-agent. */
    switch (cmd)
      {
      case aListSecretKeys:
      case aSign:
      case aSignEncr:
      case aSignEncrSym:
      case aSignSym:
      case aClearsign:
      case aDecrypt:
      case aSignKey:
      case aLSignKey:
      case aEditKey:
      case aPasswd:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
      case aQuickKeygen:
      case aQuickAddUid:
      case aFullKeygen:
      case aKeygen:
      case aImport:
      case aExportSecret:
      case aExportSecretSub:
      case aGenRevoke:
      case aDesigRevoke:
      case aCardEdit:
      case aChangePIN:
        migrate_secring (ctrl);
	break;
      case aListKeys:
        if (opt.with_secret)
          migrate_secring (ctrl);
        break;
      default:
        break;
      }

    /* The command dispatcher.  */
    switch( cmd )
      {
      case aServer:
        gpg_server (ctrl);
        break;

      case aStore: /* only store the file */
	if( argc > 1 )
	    wrong_args(_("--store [filename]"));
	if( (rc = encrypt_store(fname)) )
	    log_error ("storing '%s' failed: %s\n",
                       print_fname_stdin(fname),gpg_strerror (rc) );
	break;
      case aSym: /* encrypt the given file only with the symmetric cipher */
	if( argc > 1 )
	    wrong_args(_("--symmetric [filename]"));
	if( (rc = encrypt_symmetric(fname)) )
            log_error (_("symmetric encryption of '%s' failed: %s\n"),
                        print_fname_stdin(fname),gpg_strerror (rc) );
	break;

      case aEncr: /* encrypt the given file */
	if(multifile)
	  encrypt_crypt_files (ctrl, argc, argv, remusr);
	else
	  {
	    if( argc > 1 )
	      wrong_args(_("--encrypt [filename]"));
	    if( (rc = encrypt_crypt (ctrl, -1, fname, remusr, 0, NULL, -1)) )
	      log_error("%s: encryption failed: %s\n",
			print_fname_stdin(fname), gpg_strerror (rc) );
	  }
	break;

      case aEncrSym:
	/* This works with PGP 8 in the sense that it acts just like a
	   symmetric message.  It doesn't work at all with 2 or 6.  It
	   might work with 7, but alas, I don't have a copy to test
	   with right now. */
	if( argc > 1 )
	  wrong_args(_("--symmetric --encrypt [filename]"));
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP6 || PGP7)
	  log_error(_("you cannot use --symmetric --encrypt"
		      " while in %s mode\n"),compliance_option_string());
	else
	  {
	    if( (rc = encrypt_crypt (ctrl, -1, fname, remusr, 1, NULL, -1)) )
	      log_error("%s: encryption failed: %s\n",
			print_fname_stdin(fname), gpg_strerror (rc) );
	  }
	break;

      case aSign: /* sign the given file */
	sl = NULL;
	if( detached_sig ) { /* sign all files */
	    for( ; argc; argc--, argv++ )
		add_to_strlist( &sl, *argv );
	}
	else {
	    if( argc > 1 )
		wrong_args(_("--sign [filename]"));
	    if( argc ) {
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	    }
	}
	if( (rc = sign_file (ctrl, sl, detached_sig, locusr, 0, NULL, NULL)) )
	    log_error("signing failed: %s\n", gpg_strerror (rc) );
	free_strlist(sl);
	break;

      case aSignEncr: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--sign --encrypt [filename]"));
	if( argc ) {
	    sl = xmalloc_clear( sizeof *sl + strlen(fname));
	    strcpy(sl->d, fname);
	}
	else
	    sl = NULL;
	if ((rc = sign_file (ctrl, sl, detached_sig, locusr, 1, remusr, NULL)))
	    log_error("%s: sign+encrypt failed: %s\n",
		      print_fname_stdin(fname), gpg_strerror (rc) );
	free_strlist(sl);
	break;

      case aSignEncrSym: /* sign and encrypt the given file */
	if( argc > 1 )
	    wrong_args(_("--symmetric --sign --encrypt [filename]"));
	else if(opt.s2k_mode==0)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " with --s2k-mode 0\n"));
	else if(PGP6 || PGP7)
	  log_error(_("you cannot use --symmetric --sign --encrypt"
		      " while in %s mode\n"),compliance_option_string());
	else
	  {
	    if( argc )
	      {
		sl = xmalloc_clear( sizeof *sl + strlen(fname));
		strcpy(sl->d, fname);
	      }
	    else
	      sl = NULL;
	    if ((rc = sign_file (ctrl, sl, detached_sig, locusr,
                                 2, remusr, NULL)))
	      log_error("%s: symmetric+sign+encrypt failed: %s\n",
			print_fname_stdin(fname), gpg_strerror (rc) );
	    free_strlist(sl);
	  }
	break;

      case aSignSym: /* sign and conventionally encrypt the given file */
	if (argc > 1)
	    wrong_args(_("--sign --symmetric [filename]"));
	rc = sign_symencrypt_file (fname, locusr);
        if (rc)
	    log_error("%s: sign+symmetric failed: %s\n",
                      print_fname_stdin(fname), gpg_strerror (rc) );
	break;

      case aClearsign: /* make a clearsig */
	if( argc > 1 )
	    wrong_args(_("--clearsign [filename]"));
	if( (rc = clearsign_file(fname, locusr, NULL)) )
	    log_error("%s: clearsign failed: %s\n",
                      print_fname_stdin(fname), gpg_strerror (rc) );
	break;

      case aVerify:
	if (multifile)
	  {
	    if ((rc = verify_files (ctrl, argc, argv)))
	      log_error("verify files failed: %s\n", gpg_strerror (rc) );
	  }
	else
	  {
	    if ((rc = verify_signatures (ctrl, argc, argv)))
	      log_error("verify signatures failed: %s\n", gpg_strerror (rc) );
	  }
	break;

      case aDecrypt:
        if (multifile)
	  decrypt_messages (ctrl, argc, argv);
	else
	  {
	    if( argc > 1 )
	      wrong_args(_("--decrypt [filename]"));
	    if( (rc = decrypt_message (ctrl, fname) ))
	      log_error("decrypt_message failed: %s\n", gpg_strerror (rc) );
	  }
	break;

      case aQuickSignKey:
      case aQuickLSignKey:
        {
          const char *fpr;

          if (argc < 1)
            wrong_args ("--quick-[l]sign-key fingerprint [userids]");
          fpr = *argv++; argc--;
          sl = NULL;
          for( ; argc; argc--, argv++)
	    append_to_strlist2 (&sl, *argv, utf8_strings);
          keyedit_quick_sign (ctrl, fpr, sl, locusr, (cmd == aQuickLSignKey));
          free_strlist (sl);
        }
	break;

      case aSignKey:
	if( argc != 1 )
	  wrong_args(_("--sign-key user-id"));
	/* fall through */
      case aLSignKey:
	if( argc != 1 )
	  wrong_args(_("--lsign-key user-id"));
	/* fall through */

	sl=NULL;

	if(cmd==aSignKey)
	  append_to_strlist(&sl,"sign");
	else if(cmd==aLSignKey)
	  append_to_strlist(&sl,"lsign");
	else
	  BUG();

	append_to_strlist( &sl, "save" );
	username = make_username( fname );
	keyedit_menu (ctrl, username, locusr, sl, 0, 0 );
	xfree(username);
	free_strlist(sl);
	break;

      case aEditKey: /* Edit a key signature */
	if( !argc )
	    wrong_args(_("--edit-key user-id [commands]"));
	username = make_username( fname );
	if( argc > 1 ) {
	    sl = NULL;
	    for( argc--, argv++ ; argc; argc--, argv++ )
		append_to_strlist( &sl, *argv );
	    keyedit_menu (ctrl, username, locusr, sl, 0, 1 );
	    free_strlist(sl);
	}
	else
            keyedit_menu (ctrl, username, locusr, NULL, 0, 1 );
	xfree(username);
	break;

      case aPasswd:
        if (argc != 1)
          wrong_args (_("--passwd <user-id>"));
        else
          {
            username = make_username (fname);
            keyedit_passwd (ctrl, username);
            xfree (username);
          }
        break;

      case aDeleteKeys:
      case aDeleteSecretKeys:
      case aDeleteSecretAndPublicKeys:
	sl = NULL;
	/* I'm adding these in reverse order as add_to_strlist2
           reverses them again, and it's easier to understand in the
           proper order :) */
	for( ; argc; argc-- )
	  add_to_strlist2( &sl, argv[argc-1], utf8_strings );
	delete_keys(sl,cmd==aDeleteSecretKeys,cmd==aDeleteSecretAndPublicKeys);
	free_strlist(sl);
	break;

      case aCheckKeys:
	opt.check_sigs = 1;
      case aListSigs:
	opt.list_sigs = 1;
      case aListKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	public_key_list (ctrl, sl, 0);
	free_strlist(sl);
	break;
      case aListSecretKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	secret_key_list (ctrl, sl);
	free_strlist(sl);
	break;
      case aLocateKeys:
	sl = NULL;
	for (; argc; argc--, argv++)
          add_to_strlist2( &sl, *argv, utf8_strings );
	public_key_list (ctrl, sl, 1);
	free_strlist (sl);
	break;

      case aQuickKeygen:
        if (argc != 1 )
          wrong_args("--gen-key user-id");
        username = make_username (fname);
        quick_generate_keypair (username);
        xfree (username);
        break;

      case aKeygen: /* generate a key */
	if( opt.batch ) {
	    if( argc > 1 )
		wrong_args("--gen-key [parameterfile]");
	    generate_keypair (ctrl, 0, argc? *argv : NULL, NULL, 0);
	}
	else {
	    if( argc )
		wrong_args("--gen-key");
	    generate_keypair (ctrl, 0, NULL, NULL, 0);
	}
	break;

      case aFullKeygen: /* Generate a key with all options. */
	if (opt.batch)
          {
	    if (argc > 1)
              wrong_args ("--full-gen-key [parameterfile]");
	    generate_keypair (ctrl, 1, argc? *argv : NULL, NULL, 0);
          }
	else
          {
	    if (argc)
              wrong_args("--full-gen-key");
	    generate_keypair (ctrl, 1, NULL, NULL, 0);
	}
	break;

      case aQuickAddUid:
        {
          const char *uid, *newuid;

          if (argc != 2)
            wrong_args ("--quick-adduid USER-ID NEW-USER-ID");
          uid = *argv++; argc--;
          newuid = *argv++; argc--;
          keyedit_quick_adduid (ctrl, uid, newuid);
        }
	break;

      case aFastImport:
        opt.import_options |= IMPORT_FAST;
      case aImport:
	import_keys (ctrl, argc? argv:NULL, argc, NULL, opt.import_options);
	break;

	/* TODO: There are a number of command that use this same
	   "make strlist, call function, report error, free strlist"
	   pattern.  Join them together here and avoid all that
	   duplicated code. */

      case aExport:
      case aSendKeys:
      case aRecvKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	if( cmd == aSendKeys )
            rc = keyserver_export (ctrl, sl );
	else if( cmd == aRecvKeys )
            rc = keyserver_import (ctrl, sl );
	else
            rc = export_pubkeys (ctrl, sl, opt.export_options);
	if(rc)
	  {
	    if(cmd==aSendKeys)
	      log_error(_("keyserver send failed: %s\n"),gpg_strerror (rc));
	    else if(cmd==aRecvKeys)
	      log_error(_("keyserver receive failed: %s\n"),gpg_strerror (rc));
	    else
	      log_error(_("key export failed: %s\n"),gpg_strerror (rc));
	  }
	free_strlist(sl);
	break;

     case aSearchKeys:
	sl = NULL;
	for (; argc; argc--, argv++)
	  append_to_strlist2 (&sl, *argv, utf8_strings);
	rc = keyserver_search (ctrl, sl);
	if (rc)
	  log_error (_("keyserver search failed: %s\n"), gpg_strerror (rc));
	free_strlist (sl);
	break;

      case aRefreshKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc = keyserver_refresh (ctrl, sl);
	if(rc)
	  log_error(_("keyserver refresh failed: %s\n"),gpg_strerror (rc));
	free_strlist(sl);
	break;

      case aFetchKeys:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    append_to_strlist2( &sl, *argv, utf8_strings );
	rc = keyserver_fetch (ctrl, sl);
	if(rc)
	  log_error("key fetch failed: %s\n",gpg_strerror (rc));
	free_strlist(sl);
	break;

      case aExportSecret:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_seckeys (ctrl, sl);
	free_strlist(sl);
	break;

      case aExportSecretSub:
	sl = NULL;
	for( ; argc; argc--, argv++ )
	    add_to_strlist2( &sl, *argv, utf8_strings );
	export_secsubkeys (ctrl, sl);
	free_strlist(sl);
	break;

      case aGenRevoke:
	if( argc != 1 )
	    wrong_args("--gen-revoke user-id");
	username =  make_username(*argv);
	gen_revoke( username );
	xfree( username );
	break;

      case aDesigRevoke:
	if( argc != 1 )
	    wrong_args("--desig-revoke user-id");
	username =  make_username(*argv);
	gen_desig_revoke( username, locusr );
	xfree( username );
	break;

      case aDeArmor:
	if( argc > 1 )
	    wrong_args("--dearmor [file]");
	rc = dearmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("dearmoring failed: %s\n"), gpg_strerror (rc));
	break;

      case aEnArmor:
	if( argc > 1 )
	    wrong_args("--enarmor [file]");
	rc = enarmor_file( argc? *argv: NULL );
	if( rc )
	    log_error(_("enarmoring failed: %s\n"), gpg_strerror (rc));
	break;


      case aPrimegen:
#if 0 /*FIXME*/
	{   int mode = argc < 2 ? 0 : atoi(*argv);

	    if( mode == 1 && argc == 2 ) {
		mpi_print (es_stdout,
                           generate_public_prime( atoi(argv[1]) ), 1);
	    }
	    else if( mode == 2 && argc == 3 ) {
		mpi_print (es_stdout, generate_elg_prime(
					     0, atoi(argv[1]),
					     atoi(argv[2]), NULL,NULL ), 1);
	    }
	    else if( mode == 3 && argc == 3 ) {
		MPI *factors;
		mpi_print (es_stdout, generate_elg_prime(
					     1, atoi(argv[1]),
					     atoi(argv[2]), NULL,&factors ), 1);
		es_putc ('\n', es_stdout);
		mpi_print (es_stdout, factors[0], 1 ); /* print q */
	    }
	    else if( mode == 4 && argc == 3 ) {
		MPI g = mpi_alloc(1);
		mpi_print (es_stdout, generate_elg_prime(
						 0, atoi(argv[1]),
						 atoi(argv[2]), g, NULL ), 1);
		es_putc ('\n', es_stdout);
		mpi_print (es_stdout, g, 1 );
		mpi_free (g);
	    }
	    else
		wrong_args("--gen-prime mode bits [qbits] ");
	    es_putc ('\n', es_stdout);
	}
#endif
        wrong_args("--gen-prime not yet supported ");
	break;

      case aGenRandom:
	{
	    int level = argc ? atoi(*argv):0;
	    int count = argc > 1 ? atoi(argv[1]): 0;
	    int endless = !count;

	    if( argc < 1 || argc > 2 || level < 0 || level > 2 || count < 0 )
		wrong_args("--gen-random 0|1|2 [count]");

	    while( endless || count ) {
		byte *p;
                /* Wee need a multiple of 3, so that in case of
                   armored output we get a correct string.  No
                   linefolding is done, as it is best to levae this to
                   other tools */
		size_t n = !endless && count < 99? count : 99;

		p = gcry_random_bytes (n, level);
#ifdef HAVE_DOSISH_SYSTEM
		setmode ( fileno(stdout), O_BINARY );
#endif
                if (opt.armor) {
                    char *tmp = make_radix64_string (p, n);
                    es_fputs (tmp, es_stdout);
                    xfree (tmp);
                    if (n%3 == 1)
                      es_putc ('=', es_stdout);
                    if (n%3)
                      es_putc ('=', es_stdout);
                } else {
                    es_fwrite( p, n, 1, es_stdout );
                }
		xfree(p);
		if( !endless )
		    count -= n;
	    }
            if (opt.armor)
              es_putc ('\n', es_stdout);
	}
	break;

      case aPrintMD:
	if( argc < 1)
	    wrong_args("--print-md algo [files]");
	{
	    int all_algos = (**argv=='*' && !(*argv)[1]);
	    int algo = all_algos? 0 : gcry_md_map_name (*argv);

	    if( !algo && !all_algos )
		log_error(_("invalid hash algorithm '%s'\n"), *argv );
	    else {
		argc--; argv++;
		if( !argc )
		    print_mds(NULL, algo);
		else {
		    for(; argc; argc--, argv++ )
			print_mds(*argv, algo);
		}
	    }
	}
	break;

      case aPrintMDs: /* old option */
	if( !argc )
	    print_mds(NULL,0);
	else {
	    for(; argc; argc--, argv++ )
		print_mds(*argv,0);
	}
	break;

#ifndef NO_TRUST_MODELS
      case aListTrustDB:
	if( !argc )
          list_trustdb (es_stdout, NULL);
	else {
	    for( ; argc; argc--, argv++ )
              list_trustdb (es_stdout, *argv );
	}
	break;

      case aUpdateTrustDB:
	if( argc )
	    wrong_args("--update-trustdb");
	update_trustdb();
	break;

      case aCheckTrustDB:
        /* Old versions allowed for arguments - ignore them */
        check_trustdb();
	break;

      case aFixTrustDB:
        how_to_fix_the_trustdb ();
	break;

      case aListTrustPath:
	if( !argc )
	    wrong_args("--list-trust-path <user-ids>");
	for( ; argc; argc--, argv++ ) {
	    username = make_username( *argv );
	    list_trust_path( username );
	    xfree(username);
	}
	break;

      case aExportOwnerTrust:
	if( argc )
	    wrong_args("--export-ownertrust");
	export_ownertrust();
	break;

      case aImportOwnerTrust:
	if( argc > 1 )
	    wrong_args("--import-ownertrust [file]");
	import_ownertrust( argc? *argv:NULL );
	break;
#endif /*!NO_TRUST_MODELS*/

      case aRebuildKeydbCaches:
        if (argc)
            wrong_args ("--rebuild-keydb-caches");
        keydb_rebuild_caches (1);
        break;

#ifdef ENABLE_CARD_SUPPORT
      case aCardStatus:
        if (argc)
            wrong_args ("--card-status");
        card_status (es_stdout, NULL, 0);
        break;

      case aCardEdit:
        if (argc) {
            sl = NULL;
            for (argc--, argv++ ; argc; argc--, argv++)
                append_to_strlist (&sl, *argv);
            card_edit (ctrl, sl);
            free_strlist (sl);
	}
        else
          card_edit (ctrl, NULL);
        break;

      case aChangePIN:
        if (!argc)
            change_pin (0,1);
        else if (argc == 1)
            change_pin (atoi (*argv),1);
        else
        wrong_args ("--change-pin [no]");
        break;
#endif /* ENABLE_CARD_SUPPORT*/

      case aListConfig:
	{
	  char *str=collapse_args(argc,argv);
	  list_config(str);
	  xfree(str);
	}
	break;

      case aListGcryptConfig:
        /* Fixme: It would be nice to integrate that with
           --list-config but unfortunately there is no way yet to have
           libgcrypt print it to an estream for further parsing.  */
        gcry_control (GCRYCTL_PRINT_CONFIG, stdout);
        break;

      case aListPackets:
	opt.list_packets=2;
      default:
	if( argc > 1 )
	    wrong_args(_("[filename]"));
	/* Issue some output for the unix newbie */
	if (!fname && !opt.outfile
            && gnupg_isatty (fileno (stdin))
            && gnupg_isatty (fileno (stdout))
            && gnupg_isatty (fileno (stderr)))
	    log_info(_("Go ahead and type your message ...\n"));

	a = iobuf_open(fname);
        if (a && is_secured_file (iobuf_get_fd (a)))
          {
            iobuf_close (a);
            a = NULL;
            gpg_err_set_errno (EPERM);
          }
	if( !a )
	    log_error(_("can't open '%s'\n"), print_fname_stdin(fname));
	else {

	    if( !opt.no_armor ) {
		if( use_armor_filter( a ) ) {
		    afx = new_armor_context ();
		    push_armor_filter (afx, a);
		}
	    }
	    if( cmd == aListPackets ) {
		set_packet_list_mode(1);
		opt.list_packets=1;
	    }
	    rc = proc_packets (ctrl, NULL, a );
	    if( rc )
		log_error("processing message failed: %s\n", gpg_strerror (rc));
	    iobuf_close(a);
	}
	break;
      }

    /* cleanup */
    gpg_deinit_default_ctrl (ctrl);
    xfree (ctrl);
    release_armor_context (afx);
    FREE_STRLIST(remusr);
    FREE_STRLIST(locusr);
    g10_exit(0);
    return 8; /*NEVER REACHED*/
}


/* Note: This function is used by signal handlers!. */
static void
emergency_cleanup (void)
{
  gcry_control (GCRYCTL_TERM_SECMEM );
}


void
g10_exit( int rc )
{
  gcry_control (GCRYCTL_UPDATE_RANDOM_SEED_FILE);
  if (DBG_CLOCK)
    log_clock ("stop");

  if ( (opt.debug & DBG_MEMSTAT_VALUE) )
    {
      keydb_dump_stats ();
      gcry_control (GCRYCTL_DUMP_MEMORY_STATS);
      gcry_control (GCRYCTL_DUMP_RANDOM_STATS);
    }
  if (opt.debug)
    gcry_control (GCRYCTL_DUMP_SECMEM_STATS );

  emergency_cleanup ();

  rc = rc? rc : log_get_errorcount(0)? 2 : g10_errors_seen? 1 : 0;
  exit (rc);
}


/* Pretty-print hex hashes.  This assumes at least an 80-character
   display, but there are a few other similar assumptions in the
   display code. */
static void
print_hex (gcry_md_hd_t md, int algo, const char *fname)
{
  int i,n,count,indent=0;
  const byte *p;

  if (fname)
    indent = es_printf("%s: ",fname);

  if (indent>40)
    {
      es_printf ("\n");
      indent=0;
    }

  if (algo==DIGEST_ALGO_RMD160)
    indent += es_printf("RMD160 = ");
  else if (algo>0)
    indent += es_printf("%6s = ", gcry_md_algo_name (algo));
  else
    algo = abs(algo);

  count = indent;

  p = gcry_md_read (md, algo);
  n = gcry_md_get_algo_dlen (algo);

  count += es_printf ("%02X",*p++);

  for(i=1;i<n;i++,p++)
    {
      if(n==16)
	{
	  if(count+2>79)
	    {
	      es_printf ("\n%*s",indent," ");
	      count = indent;
	    }
	  else
	    count += es_printf(" ");

	  if (!(i%8))
	    count += es_printf(" ");
	}
      else if (n==20)
	{
	  if(!(i%2))
	    {
	      if(count+4>79)
		{
		  es_printf ("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count += es_printf(" ");
	    }

	  if (!(i%10))
	    count += es_printf(" ");
	}
      else
	{
	  if(!(i%4))
	    {
	      if (count+8>79)
		{
		  es_printf ("\n%*s",indent," ");
		  count=indent;
		}
	      else
		count += es_printf(" ");
	    }
	}

      count += es_printf("%02X",*p);
    }

  es_printf ("\n");
}

static void
print_hashline( gcry_md_hd_t md, int algo, const char *fname )
{
  int i, n;
  const byte *p;

  if ( fname )
    {
      for (p = fname; *p; p++ )
        {
          if ( *p <= 32 || *p > 127 || *p == ':' || *p == '%' )
            es_printf ("%%%02X", *p );
          else
            es_putc (*p, es_stdout);
        }
    }
  es_putc (':', es_stdout);
  es_printf ("%d:", algo);
  p = gcry_md_read (md, algo);
  n = gcry_md_get_algo_dlen (algo);
  for(i=0; i < n ; i++, p++ )
    es_printf ("%02X", *p);
  es_fputs (":\n", es_stdout);
}


static void
print_mds( const char *fname, int algo )
{
  estream_t fp;
  char buf[1024];
  size_t n;
  gcry_md_hd_t md;

  if (!fname)
    {
      fp = es_stdin;
      es_set_binary (fp);
    }
  else
    {
      fp = es_fopen (fname, "rb" );
      if (fp && is_secured_file (es_fileno (fp)))
        {
          es_fclose (fp);
          fp = NULL;
          gpg_err_set_errno (EPERM);
        }
    }
  if (!fp)
    {
      log_error("%s: %s\n", fname?fname:"[stdin]", strerror(errno) );
      return;
    }

  gcry_md_open (&md, 0, 0);
  if (algo)
    gcry_md_enable (md, algo);
  else
    {
      if (!gcry_md_test_algo (GCRY_MD_MD5))
        gcry_md_enable (md, GCRY_MD_MD5);
      gcry_md_enable (md, GCRY_MD_SHA1);
      if (!gcry_md_test_algo (GCRY_MD_RMD160))
        gcry_md_enable (md, GCRY_MD_RMD160);
      if (!gcry_md_test_algo (GCRY_MD_SHA224))
        gcry_md_enable (md, GCRY_MD_SHA224);
      if (!gcry_md_test_algo (GCRY_MD_SHA256))
        gcry_md_enable (md, GCRY_MD_SHA256);
      if (!gcry_md_test_algo (GCRY_MD_SHA384))
        gcry_md_enable (md, GCRY_MD_SHA384);
      if (!gcry_md_test_algo (GCRY_MD_SHA512))
        gcry_md_enable (md, GCRY_MD_SHA512);
    }

  while ((n=es_fread (buf, 1, DIM(buf), fp)))
    gcry_md_write (md, buf, n);

  if (es_ferror(fp))
    log_error ("%s: %s\n", fname?fname:"[stdin]", strerror(errno));
  else
    {
      gcry_md_final (md);
      if (opt.with_colons)
        {
          if ( algo )
            print_hashline (md, algo, fname);
          else
            {
              if (!gcry_md_test_algo (GCRY_MD_MD5))
                print_hashline( md, GCRY_MD_MD5, fname );
              print_hashline( md, GCRY_MD_SHA1, fname );
              if (!gcry_md_test_algo (GCRY_MD_RMD160))
                print_hashline( md, GCRY_MD_RMD160, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA224))
                print_hashline (md, GCRY_MD_SHA224, fname);
              if (!gcry_md_test_algo (GCRY_MD_SHA256))
                print_hashline( md, GCRY_MD_SHA256, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA384))
                print_hashline ( md, GCRY_MD_SHA384, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA512))
                print_hashline ( md, GCRY_MD_SHA512, fname );
            }
        }
      else
        {
          if (algo)
            print_hex (md, -algo, fname);
          else
            {
              if (!gcry_md_test_algo (GCRY_MD_MD5))
                print_hex (md, GCRY_MD_MD5, fname);
              print_hex (md, GCRY_MD_SHA1, fname );
              if (!gcry_md_test_algo (GCRY_MD_RMD160))
                print_hex (md, GCRY_MD_RMD160, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA224))
                print_hex (md, GCRY_MD_SHA224, fname);
              if (!gcry_md_test_algo (GCRY_MD_SHA256))
                print_hex (md, GCRY_MD_SHA256, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA384))
                print_hex (md, GCRY_MD_SHA384, fname );
              if (!gcry_md_test_algo (GCRY_MD_SHA512))
                print_hex (md, GCRY_MD_SHA512, fname );
            }
        }
    }
  gcry_md_close (md);

  if (fp != es_stdin)
    es_fclose (fp);
}


/****************
 * Check the supplied name,value string and add it to the notation
 * data to be used for signatures.  which==0 for sig notations, and 1
 * for cert notations.
*/
static void
add_notation_data( const char *string, int which )
{
  struct notation *notation;

  notation=string_to_notation(string,utf8_strings);
  if(notation)
    {
      if(which)
	{
	  notation->next=opt.cert_notations;
	  opt.cert_notations=notation;
	}
      else
	{
	  notation->next=opt.sig_notations;
	  opt.sig_notations=notation;
	}
    }
}

static void
add_policy_url( const char *string, int which )
{
  unsigned int i,critical=0;
  strlist_t sl;

  if(*string=='!')
    {
      string++;
      critical=1;
    }

  for(i=0;i<strlen(string);i++)
    if( !isascii (string[i]) || iscntrl(string[i]))
      break;

  if(i==0 || i<strlen(string))
    {
      if(which)
	log_error(_("the given certification policy URL is invalid\n"));
      else
	log_error(_("the given signature policy URL is invalid\n"));
    }

  if(which)
    sl=add_to_strlist( &opt.cert_policy_url, string );
  else
    sl=add_to_strlist( &opt.sig_policy_url, string );

  if(critical)
    sl->flags |= 1;
}

static void
add_keyserver_url( const char *string, int which )
{
  unsigned int i,critical=0;
  strlist_t sl;

  if(*string=='!')
    {
      string++;
      critical=1;
    }

  for(i=0;i<strlen(string);i++)
    if( !isascii (string[i]) || iscntrl(string[i]))
      break;

  if(i==0 || i<strlen(string))
    {
      if(which)
	BUG();
      else
	log_error(_("the given preferred keyserver URL is invalid\n"));
    }

  if(which)
    BUG();
  else
    sl=add_to_strlist( &opt.sig_keyserver_url, string );

  if(critical)
    sl->flags |= 1;
}
