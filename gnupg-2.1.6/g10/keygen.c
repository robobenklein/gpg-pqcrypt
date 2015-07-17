/* keygen.c - Generate a key pair
 * Copyright (C) 1998-2007, 2009-2011  Free Software Foundation, Inc.
 * Copyright (C) 2014, 2015  Werner Koch
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
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "gpg.h"
#include "util.h"
#include "main.h"
#include "packet.h"
#include "ttyio.h"
#include "options.h"
#include "keydb.h"
#include "trustdb.h"
#include "status.h"
#include "i18n.h"
#include "keyserver-internal.h"
#include "call-agent.h"
#include "pkglue.h"
#include "../common/shareddefs.h"
#include "host2net.h"
#include "mbox-util.h"


/* The default algorithms.  If you change them remember to change them
   also in gpg.c:gpgconf_list.  You should also check that the value
   is inside the bounds enforced by ask_keysize and gen_xxx.  */
#define DEFAULT_STD_ALGO       PUBKEY_ALGO_RSA
#define DEFAULT_STD_KEYSIZE    2048
#define DEFAULT_STD_CURVE      NULL
#define DEFAULT_STD_SUBALGO    PUBKEY_ALGO_RSA
#define DEFAULT_STD_SUBKEYSIZE 2048
#define DEFAULT_STD_SUBCURVE   NULL

/* Flag bits used during key generation.  */
#define KEYGEN_FLAG_NO_PROTECTION 1
#define KEYGEN_FLAG_TRANSIENT_KEY 2

/* Maximum number of supported algorithm preferences.  */
#define MAX_PREFS 30

enum para_name {
  pKEYTYPE,
  pKEYLENGTH,
  pKEYCURVE,
  pKEYUSAGE,
  pSUBKEYTYPE,
  pSUBKEYLENGTH,
  pSUBKEYCURVE,
  pSUBKEYUSAGE,
  pAUTHKEYTYPE,
  pNAMEREAL,
  pNAMEEMAIL,
  pNAMECOMMENT,
  pPREFERENCES,
  pREVOKER,
  pUSERID,
  pCREATIONDATE,
  pKEYCREATIONDATE, /* Same in seconds since epoch.  */
  pEXPIREDATE,
  pKEYEXPIRE, /* in n seconds */
  pSUBKEYEXPIRE, /* in n seconds */
  pPASSPHRASE,
  pSERIALNO,
  pCARDBACKUPKEY,
  pHANDLE,
  pKEYSERVER
};

struct para_data_s {
    struct para_data_s *next;
    int lnr;
    enum para_name key;
    union {
        u32 expire;
        u32 creation;
        unsigned int usage;
        struct revocation_key revkey;
        char value[1];
    } u;
};

struct output_control_s
{
  int lnr;
  int dryrun;
  unsigned int keygen_flags;
  int use_files;
  struct {
    char  *fname;
    char  *newfname;
    IOBUF stream;
    armor_filter_context_t *afx;
  } pub;
};


struct opaque_data_usage_and_pk {
    unsigned int usage;
    PKT_public_key *pk;
};


static int prefs_initialized = 0;
static byte sym_prefs[MAX_PREFS];
static int nsym_prefs;
static byte hash_prefs[MAX_PREFS];
static int nhash_prefs;
static byte zip_prefs[MAX_PREFS];
static int nzip_prefs;
static int mdc_available,ks_modify;

static void do_generate_keypair( struct para_data_s *para,
				 struct output_control_s *outctrl, int card );
static int write_keyblock (iobuf_t out, kbnode_t node);
static gpg_error_t gen_card_key (int algo, int keyno, int is_primary,
                                 kbnode_t pub_root,
                                 u32 *timestamp, u32 expireval);
static int gen_card_key_with_backup (int algo, int keyno, int is_primary,
                                     kbnode_t pub_root, u32 timestamp,
                                     u32 expireval, struct para_data_s *para);


static void
print_status_key_created (int letter, PKT_public_key *pk, const char *handle)
{
  byte array[MAX_FINGERPRINT_LEN], *s;
  char *buf, *p;
  size_t i, n;

  if (!handle)
    handle = "";

  buf = xmalloc (MAX_FINGERPRINT_LEN*2+31 + strlen (handle) + 1);

  p = buf;
  if (letter || pk)
    {
      *p++ = letter;
      *p++ = ' ';
      fingerprint_from_pk (pk, array, &n);
      s = array;
      for (i=0; i < n ; i++, s++, p += 2)
        sprintf (p, "%02X", *s);
    }
  if (*handle)
    {
      *p++ = ' ';
      for (i=0; handle[i] && i < 100; i++)
        *p++ = isspace ((unsigned int)handle[i])? '_':handle[i];
    }
  *p = 0;
  write_status_text ((letter || pk)?STATUS_KEY_CREATED:STATUS_KEY_NOT_CREATED,
                     buf);
  xfree (buf);
}

static void
print_status_key_not_created (const char *handle)
{
  print_status_key_created (0, NULL, handle);
}



static void
write_uid( KBNODE root, const char *s )
{
    PACKET *pkt = xmalloc_clear(sizeof *pkt );
    size_t n = strlen(s);

    pkt->pkttype = PKT_USER_ID;
    pkt->pkt.user_id = xmalloc_clear( sizeof *pkt->pkt.user_id + n - 1 );
    pkt->pkt.user_id->len = n;
    pkt->pkt.user_id->ref = 1;
    strcpy(pkt->pkt.user_id->name, s);
    add_kbnode( root, new_kbnode( pkt ) );
}

static void
do_add_key_flags (PKT_signature *sig, unsigned int use)
{
    byte buf[1];

    buf[0] = 0;

    /* The spec says that all primary keys MUST be able to certify. */
    if(sig->sig_class!=0x18)
      buf[0] |= 0x01;

    if (use & PUBKEY_USAGE_SIG)
      buf[0] |= 0x02;
    if (use & PUBKEY_USAGE_ENC)
        buf[0] |= 0x04 | 0x08;
    if (use & PUBKEY_USAGE_AUTH)
        buf[0] |= 0x20;

    build_sig_subpkt (sig, SIGSUBPKT_KEY_FLAGS, buf, 1);
}


int
keygen_add_key_expire (PKT_signature *sig, void *opaque)
{
  PKT_public_key *pk = opaque;
  byte buf[8];
  u32  u;

  if (pk->expiredate)
    {
      if (pk->expiredate > pk->timestamp)
        u = pk->expiredate - pk->timestamp;
      else
        u = 1;

      buf[0] = (u >> 24) & 0xff;
      buf[1] = (u >> 16) & 0xff;
      buf[2] = (u >>	8) & 0xff;
      buf[3] = u & 0xff;
      build_sig_subpkt (sig, SIGSUBPKT_KEY_EXPIRE, buf, 4);
    }
  else
    {
      /* Make sure we don't leave a key expiration subpacket lying
         around */
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_KEY_EXPIRE);
    }

  return 0;
}


static int
keygen_add_key_flags_and_expire (PKT_signature *sig, void *opaque)
{
  struct opaque_data_usage_and_pk *oduap = opaque;

  do_add_key_flags (sig, oduap->usage);
  return keygen_add_key_expire (sig, oduap->pk);
}


static int
set_one_pref (int val, int type, const char *item, byte *buf, int *nbuf)
{
    int i;

    for (i=0; i < *nbuf; i++ )
      if (buf[i] == val)
	{
	  log_info (_("preference '%s' duplicated\n"), item);
	  return -1;
        }

    if (*nbuf >= MAX_PREFS)
      {
	if(type==1)
	  log_info(_("too many cipher preferences\n"));
	else if(type==2)
	  log_info(_("too many digest preferences\n"));
	else if(type==3)
	  log_info(_("too many compression preferences\n"));
	else
	  BUG();

        return -1;
      }

    buf[(*nbuf)++] = val;
    return 0;
}

/*
 * Parse the supplied string and use it to set the standard
 * preferences.  The string may be in a form like the one printed by
 * "pref" (something like: "S10 S3 H3 H2 Z2 Z1") or the actual
 * cipher/hash/compress names.  Use NULL to set the default
 * preferences.  Returns: 0 = okay
 */
int
keygen_set_std_prefs (const char *string,int personal)
{
    byte sym[MAX_PREFS], hash[MAX_PREFS], zip[MAX_PREFS];
    int nsym=0, nhash=0, nzip=0, val, rc=0;
    int mdc=1, modify=0; /* mdc defaults on, modify defaults off. */
    char dummy_string[20*4+1]; /* Enough for 20 items. */

    if (!string || !ascii_strcasecmp (string, "default"))
      {
	if (opt.def_preference_list)
	  string=opt.def_preference_list;
	else
	  {
            int any_compress = 0;
	    dummy_string[0]='\0';

            /* The rationale why we use the order AES256,192,128 is
               for compatibility reasons with PGP.  If gpg would
               define AES128 first, we would get the somewhat
               confusing situation:

                 gpg -r pgpkey -r gpgkey  ---gives--> AES256
                 gpg -r gpgkey -r pgpkey  ---gives--> AES

               Note that by using --personal-cipher-preferences it is
               possible to prefer AES128.
            */

	    /* Make sure we do not add more than 15 items here, as we
	       could overflow the size of dummy_string.  We currently
	       have at most 12. */
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES256) )
	      strcat(dummy_string,"S9 ");
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES192) )
	      strcat(dummy_string,"S8 ");
	    if ( !openpgp_cipher_test_algo (CIPHER_ALGO_AES) )
	      strcat(dummy_string,"S7 ");
	    strcat(dummy_string,"S2 "); /* 3DES */

            /* The default hash algo order is:
                 SHA-256, SHA-384, SHA-512, SHA-224, SHA-1.
             */
	    if (!openpgp_md_test_algo (DIGEST_ALGO_SHA256))
	      strcat (dummy_string, "H8 ");

	    if (!openpgp_md_test_algo (DIGEST_ALGO_SHA384))
	      strcat (dummy_string, "H9 ");

	    if (!openpgp_md_test_algo (DIGEST_ALGO_SHA512))
	      strcat (dummy_string, "H10 ");

	    if (!openpgp_md_test_algo (DIGEST_ALGO_SHA224))
	      strcat (dummy_string, "H11 ");

	    strcat (dummy_string, "H2 "); /* SHA-1 */

	    if(!check_compress_algo(COMPRESS_ALGO_ZLIB))
              {
                strcat(dummy_string,"Z2 ");
                any_compress = 1;
              }

	    if(!check_compress_algo(COMPRESS_ALGO_BZIP2))
              {
                strcat(dummy_string,"Z3 ");
                any_compress = 1;
              }

	    if(!check_compress_algo(COMPRESS_ALGO_ZIP))
              {
                strcat(dummy_string,"Z1 ");
                any_compress = 1;
              }

            /* In case we have no compress algo at all, declare that
               we prefer no compresssion.  */
            if (!any_compress)
              strcat(dummy_string,"Z0 ");

            /* Remove the trailing space.  */
            if (*dummy_string && dummy_string[strlen (dummy_string)-1] == ' ')
              dummy_string[strlen (dummy_string)-1] = 0;

	    string=dummy_string;
	  }
      }
    else if (!ascii_strcasecmp (string, "none"))
        string = "";

    if(strlen(string))
      {
	char *tok,*prefstring;

	prefstring=xstrdup(string); /* need a writable string! */

	while((tok=strsep(&prefstring," ,")))
	  {
	    if((val=string_to_cipher_algo (tok)))
	      {
		if(set_one_pref(val,1,tok,sym,&nsym))
		  rc=-1;
	      }
	    else if((val=string_to_digest_algo (tok)))
	      {
		if(set_one_pref(val,2,tok,hash,&nhash))
		  rc=-1;
	      }
	    else if((val=string_to_compress_algo(tok))>-1)
	      {
		if(set_one_pref(val,3,tok,zip,&nzip))
		  rc=-1;
	      }
	    else if (ascii_strcasecmp(tok,"mdc")==0)
	      mdc=1;
	    else if (ascii_strcasecmp(tok,"no-mdc")==0)
	      mdc=0;
	    else if (ascii_strcasecmp(tok,"ks-modify")==0)
	      modify=1;
	    else if (ascii_strcasecmp(tok,"no-ks-modify")==0)
	      modify=0;
	    else
	      {
		log_info (_("invalid item '%s' in preference string\n"),tok);
		rc=-1;
	      }
	  }

	xfree(prefstring);
      }

    if(!rc)
      {
	if(personal)
	  {
	    if(personal==PREFTYPE_SYM)
	      {
		xfree(opt.personal_cipher_prefs);

		if(nsym==0)
		  opt.personal_cipher_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_cipher_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nsym+1));

		    for (i=0; i<nsym; i++)
		      {
			opt.personal_cipher_prefs[i].type = PREFTYPE_SYM;
			opt.personal_cipher_prefs[i].value = sym[i];
		      }

		    opt.personal_cipher_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_cipher_prefs[i].value = 0;
		  }
	      }
	    else if(personal==PREFTYPE_HASH)
	      {
		xfree(opt.personal_digest_prefs);

		if(nhash==0)
		  opt.personal_digest_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_digest_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nhash+1));

		    for (i=0; i<nhash; i++)
		      {
			opt.personal_digest_prefs[i].type = PREFTYPE_HASH;
			opt.personal_digest_prefs[i].value = hash[i];
		      }

		    opt.personal_digest_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_digest_prefs[i].value = 0;
		  }
	      }
	    else if(personal==PREFTYPE_ZIP)
	      {
		xfree(opt.personal_compress_prefs);

		if(nzip==0)
		  opt.personal_compress_prefs=NULL;
		else
		  {
		    int i;

		    opt.personal_compress_prefs=
		      xmalloc(sizeof(prefitem_t *)*(nzip+1));

		    for (i=0; i<nzip; i++)
		      {
			opt.personal_compress_prefs[i].type = PREFTYPE_ZIP;
			opt.personal_compress_prefs[i].value = zip[i];
		      }

		    opt.personal_compress_prefs[i].type = PREFTYPE_NONE;
		    opt.personal_compress_prefs[i].value = 0;
		  }
	      }
	  }
	else
	  {
	    memcpy (sym_prefs,  sym,  (nsym_prefs=nsym));
	    memcpy (hash_prefs, hash, (nhash_prefs=nhash));
	    memcpy (zip_prefs,  zip,  (nzip_prefs=nzip));
	    mdc_available = mdc;
	    ks_modify = modify;
	    prefs_initialized = 1;
	  }
      }

    return rc;
}

/* Return a fake user ID containing the preferences.  Caller must
   free. */
PKT_user_id *
keygen_get_std_prefs(void)
{
  int i,j=0;
  PKT_user_id *uid=xmalloc_clear(sizeof(PKT_user_id));

  if(!prefs_initialized)
    keygen_set_std_prefs(NULL,0);

  uid->ref=1;

  uid->prefs=xmalloc((sizeof(prefitem_t *)*
		      (nsym_prefs+nhash_prefs+nzip_prefs+1)));

  for(i=0;i<nsym_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_SYM;
      uid->prefs[j].value=sym_prefs[i];
    }

  for(i=0;i<nhash_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_HASH;
      uid->prefs[j].value=hash_prefs[i];
    }

  for(i=0;i<nzip_prefs;i++,j++)
    {
      uid->prefs[j].type=PREFTYPE_ZIP;
      uid->prefs[j].value=zip_prefs[i];
    }

  uid->prefs[j].type=PREFTYPE_NONE;
  uid->prefs[j].value=0;

  uid->flags.mdc=mdc_available;
  uid->flags.ks_modify=ks_modify;

  return uid;
}

static void
add_feature_mdc (PKT_signature *sig,int enabled)
{
    const byte *s;
    size_t n;
    int i;
    char *buf;

    s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES, &n );
    /* Already set or cleared */
    if (s && n &&
	((enabled && (s[0] & 0x01)) || (!enabled && !(s[0] & 0x01))))
      return;

    if (!s || !n) { /* create a new one */
        n = 1;
        buf = xmalloc_clear (n);
    }
    else {
        buf = xmalloc (n);
        memcpy (buf, s, n);
    }

    if(enabled)
      buf[0] |= 0x01; /* MDC feature */
    else
      buf[0] &= ~0x01;

    /* Are there any bits set? */
    for(i=0;i<n;i++)
      if(buf[i]!=0)
	break;

    if(i==n)
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_FEATURES);
    else
      build_sig_subpkt (sig, SIGSUBPKT_FEATURES, buf, n);

    xfree (buf);
}

static void
add_keyserver_modify (PKT_signature *sig,int enabled)
{
  const byte *s;
  size_t n;
  int i;
  char *buf;

  /* The keyserver modify flag is a negative flag (i.e. no-modify) */
  enabled=!enabled;

  s = parse_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS, &n );
  /* Already set or cleared */
  if (s && n &&
      ((enabled && (s[0] & 0x80)) || (!enabled && !(s[0] & 0x80))))
    return;

  if (!s || !n) { /* create a new one */
    n = 1;
    buf = xmalloc_clear (n);
  }
  else {
    buf = xmalloc (n);
    memcpy (buf, s, n);
  }

  if(enabled)
    buf[0] |= 0x80; /* no-modify flag */
  else
    buf[0] &= ~0x80;

  /* Are there any bits set? */
  for(i=0;i<n;i++)
    if(buf[i]!=0)
      break;

  if(i==n)
    delete_sig_subpkt (sig->hashed, SIGSUBPKT_KS_FLAGS);
  else
    build_sig_subpkt (sig, SIGSUBPKT_KS_FLAGS, buf, n);

  xfree (buf);
}


int
keygen_upd_std_prefs (PKT_signature *sig, void *opaque)
{
  (void)opaque;

  if (!prefs_initialized)
    keygen_set_std_prefs (NULL, 0);

  if (nsym_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_SYM, sym_prefs, nsym_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_SYM);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_SYM);
    }

  if (nhash_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_HASH, hash_prefs, nhash_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_HASH);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_HASH);
    }

  if (nzip_prefs)
    build_sig_subpkt (sig, SIGSUBPKT_PREF_COMPR, zip_prefs, nzip_prefs);
  else
    {
      delete_sig_subpkt (sig->hashed, SIGSUBPKT_PREF_COMPR);
      delete_sig_subpkt (sig->unhashed, SIGSUBPKT_PREF_COMPR);
    }

  /* Make sure that the MDC feature flag is set if needed.  */
  add_feature_mdc (sig,mdc_available);
  add_keyserver_modify (sig,ks_modify);
  keygen_add_keyserver_url(sig,NULL);

  return 0;
}


/****************
 * Add preference to the self signature packet.
 * This is only called for packets with version > 3.
 */
int
keygen_add_std_prefs (PKT_signature *sig, void *opaque)
{
  PKT_public_key *pk = opaque;

  do_add_key_flags (sig, pk->pubkey_usage);
  keygen_add_key_expire (sig, opaque );
  keygen_upd_std_prefs (sig, opaque);
  keygen_add_keyserver_url (sig,NULL);

  return 0;
}

int
keygen_add_keyserver_url(PKT_signature *sig, void *opaque)
{
  const char *url=opaque;

  if(!url)
    url=opt.def_keyserver_url;

  if(url)
    build_sig_subpkt(sig,SIGSUBPKT_PREF_KS,url,strlen(url));
  else
    delete_sig_subpkt (sig->hashed,SIGSUBPKT_PREF_KS);

  return 0;
}

int
keygen_add_notations(PKT_signature *sig,void *opaque)
{
  struct notation *notation;

  /* We always start clean */
  delete_sig_subpkt(sig->hashed,SIGSUBPKT_NOTATION);
  delete_sig_subpkt(sig->unhashed,SIGSUBPKT_NOTATION);
  sig->flags.notation=0;

  for(notation=opaque;notation;notation=notation->next)
    if(!notation->flags.ignore)
      {
	unsigned char *buf;
	unsigned int n1,n2;

	n1=strlen(notation->name);
	if(notation->altvalue)
	  n2=strlen(notation->altvalue);
	else if(notation->bdat)
	  n2=notation->blen;
	else
	  n2=strlen(notation->value);

	buf = xmalloc( 8 + n1 + n2 );

	/* human readable or not */
	buf[0] = notation->bdat?0:0x80;
	buf[1] = buf[2] = buf[3] = 0;
	buf[4] = n1 >> 8;
	buf[5] = n1;
	buf[6] = n2 >> 8;
	buf[7] = n2;
	memcpy(buf+8, notation->name, n1 );
	if(notation->altvalue)
	  memcpy(buf+8+n1, notation->altvalue, n2 );
	else if(notation->bdat)
	  memcpy(buf+8+n1, notation->bdat, n2 );
	else
	  memcpy(buf+8+n1, notation->value, n2 );
	build_sig_subpkt( sig, SIGSUBPKT_NOTATION |
			  (notation->flags.critical?SIGSUBPKT_FLAG_CRITICAL:0),
			  buf, 8+n1+n2 );
	xfree(buf);
      }

  return 0;
}

int
keygen_add_revkey (PKT_signature *sig, void *opaque)
{
  struct revocation_key *revkey = opaque;
  byte buf[2+MAX_FINGERPRINT_LEN];

  buf[0] = revkey->class;
  buf[1] = revkey->algid;
  memcpy (&buf[2], revkey->fpr, MAX_FINGERPRINT_LEN);

  build_sig_subpkt (sig, SIGSUBPKT_REV_KEY, buf, 2+MAX_FINGERPRINT_LEN);

  /* All sigs with revocation keys set are nonrevocable.  */
  sig->flags.revocable = 0;
  buf[0] = 0;
  build_sig_subpkt (sig, SIGSUBPKT_REVOCABLE, buf, 1);

  parse_revkeys (sig);

  return 0;
}



/* Create a back-signature.  If TIMESTAMP is not NULL, use it for the
   signature creation time.  */
gpg_error_t
make_backsig (PKT_signature *sig, PKT_public_key *pk,
              PKT_public_key *sub_pk, PKT_public_key *sub_psk,
              u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PKT_signature *backsig;

  cache_public_key (sub_pk);

  err = make_keysig_packet (&backsig, pk, NULL, sub_pk, sub_psk, 0x19,
                            0, timestamp, 0, NULL, NULL, cache_nonce);
  if (err)
    log_error ("make_keysig_packet failed for backsig: %s\n",
               gpg_strerror (err));
  else
    {
      /* Get it into a binary packed form. */
      IOBUF backsig_out = iobuf_temp();
      PACKET backsig_pkt;

      init_packet (&backsig_pkt);
      backsig_pkt.pkttype = PKT_SIGNATURE;
      backsig_pkt.pkt.signature = backsig;
      err = build_packet (backsig_out, &backsig_pkt);
      free_packet (&backsig_pkt);
      if (err)
	log_error ("build_packet failed for backsig: %s\n", gpg_strerror (err));
      else
	{
	  size_t pktlen = 0;
	  byte *buf = iobuf_get_temp_buffer (backsig_out);

	  /* Remove the packet header. */
	  if(buf[0]&0x40)
	    {
	      if (buf[1] < 192)
		{
		  pktlen = buf[1];
		  buf += 2;
		}
	      else if(buf[1] < 224)
		{
		  pktlen = (buf[1]-192)*256;
		  pktlen += buf[2]+192;
		  buf += 3;
		}
	      else if (buf[1] == 255)
		{
                  pktlen = buf32_to_size_t (buf+2);
		  buf += 6;
		}
	      else
		BUG ();
	    }
	  else
	    {
	      int mark = 1;

	      switch (buf[0]&3)
		{
		case 3:
		  BUG ();
		  break;

		case 2:
		  pktlen  = (size_t)buf[mark++] << 24;
		  pktlen |= buf[mark++] << 16;

		case 1:
		  pktlen |= buf[mark++] << 8;

		case 0:
		  pktlen |= buf[mark++];
		}

	      buf += mark;
	    }

	  /* Now make the binary blob into a subpacket.  */
	  build_sig_subpkt (sig, SIGSUBPKT_SIGNATURE, buf, pktlen);

	  iobuf_close (backsig_out);
	}
    }

  return err;
}


/* Write a direct key signature to the first key in ROOT using the key
   PSK.  REVKEY is describes the direct key signature and TIMESTAMP is
   the timestamp to set on the signature.  */
static gpg_error_t
write_direct_sig (KBNODE root, PKT_public_key *psk,
                  struct revocation_key *revkey, u32 timestamp,
                  const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  KBNODE node;
  PKT_public_key *pk;

  if (opt.verbose)
    log_info (_("writing direct signature\n"));

  /* Get the pk packet from the pub_tree. */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG ();
  pk = node->pkt->pkt.public_key;

  /* We have to cache the key, so that the verification of the
     signature creation is able to retrieve the public key.  */
  cache_public_key (pk);

  /* Make the signature.  */
  err = make_keysig_packet (&sig, pk, NULL,NULL, psk, 0x1F,
                            0, timestamp, 0,
                            keygen_add_revkey, revkey, cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packet failed: %s\n", gpg_strerror (err) );
      return err;
    }

  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt));
  return err;
}



/* Write a self-signature to the first user id in ROOT using the key
   PSK.  USE and TIMESTAMP give the extra data we need for the
   signature.  */
static gpg_error_t
write_selfsigs (KBNODE root, PKT_public_key *psk,
		unsigned int use, u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  PKT_user_id *uid;
  KBNODE node;
  PKT_public_key *pk;

  if (opt.verbose)
    log_info (_("writing self signature\n"));

  /* Get the uid packet from the list. */
  node = find_kbnode (root, PKT_USER_ID);
  if (!node)
    BUG(); /* No user id packet in tree.  */
  uid = node->pkt->pkt.user_id;

  /* Get the pk packet from the pub_tree. */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG();
  pk = node->pkt->pkt.public_key;

  /* The usage has not yet been set - do it now. */
  pk->pubkey_usage = use;

  /* We have to cache the key, so that the verification of the
     signature creation is able to retrieve the public key.  */
  cache_public_key (pk);

  /* Make the signature.  */
  err = make_keysig_packet (&sig, pk, uid, NULL, psk, 0x13,
                            0, timestamp, 0,
                            keygen_add_std_prefs, pk, cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packet failed: %s\n", gpg_strerror (err));
      return err;
    }

  pkt = xmalloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt));

  return err;
}


/* Write the key binding signature.  If TIMESTAMP is not NULL use the
   signature creation time.  PRI_PSK is the key use for signing.
   SUB_PSK is a key used to create a back-signature; that one is only
   used if USE has the PUBKEY_USAGE_SIG capability.  */
static int
write_keybinding (KBNODE root, PKT_public_key *pri_psk, PKT_public_key *sub_psk,
                  unsigned int use, u32 timestamp, const char *cache_nonce)
{
  gpg_error_t err;
  PACKET *pkt;
  PKT_signature *sig;
  KBNODE node;
  PKT_public_key *pri_pk, *sub_pk;
  struct opaque_data_usage_and_pk oduap;

  if (opt.verbose)
    log_info(_("writing key binding signature\n"));

  /* Get the primary pk packet from the tree.  */
  node = find_kbnode (root, PKT_PUBLIC_KEY);
  if (!node)
    BUG();
  pri_pk = node->pkt->pkt.public_key;

  /* We have to cache the key, so that the verification of the
   * signature creation is able to retrieve the public key.  */
  cache_public_key (pri_pk);

  /* Find the last subkey. */
  sub_pk = NULL;
  for (node = root; node; node = node->next )
    {
      if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
        sub_pk = node->pkt->pkt.public_key;
    }
  if (!sub_pk)
    BUG();

  /* Make the signature.  */
  oduap.usage = use;
  oduap.pk = sub_pk;
  err = make_keysig_packet (&sig, pri_pk, NULL, sub_pk, pri_psk, 0x18,
                            0, timestamp, 0,
                            keygen_add_key_flags_and_expire, &oduap,
                            cache_nonce);
  if (err)
    {
      log_error ("make_keysig_packeto failed: %s\n", gpg_strerror (err));
      return err;
    }

  /* Make a backsig.  */
  if (use & PUBKEY_USAGE_SIG)
    {
      err = make_backsig (sig, pri_pk, sub_pk, sub_psk, timestamp, cache_nonce);
      if (err)
        return err;
    }

  pkt = xmalloc_clear ( sizeof *pkt );
  pkt->pkttype = PKT_SIGNATURE;
  pkt->pkt.signature = sig;
  add_kbnode (root, new_kbnode (pkt) );
  return err;
}


static gpg_error_t
ecckey_from_sexp (gcry_mpi_t *array, gcry_sexp_t sexp, int algo)
{
  gpg_error_t err;
  gcry_sexp_t list, l2;
  char *curve;
  int i;
  const char *oidstr;
  unsigned int nbits;

  array[0] = NULL;
  array[1] = NULL;
  array[2] = NULL;

  list = gcry_sexp_find_token (sexp, "public-key", 0);
  if (!list)
    return gpg_error (GPG_ERR_INV_OBJ);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ);

  l2 = gcry_sexp_find_token (list, "curve", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  curve = gcry_sexp_nth_string (l2, 1);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  gcry_sexp_release (l2);
  oidstr = openpgp_curve_to_oid (curve, &nbits);
  if (!oidstr)
    {
      /* That can't happen because we used one of the curves
         gpg_curve_to_oid knows about.  */
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  err = openpgp_oid_from_str (oidstr, &array[0]);
  if (err)
    goto leave;

  l2 = gcry_sexp_find_token (list, "q", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  array[1] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l2);
  if (!array[1])
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  gcry_sexp_release (list);

  if (algo == PUBKEY_ALGO_ECDH)
    {
      array[2] = pk_ecdh_default_params (nbits);
      if (!array[2])
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

 leave:
  if (err)
    {
      for (i=0; i < 3; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
        }
    }
  return err;
}


/* Extract key parameters from SEXP and store them in ARRAY.  ELEMS is
   a string where each character denotes a parameter name.  TOPNAME is
   the name of the top element above the elements.  */
static int
key_from_sexp (gcry_mpi_t *array, gcry_sexp_t sexp,
               const char *topname, const char *elems)
{
  gcry_sexp_t list, l2;
  const char *s;
  int i, idx;
  int rc = 0;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (!list)
    return gpg_error (GPG_ERR_INV_OBJ);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ);

  for (idx=0,s=elems; *s; s++, idx++)
    {
      l2 = gcry_sexp_find_token (list, s, 1);
      if (!l2)
        {
          rc = gpg_error (GPG_ERR_NO_OBJ); /* required parameter not found */
          goto leave;
        }
      array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
      gcry_sexp_release (l2);
      if (!array[idx])
        {
          rc = gpg_error (GPG_ERR_INV_OBJ); /* required parameter invalid */
          goto leave;
        }
    }
  gcry_sexp_release (list);

 leave:
  if (rc)
    {
      for (i=0; i<idx; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
        }
      gcry_sexp_release (list);
    }
  return rc;
}


/* Create a keyblock using the given KEYGRIP.  ALGO is the OpenPGP
   algorithm of that keygrip.  */
static int
do_create_from_keygrip (ctrl_t ctrl, int algo, const char *hexkeygrip,
                        kbnode_t pub_root, u32 timestamp, u32 expireval,
                        int is_subkey)
{
  int err;
  PACKET *pkt;
  PKT_public_key *pk;
  gcry_sexp_t s_key;
  const char *algoelem;

  if (hexkeygrip[0] == '&')
    hexkeygrip++;

  switch (algo)
    {
    case PUBKEY_ALGO_RSA:       algoelem = "ne"; break;
    case PUBKEY_ALGO_DSA:       algoelem = "pqgy"; break;
    case PUBKEY_ALGO_ELGAMAL_E: algoelem = "pgy"; break;
    case PUBKEY_ALGO_ECDH:
    case PUBKEY_ALGO_ECDSA:     algoelem = ""; break;
    case PUBKEY_ALGO_EDDSA:     algoelem = ""; break;
    default: return gpg_error (GPG_ERR_INTERNAL);
    }


  /* Ask the agent for the public key matching HEXKEYGRIP.  */
  {
    unsigned char *public;

    err = agent_readkey (ctrl, 0, hexkeygrip, &public);
    if (err)
      return err;
    err = gcry_sexp_sscan (&s_key, NULL,
                           public, gcry_sexp_canon_len (public, 0, NULL, NULL));
    xfree (public);
    if (err)
      return err;
  }

  /* Build a public key packet.  */
  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      gcry_sexp_release (s_key);
      return err;
    }

  pk->timestamp = timestamp;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;

  if (algo == PUBKEY_ALGO_ECDSA
      || algo == PUBKEY_ALGO_EDDSA
      || algo == PUBKEY_ALGO_ECDH )
    err = ecckey_from_sexp (pk->pkey, s_key, algo);
  else
    err = key_from_sexp (pk->pkey, s_key, "public-key", algoelem);
  if (err)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
      gcry_sexp_release (s_key);
      free_public_key (pk);
      return err;
    }
  gcry_sexp_release (s_key);

  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      err = gpg_error_from_syserror ();
      free_public_key (pk);
      return err;
    }

  pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
}


/* Common code for the key generation fucntion gen_xxx.  */
static int
common_gen (const char *keyparms, int algo, const char *algoelem,
            kbnode_t pub_root, u32 timestamp, u32 expireval, int is_subkey,
            int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  int err;
  PACKET *pkt;
  PKT_public_key *pk;
  gcry_sexp_t s_key;

  err = agent_genkey (NULL, cache_nonce_addr, keyparms,
                      !!(keygen_flags & KEYGEN_FLAG_NO_PROTECTION),
                      passphrase,
                      &s_key);
  if (err)
    {
      log_error ("agent_genkey failed: %s\n", gpg_strerror (err) );
      return err;
    }

  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      gcry_sexp_release (s_key);
      return err;
    }

  pk->timestamp = timestamp;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;

  if (algo == PUBKEY_ALGO_ECDSA
      || algo == PUBKEY_ALGO_EDDSA
      || algo == PUBKEY_ALGO_ECDH )
    err = ecckey_from_sexp (pk->pkey, s_key, algo);
  else
    err = key_from_sexp (pk->pkey, s_key, "public-key", algoelem);
  if (err)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
      gcry_sexp_release (s_key);
      free_public_key (pk);
      return err;
    }
  gcry_sexp_release (s_key);

  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      err = gpg_error_from_syserror ();
      free_public_key (pk);
      return err;
    }

  pkt->pkttype = is_subkey ? PKT_PUBLIC_SUBKEY : PKT_PUBLIC_KEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
}


/*
 * Generate an Elgamal key.
 */
static int
gen_elg (int algo, unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  int err;
  char *keyparms;
  char nbitsstr[35];

  assert (is_ELGAMAL (algo));

  if (nbits < 1024)
    {
      nbits = 2048;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }
  else if (nbits > 4096)
    {
      nbits = 4096;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info (_("keysize rounded up to %u bits\n"), nbits );
    }

  /* Note that we use transient-key only if no-protection has also
     been enabled.  */
  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  keyparms = xtryasprintf ("(genkey(%s(nbits %zu:%s)%s))",
                           algo == GCRY_PK_ELG_E ? "openpgp-elg" :
                           algo == GCRY_PK_ELG	 ? "elg" : "x-oops" ,
                           strlen (nbitsstr), nbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "pgy",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase, cache_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/*
 * Generate an DSA key
 */
static gpg_error_t
gen_dsa (unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  int err;
  unsigned int qbits;
  char *keyparms;
  char nbitsstr[35];
  char qbitsstr[35];

  if (nbits < 768)
    {
      nbits = 2048;
      log_info(_("keysize invalid; using %u bits\n"), nbits );
    }
  else if ( nbits > 3072 )
    {
      nbits = 3072;
      log_info(_("keysize invalid; using %u bits\n"), nbits );
    }

  if( (nbits % 64) )
    {
      nbits = ((nbits + 63) / 64) * 64;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  /* To comply with FIPS rules we round up to the next value unless in
     expert mode.  */
  if (!opt.expert && nbits > 1024 && (nbits % 1024))
    {
      nbits = ((nbits + 1023) / 1024) * 1024;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  /*
    Figure out a q size based on the key size.  FIPS 180-3 says:

    L = 1024, N = 160
    L = 2048, N = 224
    L = 2048, N = 256
    L = 3072, N = 256

    2048/256 is an odd pair since there is also a 2048/224 and
    3072/256.  Matching sizes is not a very exact science.

    We'll do 256 qbits for nbits over 2047, 224 for nbits over 1024
    but less than 2048, and 160 for 1024 (DSA1).
  */

  if (nbits > 2047)
    qbits = 256;
  else if ( nbits > 1024)
    qbits = 224;
  else
    qbits = 160;

  if (qbits != 160 )
    log_info (_("WARNING: some OpenPGP programs can't"
                " handle a DSA key with this digest size\n"));

  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  snprintf (qbitsstr, sizeof qbitsstr, "%u", qbits);
  keyparms = xtryasprintf ("(genkey(dsa(nbits %zu:%s)(qbits %zu:%s)%s))",
                           strlen (nbitsstr), nbitsstr,
                           strlen (qbitsstr), qbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, PUBKEY_ALGO_DSA, "pqgy",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase, cache_nonce_addr);
      xfree (keyparms);
    }

  return err;
}



/*
 * Generate an ECC key
 */
static gpg_error_t
gen_ecc (int algo, const char *curve, kbnode_t pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  gpg_error_t err;
  char *keyparms;

  assert (algo == PUBKEY_ALGO_ECDSA
          || algo == PUBKEY_ALGO_EDDSA
          || algo == PUBKEY_ALGO_ECDH);

  if (!curve || !*curve)
    return gpg_error (GPG_ERR_UNKNOWN_CURVE);

  /* Note that we use the "comp" flag with EdDSA to request the use of
     a 0x40 compression prefix octet.  */
  if (algo == PUBKEY_ALGO_EDDSA)
    keyparms = xtryasprintf
      ("(genkey(ecc(curve %zu:%s)(flags eddsa comp%s)))",
       strlen (curve), curve,
       (((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
         && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
        " transient-key" : ""));
  else
    keyparms = xtryasprintf
      ("(genkey(ecc(curve %zu:%s)(flags nocomp%s)))",
       strlen (curve), curve,
       (((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
         && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
        " transient-key" : ""));

  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase, cache_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/*
 * Generate an RSA key.
 */
static int
gen_rsa (int algo, unsigned int nbits, KBNODE pub_root,
         u32 timestamp, u32 expireval, int is_subkey,
         int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  int err;
  char *keyparms;
  char nbitsstr[35];
  const unsigned maxsize = (opt.flags.large_rsa ? 8192 : 4096);

  assert (is_RSA(algo));

  if (!nbits)
    nbits = DEFAULT_STD_KEYSIZE;

  if (nbits < 1024)
    {
      nbits = 2048;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }
  else if (nbits > maxsize)
    {
      nbits = maxsize;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info (_("keysize rounded up to %u bits\n"), nbits );
    }

  snprintf (nbitsstr, sizeof nbitsstr, "%u", nbits);
  keyparms = xtryasprintf ("(genkey(rsa(nbits %zu:%s)%s))",
                           strlen (nbitsstr), nbitsstr,
                           ((keygen_flags & KEYGEN_FLAG_TRANSIENT_KEY)
                            && (keygen_flags & KEYGEN_FLAG_NO_PROTECTION))?
                           "(transient-key)" : "" );
  if (!keyparms)
    err = gpg_error_from_syserror ();
  else
    {
      err = common_gen (keyparms, algo, "ne",
                        pub_root, timestamp, expireval, is_subkey,
                        keygen_flags, passphrase, cache_nonce_addr);
      xfree (keyparms);
    }

  return err;
}


/****************
 * check valid days:
 * return 0 on error or the multiplier
 */
static int
check_valid_days( const char *s )
{
    if( !digitp(s) )
	return 0;
    for( s++; *s; s++)
	if( !digitp(s) )
	    break;
    if( !*s )
	return 1;
    if( s[1] )
	return 0; /* e.g. "2323wc" */
    if( *s == 'd' || *s == 'D' )
	return 1;
    if( *s == 'w' || *s == 'W' )
	return 7;
    if( *s == 'm' || *s == 'M' )
	return 30;
    if( *s == 'y' || *s == 'Y' )
	return 365;
    return 0;
}


static void
print_key_flags(int flags)
{
  if(flags&PUBKEY_USAGE_SIG)
    tty_printf("%s ",_("Sign"));

  if(flags&PUBKEY_USAGE_CERT)
    tty_printf("%s ",_("Certify"));

  if(flags&PUBKEY_USAGE_ENC)
    tty_printf("%s ",_("Encrypt"));

  if(flags&PUBKEY_USAGE_AUTH)
    tty_printf("%s ",_("Authenticate"));
}


/* Returns the key flags */
static unsigned int
ask_key_flags(int algo,int subkey)
{
  /* TRANSLATORS: Please use only plain ASCII characters for the
     translation.  If this is not possible use single digits.  The
     string needs to 8 bytes long. Here is a description of the
     functions:

       s = Toggle signing capability
       e = Toggle encryption capability
       a = Toggle authentication capability
       q = Finish
  */
  const char *togglers=_("SsEeAaQq");
  char *answer=NULL;
  const char *s;
  unsigned int current=0;
  unsigned int possible=openpgp_pk_algo_usage(algo);

  if ( strlen(togglers) != 8 )
    {
      tty_printf ("NOTE: Bad translation at %s:%d. "
                  "Please report.\n", __FILE__, __LINE__);
      togglers = "11223300";
    }

  /* Only primary keys may certify. */
  if(subkey)
    possible&=~PUBKEY_USAGE_CERT;

  /* Preload the current set with the possible set, minus
     authentication, since nobody really uses auth yet. */
  current=possible&~PUBKEY_USAGE_AUTH;

  for(;;)
    {
      tty_printf("\n");
      tty_printf(_("Possible actions for a %s key: "),
		 openpgp_pk_algo_name (algo));
      print_key_flags(possible);
      tty_printf("\n");
      tty_printf(_("Current allowed actions: "));
      print_key_flags(current);
      tty_printf("\n\n");

      if(possible&PUBKEY_USAGE_SIG)
	tty_printf(_("   (%c) Toggle the sign capability\n"),
		   togglers[0]);
      if(possible&PUBKEY_USAGE_ENC)
	tty_printf(_("   (%c) Toggle the encrypt capability\n"),
		   togglers[2]);
      if(possible&PUBKEY_USAGE_AUTH)
	tty_printf(_("   (%c) Toggle the authenticate capability\n"),
		   togglers[4]);

      tty_printf(_("   (%c) Finished\n"),togglers[6]);
      tty_printf("\n");

      xfree(answer);
      answer = cpr_get("keygen.flags",_("Your selection? "));
      cpr_kill_prompt();

      if (*answer == '=')
        {
          /* Hack to allow direct entry of the capabilities.  */
          current = 0;
          for (s=answer+1; *s; s++)
            {
              if ((*s == 's' || *s == 'S') && (possible&PUBKEY_USAGE_SIG))
                current |= PUBKEY_USAGE_SIG;
              else if ((*s == 'e' || *s == 'E') && (possible&PUBKEY_USAGE_ENC))
                current |= PUBKEY_USAGE_ENC;
              else if ((*s == 'a' || *s == 'A') && (possible&PUBKEY_USAGE_AUTH))
                current |= PUBKEY_USAGE_AUTH;
              else if (!subkey && *s == 'c')
                {
                  /* Accept 'c' for the primary key because USAGE_CERT
                     will will be set anyway.  This is for folks who
                     want to experiment with a cert-only primary key.  */
                  current |= PUBKEY_USAGE_CERT;
                }
            }
          break;
        }
      else if (strlen(answer)>1)
	tty_printf(_("Invalid selection.\n"));
      else if(*answer=='\0' || *answer==togglers[6] || *answer==togglers[7])
	break;
      else if((*answer==togglers[0] || *answer==togglers[1])
	      && possible&PUBKEY_USAGE_SIG)
	{
	  if(current&PUBKEY_USAGE_SIG)
	    current&=~PUBKEY_USAGE_SIG;
	  else
	    current|=PUBKEY_USAGE_SIG;
	}
      else if((*answer==togglers[2] || *answer==togglers[3])
	      && possible&PUBKEY_USAGE_ENC)
	{
	  if(current&PUBKEY_USAGE_ENC)
	    current&=~PUBKEY_USAGE_ENC;
	  else
	    current|=PUBKEY_USAGE_ENC;
	}
      else if((*answer==togglers[4] || *answer==togglers[5])
	      && possible&PUBKEY_USAGE_AUTH)
	{
	  if(current&PUBKEY_USAGE_AUTH)
	    current&=~PUBKEY_USAGE_AUTH;
	  else
	    current|=PUBKEY_USAGE_AUTH;
	}
      else
	tty_printf(_("Invalid selection.\n"));
    }

  xfree(answer);

  return current;
}


/* Check whether we have a key for the key with HEXGRIP.  Returns 0 if
   there is no such key or the OpenPGP algo number for the key.  */
static int
check_keygrip (ctrl_t ctrl, const char *hexgrip)
{
  gpg_error_t err;
  unsigned char *public;
  size_t publiclen;
  const char *algostr;

  if (hexgrip[0] == '&')
    hexgrip++;

  err = agent_readkey (ctrl, 0, hexgrip, &public);
  if (err)
    return 0;
  publiclen = gcry_sexp_canon_len (public, 0, NULL, NULL);

  get_pk_algo_from_canon_sexp (public, publiclen, &algostr);
  xfree (public);

  /* FIXME: Mapping of ECC algorithms is probably not correct. */
  if (!algostr)
    return 0;
  else if (!strcmp (algostr, "rsa"))
    return PUBKEY_ALGO_RSA;
  else if (!strcmp (algostr, "dsa"))
    return PUBKEY_ALGO_DSA;
  else if (!strcmp (algostr, "elg"))
    return PUBKEY_ALGO_ELGAMAL_E;
  else if (!strcmp (algostr, "ecc"))
    return PUBKEY_ALGO_ECDH;
  else if (!strcmp (algostr, "ecdsa"))
    return PUBKEY_ALGO_ECDSA;
  else if (!strcmp (algostr, "eddsa"))
    return PUBKEY_ALGO_EDDSA;
  else
    return 0;
}



/* Ask for an algorithm.  The function returns the algorithm id to
 * create. If ADDMODE is false the function won't show an option to
 * create the primary and subkey combined and won't set R_USAGE
 * either.  If a combined algorithm has been selected, the subkey
 * algorithm is stored at R_SUBKEY_ALGO.  If R_KEYGRIP is given, the
 * user has the choice to enter the keygrip of an existing key.  That
 * keygrip is then stored at this address.  The caller needs to free
 * it. */
static int
ask_algo (ctrl_t ctrl, int addmode, int *r_subkey_algo, unsigned int *r_usage,
          char **r_keygrip)
{
  char *keygrip = NULL;
  char *answer = NULL;
  int algo;
  int dummy_algo;

  if (!r_subkey_algo)
    r_subkey_algo = &dummy_algo;

  tty_printf (_("Please select what kind of key you want:\n"));

#if GPG_USE_RSA
  if (!addmode)
    tty_printf (_("   (%d) RSA and RSA (default)\n"), 1 );
#endif

  if (!addmode)
    tty_printf (_("   (%d) DSA and Elgamal\n"), 2 );

  tty_printf (_("   (%d) DSA (sign only)\n"), 3 );
#if GPG_USE_RSA
  tty_printf (_("   (%d) RSA (sign only)\n"), 4 );
#endif

  if (addmode)
    {
      tty_printf (_("   (%d) Elgamal (encrypt only)\n"), 5 );
#if GPG_USE_RSA
      tty_printf (_("   (%d) RSA (encrypt only)\n"), 6 );
#endif
    }
  if (opt.expert)
    {
      tty_printf (_("   (%d) DSA (set your own capabilities)\n"), 7 );
#if GPG_USE_RSA
      tty_printf (_("   (%d) RSA (set your own capabilities)\n"), 8 );
#endif
    }

#if GPG_USE_ECDSA || GPG_USE_ECDH || GPG_USE_EDDSA
  if (opt.expert && !addmode)
    tty_printf (_("   (%d) ECC and ECC\n"), 9 );
  if (opt.expert)
    tty_printf (_("  (%d) ECC (sign only)\n"), 10 );
  if (opt.expert)
    tty_printf (_("  (%d) ECC (set your own capabilities)\n"), 11 );
  if (opt.expert && addmode)
    tty_printf (_("  (%d) ECC (encrypt only)\n"), 12 );
#endif

  if (opt.expert && r_keygrip)
    tty_printf (_("  (%d) Existing key\n"), 13 );

  for (;;)
    {
      *r_usage = 0;
      *r_subkey_algo = 0;
      xfree (answer);
      answer = cpr_get ("keygen.algo", _("Your selection? "));
      cpr_kill_prompt ();
      algo = *answer? atoi (answer) : 1;
      if ((algo == 1 || !strcmp (answer, "rsa+rsa")) && !addmode)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_subkey_algo = PUBKEY_ALGO_RSA;
          break;
	}
      else if ((algo == 2 || !strcmp (answer, "dsa+elg")) && !addmode)
        {
          algo = PUBKEY_ALGO_DSA;
          *r_subkey_algo = PUBKEY_ALGO_ELGAMAL_E;
          break;
	}
      else if (algo == 3 || !strcmp (answer, "dsa"))
        {
          algo = PUBKEY_ALGO_DSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if (algo == 4 || !strcmp (answer, "rsa/s"))
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if ((algo == 5 || !strcmp (answer, "elg")) && addmode)
        {
          algo = PUBKEY_ALGO_ELGAMAL_E;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 6 || !strcmp (answer, "rsa/e")) && addmode)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 7 || !strcmp (answer, "dsa/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_DSA;
          *r_usage = ask_key_flags (algo, addmode);
          break;
	}
      else if ((algo == 8 || !strcmp (answer, "rsa/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_RSA;
          *r_usage = ask_key_flags (algo, addmode);
          break;
	}
      else if ((algo == 9 || !strcmp (answer, "ecc+ecc"))
               && opt.expert && !addmode)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_subkey_algo = PUBKEY_ALGO_ECDH;
          break;
	}
      else if ((algo == 10 || !strcmp (answer, "ecc/s")) && opt.expert)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_usage = PUBKEY_USAGE_SIG;
          break;
	}
      else if ((algo == 11 || !strcmp (answer, "ecc/*")) && opt.expert)
        {
          algo = PUBKEY_ALGO_ECDSA;
          *r_usage = ask_key_flags (algo, addmode);
          break;
	}
      else if ((algo == 12 || !strcmp (answer, "ecc/e"))
               && opt.expert && addmode)
        {
          algo = PUBKEY_ALGO_ECDH;
          *r_usage = PUBKEY_USAGE_ENC;
          break;
	}
      else if ((algo == 13 || !strcmp (answer, "keygrip"))
               && opt.expert && r_keygrip)
        {
          for (;;)
            {
              xfree (answer);
              answer = tty_get (_("Enter the keygrip: "));
              tty_kill_prompt ();
              trim_spaces (answer);
              if (!*answer)
                {
                  xfree (answer);
                  answer = NULL;
                  continue;
                }

              if (strlen (answer) != 40 &&
                       !(answer[0] == '&' && strlen (answer+1) == 40))
                tty_printf
                  (_("Not a valid keygrip (expecting 40 hex digits)\n"));
              else if (!(algo = check_keygrip (ctrl, answer)) )
                tty_printf (_("No key with this keygrip\n"));
              else
                break; /* Okay.  */
            }
          xfree (keygrip);
          keygrip = answer;
          answer = NULL;
          *r_usage = ask_key_flags (algo, addmode);
          break;
	}
      else
        tty_printf (_("Invalid selection.\n"));

    }

  xfree(answer);
  if (r_keygrip)
    *r_keygrip = keygrip;
  return algo;
}


/* Ask for the key size.  ALGO is the algorithm.  If PRIMARY_KEYSIZE
   is not 0, the function asks for the size of the encryption
   subkey. */
static unsigned
ask_keysize (int algo, unsigned int primary_keysize)
{
  unsigned int nbits, min, def = DEFAULT_STD_KEYSIZE, max=4096;
  int for_subkey = !!primary_keysize;
  int autocomp = 0;

  if(opt.expert)
    min=512;
  else
    min=1024;

  if (primary_keysize && !opt.expert)
    {
      /* Deduce the subkey size from the primary key size.  */
      if (algo == PUBKEY_ALGO_DSA && primary_keysize > 3072)
        nbits = 3072; /* For performance reasons we don't support more
                         than 3072 bit DSA.  However we won't see this
                         case anyway because DSA can't be used as an
                         encryption subkey ;-). */
      else
        nbits = primary_keysize;
      autocomp = 1;
      goto leave;
    }

  switch(algo)
    {
    case PUBKEY_ALGO_DSA:
      def=2048;
      max=3072;
      break;

    case PUBKEY_ALGO_ECDSA:
    case PUBKEY_ALGO_ECDH:
      min=256;
      def=256;
      max=521;
      break;

    case PUBKEY_ALGO_EDDSA:
      min=255;
      def=255;
      max=441;
      break;

    case PUBKEY_ALGO_RSA:
      min=1024;
      break;
    }

  tty_printf(_("%s keys may be between %u and %u bits long.\n"),
	     openpgp_pk_algo_name (algo), min, max);

  for (;;)
    {
      char *prompt, *answer;

      if (for_subkey)
        prompt = xasprintf (_("What keysize do you want "
                              "for the subkey? (%u) "), def);
      else
        prompt = xasprintf (_("What keysize do you want? (%u) "), def);
      answer = cpr_get ("keygen.size", prompt);
      cpr_kill_prompt ();
      nbits = *answer? atoi (answer): def;
      xfree(prompt);
      xfree(answer);

      if(nbits<min || nbits>max)
	tty_printf(_("%s keysizes must be in the range %u-%u\n"),
		   openpgp_pk_algo_name (algo), min, max);
      else
	break;
    }

  tty_printf (_("Requested keysize is %u bits\n"), nbits);

 leave:
  if (algo == PUBKEY_ALGO_DSA && (nbits % 64))
    {
      nbits = ((nbits + 63) / 64) * 64;
      if (!autocomp)
        tty_printf (_("rounded up to %u bits\n"), nbits);
    }
  else if (algo == PUBKEY_ALGO_EDDSA)
    {
      if (nbits != 255 && nbits != 441)
        {
          if (nbits < 256)
            nbits = 255;
          else
            nbits = 441;
          if (!autocomp)
            tty_printf (_("rounded to %u bits\n"), nbits);
        }
    }
  else if (algo == PUBKEY_ALGO_ECDH || algo == PUBKEY_ALGO_ECDSA)
    {
      if (nbits != 256 && nbits != 384 && nbits != 521)
        {
          if (nbits < 256)
            nbits = 256;
          else if (nbits < 384)
            nbits = 384;
          else
            nbits = 521;
          if (!autocomp)
            tty_printf (_("rounded to %u bits\n"), nbits);
        }
    }
  else if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      if (!autocomp)
        tty_printf (_("rounded up to %u bits\n"), nbits );
    }

  return nbits;
}


/* Ask for the curve.  ALGO is the selected algorithm which this
   function may adjust.  Returns a malloced string with the name of
   the curve.  BOTH tells that gpg creates a primary and subkey. */
static char *
ask_curve (int *algo, int both)
{
  struct {
    const char *name;
    int available;
    int expert_only;
    int fix_curve;
    const char *pretty_name;
  } curves[] = {
#if GPG_USE_EDDSA
    { "Curve25519",      0, 0, 1, "Curve 25519" },
#endif
#if GPG_USE_ECDSA || GPG_USE_ECDH
    { "NIST P-256",      0, 1, 0, },
    { "NIST P-384",      0, 0, 0, },
    { "NIST P-521",      0, 1, 0, },
    { "brainpoolP256r1", 0, 1, 0, "Brainpool P-256" },
    { "brainpoolP384r1", 0, 1, 0, "Brainpool P-384" },
    { "brainpoolP512r1", 0, 1, 0, "Brainpool P-512" },
    { "secp256k1",       0, 1, 0  },
#endif
  };
  int idx;
  char *answer;
  char *result = NULL;
  gcry_sexp_t keyparms;

  tty_printf (_("Please select which elliptic curve you want:\n"));

 again:
  keyparms = NULL;
  for (idx=0; idx < DIM(curves); idx++)
    {
      int rc;

      curves[idx].available = 0;
      if (!opt.expert && curves[idx].expert_only)
        continue;

      /* FIXME: The strcmp below is a temporary hack during
         development.  It shall be removed as soon as we have proper
         Curve25519 support in Libgcrypt.  */
      gcry_sexp_release (keyparms);
      rc = gcry_sexp_build (&keyparms, NULL,
                            "(public-key(ecc(curve %s)))",
                            (!strcmp (curves[idx].name, "Curve25519")
                             ? "Ed25519" : curves[idx].name));
      if (rc)
        continue;
      if (!gcry_pk_get_curve (keyparms, 0, NULL))
        continue;
      if (both && curves[idx].fix_curve)
        {
          /* Both Curve 25519 keys are to be created.  Check that
             Libgcrypt also supports the real Curve25519.  */
          gcry_sexp_release (keyparms);
          rc = gcry_sexp_build (&keyparms, NULL,
                                "(public-key(ecc(curve %s)))",
                                 curves[idx].name);
          if (rc)
            continue;
          if (!gcry_pk_get_curve (keyparms, 0, NULL))
            continue;
        }

      curves[idx].available = 1;
      tty_printf ("   (%d) %s\n", idx + 1,
                  curves[idx].pretty_name?
                  curves[idx].pretty_name:curves[idx].name);
    }
  gcry_sexp_release (keyparms);


  for (;;)
    {
      answer = cpr_get ("keygen.curve", _("Your selection? "));
      cpr_kill_prompt ();
      idx = *answer? atoi (answer) : 1;
      if (*answer && !idx)
        {
          /* See whether the user entered the name of the curve.  */
          for (idx=0; idx < DIM(curves); idx++)
            {
              if (!opt.expert && curves[idx].expert_only)
                continue;
              if (!stricmp (curves[idx].name, answer)
                  || (curves[idx].pretty_name
                      && !stricmp (curves[idx].pretty_name, answer)))
                break;
            }
          if (idx == DIM(curves))
            idx = -1;
        }
      else
        idx--;
      xfree(answer);
      answer = NULL;
      if (idx < 0 || idx >= DIM (curves) || !curves[idx].available)
        tty_printf (_("Invalid selection.\n"));
      else
        {
          if (curves[idx].fix_curve)
            {
              log_info ("WARNING: Curve25519 is not yet part of the"
                        " OpenPGP standard.\n");

              if (!cpr_get_answer_is_yes("experimental_curve.override",
                                         "Use this curve anyway? (y/N) ")  )
                goto again;
            }

          /* If the user selected a signing algorithm and Curve25519
             we need to update the algo and and the curve name.  */
          if ((*algo == PUBKEY_ALGO_ECDSA || *algo == PUBKEY_ALGO_EDDSA)
              && curves[idx].fix_curve)
            {
              *algo = PUBKEY_ALGO_EDDSA;
              result = xstrdup ("Ed25519");
            }
          else
            result = xstrdup (curves[idx].name);
          break;
        }
    }

  if (!result)
    result = xstrdup (curves[0].name);

  return result;
}


/****************
 * Parse an expire string and return its value in seconds.
 * Returns (u32)-1 on error.
 * This isn't perfect since scan_isodatestr returns unix time, and
 * OpenPGP actually allows a 32-bit time *plus* a 32-bit offset.
 * Because of this, we only permit setting expirations up to 2106, but
 * OpenPGP could theoretically allow up to 2242.  I think we'll all
 * just cope for the next few years until we get a 64-bit time_t or
 * similar.
 */
u32
parse_expire_string( const char *string )
{
  int mult;
  u32 seconds;
  u32 abs_date = 0;
  u32 curtime = make_timestamp ();
  time_t tt;

  if (!*string)
    seconds = 0;
  else if (!strncmp (string, "seconds=", 8))
    seconds = atoi (string+8);
  else if ((abs_date = scan_isodatestr(string))
           && (abs_date+86400/2) > curtime)
    seconds = (abs_date+86400/2) - curtime;
  else if ((tt = isotime2epoch (string)) != (time_t)(-1))
    seconds = (u32)tt - curtime;
  else if ((mult = check_valid_days (string)))
    seconds = atoi (string) * 86400L * mult;
  else
    seconds = (u32)(-1);

  return seconds;
}

/* Parsean Creation-Date string which is either "1986-04-26" or
   "19860426T042640".  Returns 0 on error. */
static u32
parse_creation_string (const char *string)
{
  u32 seconds;

  if (!*string)
    seconds = 0;
  else if ( !strncmp (string, "seconds=", 8) )
    seconds = atoi (string+8);
  else if ( !(seconds = scan_isodatestr (string)))
    {
      time_t tmp = isotime2epoch (string);
      seconds = (tmp == (time_t)(-1))? 0 : tmp;
    }
  return seconds;
}


/* object == 0 for a key, and 1 for a sig */
u32
ask_expire_interval(int object,const char *def_expire)
{
    u32 interval;
    char *answer;

    switch(object)
      {
      case 0:
	if(def_expire)
	  BUG();
	tty_printf(_("Please specify how long the key should be valid.\n"
		     "         0 = key does not expire\n"
		     "      <n>  = key expires in n days\n"
		     "      <n>w = key expires in n weeks\n"
		     "      <n>m = key expires in n months\n"
		     "      <n>y = key expires in n years\n"));
	break;

      case 1:
	if(!def_expire)
	  BUG();
	tty_printf(_("Please specify how long the signature should be valid.\n"
		     "         0 = signature does not expire\n"
		     "      <n>  = signature expires in n days\n"
		     "      <n>w = signature expires in n weeks\n"
		     "      <n>m = signature expires in n months\n"
		     "      <n>y = signature expires in n years\n"));
	break;

      default:
	BUG();
      }

    /* Note: The elgamal subkey for DSA has no expiration date because
     * it must be signed with the DSA key and this one has the expiration
     * date */

    answer = NULL;
    for(;;)
      {
	u32 curtime;

	xfree(answer);
	if(object==0)
	  answer = cpr_get("keygen.valid",_("Key is valid for? (0) "));
	else
	  {
	    char *prompt;

#define PROMPTSTRING _("Signature is valid for? (%s) ")
	    /* This will actually end up larger than necessary because
	       of the 2 bytes for '%s' */
	    prompt=xmalloc(strlen(PROMPTSTRING)+strlen(def_expire)+1);
	    sprintf(prompt,PROMPTSTRING,def_expire);
#undef PROMPTSTRING

	    answer = cpr_get("siggen.valid",prompt);
	    xfree(prompt);

	    if(*answer=='\0')
	      answer=xstrdup(def_expire);
	  }
	cpr_kill_prompt();
	trim_spaces(answer);
        curtime = make_timestamp ();
	interval = parse_expire_string( answer );
	if( interval == (u32)-1 )
	  {
	    tty_printf(_("invalid value\n"));
	    continue;
	  }

	if( !interval )
	  {
            tty_printf((object==0)
                       ? _("Key does not expire at all\n")
                       : _("Signature does not expire at all\n"));
	  }
	else
	  {
	    tty_printf(object==0
		       ? _("Key expires at %s\n")
		       : _("Signature expires at %s\n"),
		       asctimestamp((ulong)(curtime + interval) ) );
#if SIZEOF_TIME_T <= 4 && !defined (HAVE_UNSIGNED_TIME_T)
	    if ( (time_t)((ulong)(curtime+interval)) < 0 )
	      tty_printf (_("Your system can't display dates beyond 2038.\n"
                            "However, it will be correctly handled up to"
                            " 2106.\n"));
            else
#endif /*SIZEOF_TIME_T*/
              if ( (time_t)((unsigned long)(curtime+interval)) < curtime )
                {
                  tty_printf (_("invalid value\n"));
                  continue;
                }
	  }

	if( cpr_enabled() || cpr_get_answer_is_yes("keygen.valid.okay",
						   _("Is this correct? (y/N) ")) )
	  break;
      }

    xfree(answer);
    return interval;
}

u32
ask_expiredate()
{
    u32 x = ask_expire_interval(0,NULL);
    return x? make_timestamp() + x : 0;
}



static PKT_user_id *
uid_from_string (const char *string)
{
  size_t n;
  PKT_user_id *uid;

  n = strlen (string);
  uid = xmalloc_clear (sizeof *uid + n);
  uid->len = n;
  strcpy (uid->name, string);
  uid->ref = 1;
  return uid;
}


/* Return true if the user id UID already exists in the keyblock.  */
static int
uid_already_in_keyblock (kbnode_t keyblock, const char *uid)
{
  PKT_user_id *uidpkt = uid_from_string (uid);
  kbnode_t node;
  int result = 0;

  for (node=keyblock; node && !result; node=node->next)
    if (!is_deleted_kbnode (node)
        && node->pkt->pkttype == PKT_USER_ID
        && !cmp_user_ids (uidpkt, node->pkt->pkt.user_id))
      result = 1;
  free_user_id (uidpkt);
  return result;
}


/* Ask for a user ID.  With a MODE of 1 an extra help prompt is
   printed for use during a new key creation.  If KEYBLOCK is not NULL
   the function prevents the creation of an already existing user
   ID.  IF FULL is not set some prompts are not shown.  */
static char *
ask_user_id (int mode, int full, KBNODE keyblock)
{
    char *answer;
    char *aname, *acomment, *amail, *uid;

    if ( !mode )
      {
        /* TRANSLATORS: This is the new string telling the user what
           gpg is now going to do (i.e. ask for the parts of the user
           ID).  Note that if you do not translate this string, a
           different string will be used, which might still have
           a correct translation.  */
	const char *s1 =
          N_("\n"
             "GnuPG needs to construct a user ID to identify your key.\n"
             "\n");
        const char *s2 = _(s1);

        if (!strcmp (s1, s2))
          {
            /* There is no translation for the string thus we to use
               the old info text.  gettext has no way to tell whether
               a translation is actually available, thus we need to
               to compare again. */
            /* TRANSLATORS: This string is in general not anymore used
               but you should keep your existing translation.  In case
               the new string is not translated this old string will
               be used. */
            const char *s3 = N_("\n"
"You need a user ID to identify your key; "
                                        "the software constructs the user ID\n"
"from the Real Name, Comment and Email Address in this form:\n"
"    \"Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>\"\n\n");
            const char *s4 = _(s3);
            if (strcmp (s3, s4))
              s2 = s3; /* A translation exists - use it. */
          }
        tty_printf ("%s", s2) ;
      }
    uid = aname = acomment = amail = NULL;
    for(;;) {
	char *p;
	int fail=0;

	if( !aname ) {
	    for(;;) {
		xfree(aname);
		aname = cpr_get("keygen.name",_("Real name: "));
		trim_spaces(aname);
		cpr_kill_prompt();

		if( opt.allow_freeform_uid )
		    break;

		if( strpbrk( aname, "<>" ) )
		    tty_printf(_("Invalid character in name\n"));
		else if( digitp(aname) )
		    tty_printf(_("Name may not start with a digit\n"));
		else if( strlen(aname) < 5 )
		    tty_printf(_("Name must be at least 5 characters long\n"));
		else
		    break;
	    }
	}
	if( !amail ) {
	    for(;;) {
		xfree(amail);
		amail = cpr_get("keygen.email",_("Email address: "));
		trim_spaces(amail);
		cpr_kill_prompt();
		if( !*amail || opt.allow_freeform_uid )
		    break;   /* no email address is okay */
		else if ( !is_valid_mailbox (amail) )
                    tty_printf(_("Not a valid email address\n"));
		else
		    break;
	    }
	}
	if (!acomment) {
          if (full) {
	    for(;;) {
		xfree(acomment);
		acomment = cpr_get("keygen.comment",_("Comment: "));
		trim_spaces(acomment);
		cpr_kill_prompt();
		if( !*acomment )
		    break;   /* no comment is okay */
		else if( strpbrk( acomment, "()" ) )
		    tty_printf(_("Invalid character in comment\n"));
		else
		    break;
	    }
          }
          else {
            xfree (acomment);
            acomment = xstrdup ("");
          }
	}


	xfree(uid);
	uid = p = xmalloc(strlen(aname)+strlen(amail)+strlen(acomment)+12+10);
	p = stpcpy(p, aname );
	if( *acomment )
	    p = stpcpy(stpcpy(stpcpy(p," ("), acomment),")");
	if( *amail )
	    p = stpcpy(stpcpy(stpcpy(p," <"), amail),">");

	/* Append a warning if the RNG is switched into fake mode.  */
        if ( random_is_faked ()  )
          strcpy(p, " (insecure!)" );

	/* print a note in case that UTF8 mapping has to be done */
	for(p=uid; *p; p++ ) {
	    if( *p & 0x80 ) {
		tty_printf(_("You are using the '%s' character set.\n"),
			   get_native_charset() );
		break;
	    }
	}

	tty_printf(_("You selected this USER-ID:\n    \"%s\"\n\n"), uid);

	if( !*amail && !opt.allow_freeform_uid
	    && (strchr( aname, '@' ) || strchr( acomment, '@'))) {
	    fail = 1;
            tty_printf(_("Please don't put the email address "
                         "into the real name or the comment\n") );
	}

        if (!fail && keyblock)
          {
            if (uid_already_in_keyblock (keyblock, uid))
              {
                tty_printf (_("Such a user ID already exists on this key!\n"));
                fail = 1;
              }
          }

	for(;;) {
            /* TRANSLATORS: These are the allowed answers in
               lower and uppercase.  Below you will find the matching
               string which should be translated accordingly and the
               letter changed to match the one in the answer string.

                 n = Change name
                 c = Change comment
                 e = Change email
                 o = Okay (ready, continue)
                 q = Quit
             */
	    const char *ansstr = _("NnCcEeOoQq");

	    if( strlen(ansstr) != 10 )
		BUG();
	    if( cpr_enabled() ) {
                answer = xstrdup (ansstr + (fail?8:6));
		answer[1] = 0;
	    }
            else if (full) {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (C)omment, (E)mail or (Q)uit? ") :
		  _("Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? "));
		cpr_kill_prompt();
            }
            else {
		answer = cpr_get("keygen.userid.cmd", fail?
		  _("Change (N)ame, (E)mail, or (Q)uit? ") :
		  _("Change (N)ame, (E)mail, or (O)kay/(Q)uit? "));
		cpr_kill_prompt();
	    }
	    if( strlen(answer) > 1 )
		;
	    else if( *answer == ansstr[0] || *answer == ansstr[1] ) {
		xfree(aname); aname = NULL;
		break;
	    }
	    else if( *answer == ansstr[2] || *answer == ansstr[3] ) {
		xfree(acomment); acomment = NULL;
		break;
	    }
	    else if( *answer == ansstr[4] || *answer == ansstr[5] ) {
		xfree(amail); amail = NULL;
		break;
	    }
	    else if( *answer == ansstr[6] || *answer == ansstr[7] ) {
		if( fail ) {
		    tty_printf(_("Please correct the error first\n"));
		}
		else {
		    xfree(aname); aname = NULL;
		    xfree(acomment); acomment = NULL;
		    xfree(amail); amail = NULL;
		    break;
		}
	    }
	    else if( *answer == ansstr[8] || *answer == ansstr[9] ) {
		xfree(aname); aname = NULL;
		xfree(acomment); acomment = NULL;
		xfree(amail); amail = NULL;
		xfree(uid); uid = NULL;
		break;
	    }
	    xfree(answer);
	}
	xfree(answer);
	if (!amail && !acomment)
	    break;
	xfree(uid); uid = NULL;
    }
    if( uid ) {
	char *p = native_to_utf8( uid );
	xfree( uid );
	uid = p;
    }
    return uid;
}


/*  MODE  0 - standard
          1 - Ask for passphrase of the card backup key.  */
#if 0
static DEK *
do_ask_passphrase (STRING2KEY **ret_s2k, int mode, int *r_canceled)
{
    DEK *dek = NULL;
    STRING2KEY *s2k;
    const char *errtext = NULL;
    const char *custdesc = NULL;

    tty_printf(_("You need a Passphrase to protect your secret key.\n\n") );

    if (mode == 1)
      custdesc = _("Please enter a passphrase to protect the off-card "
                   "backup of the new encryption key.");

    s2k = xmalloc_secure( sizeof *s2k );
    for(;;) {
	s2k->mode = opt.s2k_mode;
	s2k->hash_algo = S2K_DIGEST_ALGO;
	dek = passphrase_to_dek_ext (NULL, 0, opt.s2k_cipher_algo, s2k, 2,
                                     errtext, custdesc, NULL, r_canceled);
        if (!dek && *r_canceled) {
	    xfree(dek); dek = NULL;
	    xfree(s2k); s2k = NULL;
            break;
        }
	else if( !dek ) {
	    errtext = N_("passphrase not correctly repeated; try again");
	    tty_printf(_("%s.\n"), _(errtext));
	}
	else if( !dek->keylen ) {
	    xfree(dek); dek = NULL;
	    xfree(s2k); s2k = NULL;
	    tty_printf(_(
	    "You don't want a passphrase - this is probably a *bad* idea!\n"
	    "I will do it anyway.  You can change your passphrase at any time,\n"
	    "using this program with the option \"--edit-key\".\n\n"));
	    break;
	}
	else
	    break; /* okay */
    }
    *ret_s2k = s2k;
    return dek;
}
#endif /* 0 */


/* Basic key generation.  Here we divert to the actual generation
   routines based on the requested algorithm.  */
static int
do_create (int algo, unsigned int nbits, const char *curve, KBNODE pub_root,
           u32 timestamp, u32 expiredate, int is_subkey,
           int keygen_flags, const char *passphrase, char **cache_nonce_addr)
{
  gpg_error_t err;

  /* Fixme: The entropy collecting message should be moved to a
     libgcrypt progress handler.  */
  if (!opt.batch)
    tty_printf (_(
"We need to generate a lot of random bytes. It is a good idea to perform\n"
"some other action (type on the keyboard, move the mouse, utilize the\n"
"disks) during the prime generation; this gives the random number\n"
"generator a better chance to gain enough entropy.\n") );

  if (algo == PUBKEY_ALGO_ELGAMAL_E)
    err = gen_elg (algo, nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase, cache_nonce_addr);
  else if (algo == PUBKEY_ALGO_DSA)
    err = gen_dsa (nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase, cache_nonce_addr);
  else if (algo == PUBKEY_ALGO_ECDSA
           || algo == PUBKEY_ALGO_EDDSA
           || algo == PUBKEY_ALGO_ECDH)
    err = gen_ecc (algo, curve, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase, cache_nonce_addr);
  else if (algo == PUBKEY_ALGO_RSA)
    err = gen_rsa (algo, nbits, pub_root, timestamp, expiredate, is_subkey,
                   keygen_flags, passphrase, cache_nonce_addr);
  else
    BUG();

  return err;
}


/* Generate a new user id packet or return NULL if canceled.  If
   KEYBLOCK is not NULL the function prevents the creation of an
   already existing user ID.  If UIDSTR is not NULL the user is not
   asked but UIDSTR is used to create the user id packet; if the user
   id already exists NULL is returned.  UIDSTR is expected to be utf-8
   encoded and should have already been checked for a valid length
   etc.  */
PKT_user_id *
generate_user_id (KBNODE keyblock, const char *uidstr)
{
  PKT_user_id *uid;
  char *p;

  if (uidstr)
    {
      if (uid_already_in_keyblock (keyblock, uidstr))
        return NULL;  /* Already exists.  */
      uid = uid_from_string (uidstr);
    }
  else
    {
      p = ask_user_id (1, 1, keyblock);
      if (!p)
        return NULL;  /* Canceled. */
      uid = uid_from_string (p);
      xfree (p);
    }
  return uid;
}


/* Append R to the linked list PARA.  */
static void
append_to_parameter (struct para_data_s *para, struct para_data_s *r)
{
  assert (para);
  while (para->next)
    para = para->next;
  para->next = r;
}

/* Release the parameter list R.  */
static void
release_parameter_list (struct para_data_s *r)
{
  struct para_data_s *r2;

  for (; r ; r = r2)
    {
      r2 = r->next;
      if (r->key == pPASSPHRASE && *r->u.value)
        wipememory (r->u.value, strlen (r->u.value));
      xfree (r);
    }
}

static struct para_data_s *
get_parameter( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r;

    for( r = para; r && r->key != key; r = r->next )
	;
    return r;
}

static const char *
get_parameter_value( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return (r && *r->u.value)? r->u.value : NULL;
}


/* This is similar to get_parameter_value but also returns the empty
   string.  This is required so that quick_generate_keypair can use an
   empty Passphrase to specify no-protection.  */
static const char *
get_parameter_passphrase (struct para_data_s *para)
{
  struct para_data_s *r = get_parameter (para, pPASSPHRASE);
  return r ? r->u.value : NULL;
}


static int
get_parameter_algo( struct para_data_s *para, enum para_name key,
                    int *r_default)
{
  int i;
  struct para_data_s *r = get_parameter( para, key );

  if (r_default)
    *r_default = 0;

  if (!r)
    return -1;

  /* Note that we need to handle the ECC algorithms specified as
     strings directly because Libgcrypt folds them all to ECC.  */
  if (!ascii_strcasecmp (r->u.value, "default"))
    {
      /* Note: If you change this default algo, remember to change it
         also in gpg.c:gpgconf_list.  */
      i = DEFAULT_STD_ALGO;
      if (r_default)
        *r_default = 1;
    }
  else if (digitp (r->u.value))
    i = atoi( r->u.value );
  else if (!strcmp (r->u.value, "ELG-E")
           || !strcmp (r->u.value, "ELG"))
    i = PUBKEY_ALGO_ELGAMAL_E;
  else if (!ascii_strcasecmp (r->u.value, "EdDSA"))
    i = PUBKEY_ALGO_EDDSA;
  else if (!ascii_strcasecmp (r->u.value, "ECDSA"))
    i = PUBKEY_ALGO_ECDSA;
  else if (!ascii_strcasecmp (r->u.value, "ECDH"))
    i = PUBKEY_ALGO_ECDH;
  else
    i = map_pk_gcry_to_openpgp (gcry_pk_map_name (r->u.value));

  if (i == PUBKEY_ALGO_RSA_E || i == PUBKEY_ALGO_RSA_S)
    i = 0; /* we don't want to allow generation of these algorithms */
  return i;
}

/*
 * Parse the usage parameter and set the keyflags.  Returns -1 on
 * error, 0 for no usage given or 1 for usage available.
 */
static int
parse_parameter_usage (const char *fname,
                       struct para_data_s *para, enum para_name key)
{
    struct para_data_s *r = get_parameter( para, key );
    char *p, *pn;
    unsigned int use;

    if( !r )
	return 0; /* none (this is an optional parameter)*/

    use = 0;
    pn = r->u.value;
    while ( (p = strsep (&pn, " \t,")) ) {
        if ( !*p)
            ;
        else if ( !ascii_strcasecmp (p, "sign") )
            use |= PUBKEY_USAGE_SIG;
        else if ( !ascii_strcasecmp (p, "encrypt") )
            use |= PUBKEY_USAGE_ENC;
        else if ( !ascii_strcasecmp (p, "auth") )
            use |= PUBKEY_USAGE_AUTH;
        else {
            log_error("%s:%d: invalid usage list\n", fname, r->lnr );
            return -1; /* error */
        }
    }
    r->u.usage = use;
    return 1;
}

static int
parse_revocation_key (const char *fname,
		      struct para_data_s *para, enum para_name key)
{
  struct para_data_s *r = get_parameter( para, key );
  struct revocation_key revkey;
  char *pn;
  int i;

  if( !r )
    return 0; /* none (this is an optional parameter) */

  pn = r->u.value;

  revkey.class=0x80;
  revkey.algid=atoi(pn);
  if(!revkey.algid)
    goto fail;

  /* Skip to the fpr */
  while(*pn && *pn!=':')
    pn++;

  if(*pn!=':')
    goto fail;

  pn++;

  for(i=0;i<MAX_FINGERPRINT_LEN && *pn;i++,pn+=2)
    {
      int c=hextobyte(pn);
      if(c==-1)
	goto fail;

      revkey.fpr[i]=c;
    }

  /* skip to the tag */
  while(*pn && *pn!='s' && *pn!='S')
    pn++;

  if(ascii_strcasecmp(pn,"sensitive")==0)
    revkey.class|=0x40;

  memcpy(&r->u.revkey,&revkey,sizeof(struct revocation_key));

  return 0;

  fail:
  log_error("%s:%d: invalid revocation key\n", fname, r->lnr );
  return -1; /* error */
}


static u32
get_parameter_u32( struct para_data_s *para, enum para_name key )
{
  struct para_data_s *r = get_parameter( para, key );

  if( !r )
    return 0;
  if( r->key == pKEYCREATIONDATE )
    return r->u.creation;
  if( r->key == pKEYEXPIRE || r->key == pSUBKEYEXPIRE )
    return r->u.expire;
  if( r->key == pKEYUSAGE || r->key == pSUBKEYUSAGE )
    return r->u.usage;

  return (unsigned int)strtoul( r->u.value, NULL, 10 );
}

static unsigned int
get_parameter_uint( struct para_data_s *para, enum para_name key )
{
    return get_parameter_u32( para, key );
}

static struct revocation_key *
get_parameter_revkey( struct para_data_s *para, enum para_name key )
{
    struct para_data_s *r = get_parameter( para, key );
    return r? &r->u.revkey : NULL;
}

static int
proc_parameter_file( struct para_data_s *para, const char *fname,
                     struct output_control_s *outctrl, int card )
{
  struct para_data_s *r;
  const char *s1, *s2, *s3;
  size_t n;
  char *p;
  int is_default = 0;
  int have_user_id = 0;
  int err, algo;

  /* Check that we have all required parameters. */
  r = get_parameter( para, pKEYTYPE );
  if(r)
    {
      algo = get_parameter_algo (para, pKEYTYPE, &is_default);
      if (openpgp_pk_test_algo2 (algo, PUBKEY_USAGE_SIG))
	{
	  log_error ("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}
    }
  else
    {
      log_error ("%s: no Key-Type specified\n",fname);
      return -1;
    }

  err = parse_parameter_usage (fname, para, pKEYUSAGE);
  if (!err)
    {
      /* Default to algo capabilities if key-usage is not provided and
         no default algorithm has been requested.  */
      r = xmalloc_clear(sizeof(*r));
      r->key = pKEYUSAGE;
      r->u.usage = (is_default
                    ? (PUBKEY_USAGE_CERT | PUBKEY_USAGE_SIG)
                    : openpgp_pk_algo_usage(algo));
      append_to_parameter (para, r);
    }
  else if (err == -1)
    return -1;
  else
    {
      r = get_parameter (para, pKEYUSAGE);
      if (r && (r->u.usage & ~openpgp_pk_algo_usage (algo)))
        {
          log_error ("%s:%d: specified Key-Usage not allowed for algo %d\n",
                     fname, r->lnr, algo);
          return -1;
        }
    }

  is_default = 0;
  r = get_parameter( para, pSUBKEYTYPE );
  if(r)
    {
      algo = get_parameter_algo (para, pSUBKEYTYPE, &is_default);
      if (openpgp_pk_test_algo (algo))
	{
	  log_error ("%s:%d: invalid algorithm\n", fname, r->lnr );
	  return -1;
	}

      err = parse_parameter_usage (fname, para, pSUBKEYUSAGE);
      if (!err)
	{
	  /* Default to algo capabilities if subkey-usage is not
	     provided */
	  r = xmalloc_clear (sizeof(*r));
	  r->key = pSUBKEYUSAGE;
	  r->u.usage = (is_default
                        ? PUBKEY_USAGE_ENC
                        : openpgp_pk_algo_usage (algo));
          append_to_parameter (para, r);
	}
      else if (err == -1)
	return -1;
      else
        {
          r = get_parameter (para, pSUBKEYUSAGE);
          if (r && (r->u.usage & ~openpgp_pk_algo_usage (algo)))
            {
              log_error ("%s:%d: specified Subkey-Usage not allowed"
                         " for algo %d\n", fname, r->lnr, algo);
              return -1;
            }
        }
    }


  if( get_parameter_value( para, pUSERID ) )
    have_user_id=1;
  else
    {
      /* create the formatted user ID */
      s1 = get_parameter_value( para, pNAMEREAL );
      s2 = get_parameter_value( para, pNAMECOMMENT );
      s3 = get_parameter_value( para, pNAMEEMAIL );
      if( s1 || s2 || s3 )
	{
	  n = (s1?strlen(s1):0) + (s2?strlen(s2):0) + (s3?strlen(s3):0);
	  r = xmalloc_clear( sizeof *r + n + 20 );
	  r->key = pUSERID;
	  p = r->u.value;
	  if( s1 )
	    p = stpcpy(p, s1 );
	  if( s2 )
	    p = stpcpy(stpcpy(stpcpy(p," ("), s2 ),")");
	  if( s3 )
	    p = stpcpy(stpcpy(stpcpy(p," <"), s3 ),">");
          append_to_parameter (para, r);
	  have_user_id=1;
	}
    }

  if(!have_user_id)
    {
      log_error("%s: no User-ID specified\n",fname);
      return -1;
    }

  /* Set preferences, if any. */
  keygen_set_std_prefs(get_parameter_value( para, pPREFERENCES ), 0);

  /* Set keyserver, if any. */
  s1=get_parameter_value( para, pKEYSERVER );
  if(s1)
    {
      struct keyserver_spec *spec;

      spec = parse_keyserver_uri (s1, 1);
      if(spec)
	{
	  free_keyserver_spec(spec);
	  opt.def_keyserver_url=s1;
	}
      else
	{
	  log_error("%s:%d: invalid keyserver url\n", fname, r->lnr );
	  return -1;
	}
    }

  /* Set revoker, if any. */
  if (parse_revocation_key (fname, para, pREVOKER))
    return -1;


  /* Make KEYCREATIONDATE from Creation-Date.  */
  r = get_parameter (para, pCREATIONDATE);
  if (r && *r->u.value)
    {
      u32 seconds;

      seconds = parse_creation_string (r->u.value);
      if (!seconds)
	{
	  log_error ("%s:%d: invalid creation date\n", fname, r->lnr );
	  return -1;
	}
      r->u.creation = seconds;
      r->key = pKEYCREATIONDATE;  /* Change that entry. */
    }

  /* Make KEYEXPIRE from Expire-Date.  */
  r = get_parameter( para, pEXPIREDATE );
  if( r && *r->u.value )
    {
      u32 seconds;

      seconds = parse_expire_string( r->u.value );
      if( seconds == (u32)-1 )
	{
	  log_error("%s:%d: invalid expire date\n", fname, r->lnr );
	  return -1;
	}
      r->u.expire = seconds;
      r->key = pKEYEXPIRE;  /* change hat entry */
      /* also set it for the subkey */
      r = xmalloc_clear( sizeof *r + 20 );
      r->key = pSUBKEYEXPIRE;
      r->u.expire = seconds;
      append_to_parameter (para, r);
    }

  do_generate_keypair( para, outctrl, card );
  return 0;
}


/****************
 * Kludge to allow non interactive key generation controlled
 * by a parameter file.
 * Note, that string parameters are expected to be in UTF-8
 */
static void
read_parameter_file( const char *fname )
{
    static struct { const char *name;
		    enum para_name key;
    } keywords[] = {
	{ "Key-Type",       pKEYTYPE},
	{ "Key-Length",     pKEYLENGTH },
	{ "Key-Curve",      pKEYCURVE },
	{ "Key-Usage",      pKEYUSAGE },
	{ "Subkey-Type",    pSUBKEYTYPE },
	{ "Subkey-Length",  pSUBKEYLENGTH },
	{ "Subkey-Curve",   pSUBKEYCURVE },
	{ "Subkey-Usage",   pSUBKEYUSAGE },
	{ "Name-Real",      pNAMEREAL },
	{ "Name-Email",     pNAMEEMAIL },
	{ "Name-Comment",   pNAMECOMMENT },
	{ "Expire-Date",    pEXPIREDATE },
	{ "Creation-Date",  pCREATIONDATE },
	{ "Passphrase",     pPASSPHRASE },
	{ "Preferences",    pPREFERENCES },
	{ "Revoker",        pREVOKER },
        { "Handle",         pHANDLE },
	{ "Keyserver",      pKEYSERVER },
	{ NULL, 0 }
    };
    IOBUF fp;
    byte *line;
    unsigned int maxlen, nline;
    char *p;
    int lnr;
    const char *err = NULL;
    struct para_data_s *para, *r;
    int i;
    struct output_control_s outctrl;

    memset( &outctrl, 0, sizeof( outctrl ) );
    outctrl.pub.afx = new_armor_context ();

    if( !fname || !*fname)
      fname = "-";

    fp = iobuf_open (fname);
    if (fp && is_secured_file (iobuf_get_fd (fp)))
      {
        iobuf_close (fp);
        fp = NULL;
        gpg_err_set_errno (EPERM);
      }
    if (!fp) {
      log_error (_("can't open '%s': %s\n"), fname, strerror(errno) );
      return;
    }
    iobuf_ioctl (fp, IOBUF_IOCTL_NO_CACHE, 1, NULL);

    lnr = 0;
    err = NULL;
    para = NULL;
    maxlen = 1024;
    line = NULL;
    while ( iobuf_read_line (fp, &line, &nline, &maxlen) ) {
	char *keyword, *value;

	lnr++;
	if( !maxlen ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*(byte*)p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	keyword = p;
	if( *keyword == '%' ) {
	    for( ; !isspace(*(byte*)p); p++ )
		;
	    if( *p )
		*p++ = 0;
	    for( ; isspace(*(byte*)p); p++ )
		;
	    value = p;
	    trim_trailing_ws( value, strlen(value) );
	    if( !ascii_strcasecmp( keyword, "%echo" ) )
		log_info("%s\n", value );
	    else if( !ascii_strcasecmp( keyword, "%dry-run" ) )
		outctrl.dryrun = 1;
	    else if( !ascii_strcasecmp( keyword, "%ask-passphrase" ) )
              ; /* Dummy for backward compatibility. */
	    else if( !ascii_strcasecmp( keyword, "%no-ask-passphrase" ) )
	      ; /* Dummy for backward compatibility. */
	    else if( !ascii_strcasecmp( keyword, "%no-protection" ) )
                outctrl.keygen_flags |= KEYGEN_FLAG_NO_PROTECTION;
	    else if( !ascii_strcasecmp( keyword, "%transient-key" ) )
                outctrl.keygen_flags |= KEYGEN_FLAG_TRANSIENT_KEY;
	    else if( !ascii_strcasecmp( keyword, "%commit" ) ) {
		outctrl.lnr = lnr;
		if (proc_parameter_file( para, fname, &outctrl, 0 ))
                  print_status_key_not_created
                    (get_parameter_value (para, pHANDLE));
		release_parameter_list( para );
		para = NULL;
	    }
	    else if( !ascii_strcasecmp( keyword, "%pubring" ) ) {
		if( outctrl.pub.fname && !strcmp( outctrl.pub.fname, value ) )
		    ; /* still the same file - ignore it */
		else {
		    xfree( outctrl.pub.newfname );
		    outctrl.pub.newfname = xstrdup( value );
		    outctrl.use_files = 1;
		}
	    }
	    else if( !ascii_strcasecmp( keyword, "%secring" ) ) {
              /* Ignore this command.  */
	    }
	    else
		log_info("skipping control '%s' (%s)\n", keyword, value );


	    continue;
	}


	if( !(p = strchr( p, ':' )) || p == keyword ) {
	    err = "missing colon";
	    break;
	}
	if( *p )
	    *p++ = 0;
	for( ; isspace(*(byte*)p); p++ )
	    ;
	if( !*p ) {
	    err = "missing argument";
	    break;
	}
	value = p;
	trim_trailing_ws( value, strlen(value) );

	for(i=0; keywords[i].name; i++ ) {
	    if( !ascii_strcasecmp( keywords[i].name, keyword ) )
		break;
	}
	if( !keywords[i].name ) {
	    err = "unknown keyword";
	    break;
	}
	if( keywords[i].key != pKEYTYPE && !para ) {
	    err = "parameter block does not start with \"Key-Type\"";
	    break;
	}

	if( keywords[i].key == pKEYTYPE && para ) {
	    outctrl.lnr = lnr;
	    if (proc_parameter_file( para, fname, &outctrl, 0 ))
              print_status_key_not_created
                (get_parameter_value (para, pHANDLE));
	    release_parameter_list( para );
	    para = NULL;
	}
	else {
	    for( r = para; r; r = r->next ) {
		if( r->key == keywords[i].key )
		    break;
	    }
	    if( r ) {
		err = "duplicate keyword";
		break;
	    }
	}
	r = xmalloc_clear( sizeof *r + strlen( value ) );
	r->lnr = lnr;
	r->key = keywords[i].key;
	strcpy( r->u.value, value );
	r->next = para;
	para = r;
    }
    if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( iobuf_error (fp) ) {
	log_error("%s:%d: read error\n", fname, lnr);
    }
    else if( para ) {
	outctrl.lnr = lnr;
	if (proc_parameter_file( para, fname, &outctrl, 0 ))
          print_status_key_not_created (get_parameter_value (para, pHANDLE));
    }

    if( outctrl.use_files ) { /* close open streams */
	iobuf_close( outctrl.pub.stream );

        /* Must invalidate that ugly cache to actually close it.  */
        if (outctrl.pub.fname)
          iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE,
                       0, (char*)outctrl.pub.fname);

	xfree( outctrl.pub.fname );
	xfree( outctrl.pub.newfname );
    }

    release_parameter_list( para );
    iobuf_close (fp);
    release_armor_context (outctrl.pub.afx);
}


/* Helper for quick_generate_keypair.  */
static struct para_data_s *
quickgen_set_para (struct para_data_s *para, int for_subkey,
                   int algo, int nbits, const char *curve)
{
  struct para_data_s *r;

  r = xmalloc_clear (sizeof *r + 20);
  r->key = for_subkey? pSUBKEYUSAGE :  pKEYUSAGE;
  strcpy (r->u.value, for_subkey ? "encrypt" : "sign");
  r->next = para;
  para = r;
  r = xmalloc_clear (sizeof *r + 20);
  r->key = for_subkey? pSUBKEYTYPE : pKEYTYPE;
  sprintf (r->u.value, "%d", algo);
  r->next = para;
  para = r;

  if (curve)
    {
      r = xmalloc_clear (sizeof *r + strlen (curve));
      r->key = for_subkey? pSUBKEYCURVE : pKEYCURVE;
      strcpy (r->u.value, curve);
      r->next = para;
      para = r;
    }
  else
    {
      r = xmalloc_clear (sizeof *r + 20);
      r->key = for_subkey? pSUBKEYLENGTH : pKEYLENGTH;
      sprintf (r->u.value, "%u", nbits);
      r->next = para;
      para = r;
    }

  return para;
}


/*
 * Unattended generation of a standard key.
 */
void
quick_generate_keypair (const char *uid)
{
  gpg_error_t err;
  struct para_data_s *para = NULL;
  struct para_data_s *r;
  struct output_control_s outctrl;
  int use_tty;

  memset (&outctrl, 0, sizeof outctrl);

  use_tty = (!opt.batch && !opt.answer_yes
             && !cpr_enabled ()
             && gnupg_isatty (fileno (stdin))
             && gnupg_isatty (fileno (stdout))
             && gnupg_isatty (fileno (stderr)));

  r = xmalloc_clear (sizeof *r + strlen (uid));
  r->key = pUSERID;
  strcpy (r->u.value, uid);
  r->next = para;
  para = r;

  uid = trim_spaces (r->u.value);
  if (!*uid || (!opt.allow_freeform_uid && !is_valid_user_id (uid)))
    {
      log_error (_("Key generation failed: %s\n"),
                 gpg_strerror (GPG_ERR_INV_USER_ID));
      goto leave;
    }

  /* If gpg is directly used on the console ask whether a key with the
     given user id shall really be created.  */
  if (use_tty)
    {
      tty_printf (_("About to create a key for:\n    \"%s\"\n\n"), uid);
      if (!cpr_get_answer_is_yes_def ("quick_keygen.okay",
                                      _("Continue? (Y/n) "), 1))
        goto leave;
    }

  /* Check whether such a user ID already exists.  */
  {
    KEYDB_HANDLE kdbhd;
    KEYDB_SEARCH_DESC desc;

    memset (&desc, 0, sizeof desc);
    desc.mode = KEYDB_SEARCH_MODE_EXACT;
    desc.u.name = uid;

    kdbhd = keydb_new ();
    err = keydb_search (kdbhd, &desc, 1, NULL);
    keydb_release (kdbhd);
    if (gpg_err_code (err) != GPG_ERR_NOT_FOUND)
      {
        log_info (_("A key for \"%s\" already exists\n"), uid);
        if (opt.answer_yes)
          ;
        else if (!use_tty
                 || !cpr_get_answer_is_yes_def ("quick_keygen.force",
                                                _("Create anyway? (y/N) "), 0))
          {
            log_inc_errorcount ();  /* we used log_info */
            goto leave;
          }
        log_info (_("creating anyway\n"));
      }
  }

  para = quickgen_set_para (para, 0,
                            DEFAULT_STD_ALGO, DEFAULT_STD_KEYSIZE,
                            DEFAULT_STD_CURVE);
  para = quickgen_set_para (para, 1,
                            DEFAULT_STD_SUBALGO, DEFAULT_STD_SUBKEYSIZE,
                            DEFAULT_STD_SUBCURVE);

  /* If the pinentry loopback mode is not and we have a static
     passphrase (i.e. set with --passphrase{,-fd,-file} while in batch
     mode), we use that passphrase for the new key.  */
  if (opt.pinentry_mode != PINENTRY_MODE_LOOPBACK
      && have_static_passphrase ())
    {
      const char *s = get_static_passphrase ();

      r = xmalloc_clear (sizeof *r + strlen (s));
      r->key = pPASSPHRASE;
      strcpy (r->u.value, s);
      r->next = para;
      para = r;
    }

  proc_parameter_file (para, "[internal]", &outctrl, 0);
 leave:
  release_parameter_list (para);
}


/*
 * Generate a keypair (fname is only used in batch mode) If
 * CARD_SERIALNO is not NULL the function will create the keys on an
 * OpenPGP Card.  If CARD_BACKUP_KEY has been set and CARD_SERIALNO is
 * NOT NULL, the encryption key for the card is generated on the host,
 * imported to the card and a backup file created by gpg-agent.  If
 * FULL is not set only the basic prompts are used (except for batch
 * mode).
 */
void
generate_keypair (ctrl_t ctrl, int full, const char *fname,
                  const char *card_serialno, int card_backup_key)
{
  unsigned int nbits;
  char *uid = NULL;
  int algo;
  unsigned int use;
  int both = 0;
  u32 expire;
  struct para_data_s *para = NULL;
  struct para_data_s *r;
  struct output_control_s outctrl;

#ifndef ENABLE_CARD_SUPPORT
  (void)card_backup_key;
#endif

  memset( &outctrl, 0, sizeof( outctrl ) );

  if (opt.batch && card_serialno)
    {
      /* We don't yet support unattended key generation. */
      log_error (_("can't do this in batch mode\n"));
      return;
    }

  if (opt.batch)
    {
      read_parameter_file( fname );
      return;
    }

  if (card_serialno)
    {
#ifdef ENABLE_CARD_SUPPORT
      r = xcalloc (1, sizeof *r + strlen (card_serialno) );
      r->key = pSERIALNO;
      strcpy( r->u.value, card_serialno);
      r->next = para;
      para = r;

      algo = PUBKEY_ALGO_RSA;

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pKEYUSAGE;
      strcpy (r->u.value, "sign");
      r->next = para;
      para = r;

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;
      r = xcalloc (1, sizeof *r + 20 );
      r->key = pSUBKEYUSAGE;
      strcpy (r->u.value, "encrypt");
      r->next = para;
      para = r;

      r = xcalloc (1, sizeof *r + 20 );
      r->key = pAUTHKEYTYPE;
      sprintf( r->u.value, "%d", algo );
      r->next = para;
      para = r;

      if (card_backup_key)
        {
          r = xcalloc (1, sizeof *r + 1);
          r->key = pCARDBACKUPKEY;
          strcpy (r->u.value, "1");
          r->next = para;
          para = r;
        }
#endif /*ENABLE_CARD_SUPPORT*/
    }
  else if (full)  /* Full featured key generation.  */
    {
      int subkey_algo;
      char *curve = NULL;

      /* Fixme: To support creating a primary key by keygrip we better
         also define the keyword for the parameter file.  Note that
         the subkey case will never be asserted if a keygrip has been
         given.  */
      algo = ask_algo (ctrl, 0, &subkey_algo, &use, NULL);
      if (subkey_algo)
        {
          /* Create primary and subkey at once.  */
          both = 1;
          if (algo == PUBKEY_ALGO_ECDSA
              || algo == PUBKEY_ALGO_EDDSA
              || algo == PUBKEY_ALGO_ECDH)
            {
              curve = ask_curve (&algo, both);
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pKEYTYPE;
              sprintf( r->u.value, "%d", algo);
              r->next = para;
              para = r;
              nbits = 0;
              r = xmalloc_clear (sizeof *r + strlen (curve));
              r->key = pKEYCURVE;
              strcpy (r->u.value, curve);
              r->next = para;
              para = r;
            }
          else
            {
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pKEYTYPE;
              sprintf( r->u.value, "%d", algo);
              r->next = para;
              para = r;
              nbits = ask_keysize (algo, 0);
              r = xmalloc_clear( sizeof *r + 20 );
              r->key = pKEYLENGTH;
              sprintf( r->u.value, "%u", nbits);
              r->next = para;
              para = r;
            }
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pKEYUSAGE;
          strcpy( r->u.value, "sign" );
          r->next = para;
          para = r;

          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pSUBKEYTYPE;
          sprintf( r->u.value, "%d", subkey_algo);
          r->next = para;
          para = r;
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pSUBKEYUSAGE;
          strcpy( r->u.value, "encrypt" );
          r->next = para;
          para = r;

          if (algo == PUBKEY_ALGO_ECDSA
              || algo == PUBKEY_ALGO_EDDSA
              || algo == PUBKEY_ALGO_ECDH)
            {
              if (algo == PUBKEY_ALGO_EDDSA
                  && subkey_algo == PUBKEY_ALGO_ECDH)
                {
                  /* Need to switch to a different curve for the
                     encryption key.  */
                  xfree (curve);
                  curve = xstrdup ("Curve25519");
                }
              r = xmalloc_clear (sizeof *r + strlen (curve));
              r->key = pSUBKEYCURVE;
              strcpy (r->u.value, curve);
              r->next = para;
              para = r;
            }
        }
      else /* Create only a single key.  */
        {
          /* For ECC we need to ask for the curve before storing the
             algo because ask_curve may change the algo.  */
          if (algo == PUBKEY_ALGO_ECDSA
              || algo == PUBKEY_ALGO_EDDSA
              || algo == PUBKEY_ALGO_ECDH)
            {
              curve = ask_curve (&algo, 0);
              nbits = 0;
              r = xmalloc_clear (sizeof *r + strlen (curve));
              r->key = pKEYCURVE;
              strcpy (r->u.value, curve);
              r->next = para;
              para = r;
            }

          r = xmalloc_clear( sizeof *r + 20 );
          r->key = pKEYTYPE;
          sprintf( r->u.value, "%d", algo );
          r->next = para;
          para = r;

          if (use)
            {
              r = xmalloc_clear( sizeof *r + 25 );
              r->key = pKEYUSAGE;
              sprintf( r->u.value, "%s%s%s",
                       (use & PUBKEY_USAGE_SIG)? "sign ":"",
                       (use & PUBKEY_USAGE_ENC)? "encrypt ":"",
                       (use & PUBKEY_USAGE_AUTH)? "auth":"" );
              r->next = para;
              para = r;
            }
          nbits = 0;
        }

      if (algo == PUBKEY_ALGO_ECDSA
          || algo == PUBKEY_ALGO_EDDSA
          || algo == PUBKEY_ALGO_ECDH)
        {
          /* The curve has already been set.  */
        }
      else
        {
          nbits = ask_keysize (both? subkey_algo : algo, nbits);
          r = xmalloc_clear( sizeof *r + 20 );
          r->key = both? pSUBKEYLENGTH : pKEYLENGTH;
          sprintf( r->u.value, "%u", nbits);
          r->next = para;
          para = r;
        }

      xfree (curve);
    }
  else /* Default key generation.  */
    {
      tty_printf ( _("Note: Use \"%s %s\""
                     " for a full featured key generation dialog.\n"),
                   NAME_OF_INSTALLED_GPG, "--full-gen-key" );
      para = quickgen_set_para (para, 0,
                                DEFAULT_STD_ALGO, DEFAULT_STD_KEYSIZE,
                                DEFAULT_STD_CURVE);
      para = quickgen_set_para (para, 1,
                                DEFAULT_STD_SUBALGO, DEFAULT_STD_SUBKEYSIZE,
                                DEFAULT_STD_SUBCURVE);
    }


  expire = full? ask_expire_interval (0, NULL) : 0;
  r = xcalloc (1, sizeof *r + 20);
  r->key = pKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;
  r = xcalloc (1, sizeof *r + 20);
  r->key = pSUBKEYEXPIRE;
  r->u.expire = expire;
  r->next = para;
  para = r;

  uid = ask_user_id (0, full, NULL);
  if (!uid)
    {
      log_error(_("Key generation canceled.\n"));
      release_parameter_list( para );
      return;
    }
  r = xcalloc (1, sizeof *r + strlen (uid));
  r->key = pUSERID;
  strcpy (r->u.value, uid);
  r->next = para;
  para = r;

  proc_parameter_file (para, "[internal]", &outctrl, !!card_serialno);
  release_parameter_list (para);
}


#if 0 /* not required */
/* Generate a raw key and return it as a secret key packet.  The
   function will ask for the passphrase and return a protected as well
   as an unprotected copy of a new secret key packet.  0 is returned
   on success and the caller must then free the returned values.  */
static int
generate_raw_key (int algo, unsigned int nbits, u32 created_at,
                  PKT_secret_key **r_sk_unprotected,
                  PKT_secret_key **r_sk_protected)
{
  int rc;
  DEK *dek = NULL;
  STRING2KEY *s2k = NULL;
  PKT_secret_key *sk = NULL;
  int i;
  size_t nskey, npkey;
  gcry_sexp_t s_parms, s_key;
  int canceled;

  npkey = pubkey_get_npkey (algo);
  nskey = pubkey_get_nskey (algo);
  assert (nskey <= PUBKEY_MAX_NSKEY && npkey < nskey);

  if (nbits < 512)
    {
      nbits = 512;
      log_info (_("keysize invalid; using %u bits\n"), nbits );
    }

  if ((nbits % 32))
    {
      nbits = ((nbits + 31) / 32) * 32;
      log_info(_("keysize rounded up to %u bits\n"), nbits );
    }

  dek = do_ask_passphrase (&s2k, 1, &canceled);
  if (canceled)
    {
      rc = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  sk = xmalloc_clear (sizeof *sk);
  sk->timestamp = created_at;
  sk->version = 4;
  sk->pubkey_algo = algo;

  if ( !is_RSA (algo) )
    {
      log_error ("only RSA is supported for offline generated keys\n");
      rc = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      goto leave;
    }
  rc = gcry_sexp_build (&s_parms, NULL,
                        "(genkey(rsa(nbits %d)))",
                        (int)nbits);
  if (rc)
    log_bug ("gcry_sexp_build failed: %s\n", gpg_strerror (rc));
  rc = gcry_pk_genkey (&s_key, s_parms);
  gcry_sexp_release (s_parms);
  if (rc)
    {
      log_error ("gcry_pk_genkey failed: %s\n", gpg_strerror (rc) );
      goto leave;
    }
  rc = key_from_sexp (sk->skey, s_key, "private-key", "nedpqu");
  gcry_sexp_release (s_key);
  if (rc)
    {
      log_error ("key_from_sexp failed: %s\n", gpg_strerror (rc) );
      goto leave;
    }

  for (i=npkey; i < nskey; i++)
    sk->csum += checksum_mpi (sk->skey[i]);

  if (r_sk_unprotected)
    *r_sk_unprotected = copy_secret_key (NULL, sk);

  rc = genhelp_protect (dek, s2k, sk);
  if (rc)
    goto leave;

  if (r_sk_protected)
    {
      *r_sk_protected = sk;
      sk = NULL;
    }

 leave:
  if (sk)
    free_secret_key (sk);
  xfree (dek);
  xfree (s2k);
  return rc;
}
#endif /* ENABLE_CARD_SUPPORT */

/* Create and delete a dummy packet to start off a list of kbnodes. */
static void
start_tree(KBNODE *tree)
{
  PACKET *pkt;

  pkt=xmalloc_clear(sizeof(*pkt));
  pkt->pkttype=PKT_NONE;
  *tree=new_kbnode(pkt);
  delete_kbnode(*tree);
}


static void
do_generate_keypair (struct para_data_s *para,
		     struct output_control_s *outctrl, int card)
{
  gpg_error_t err;
  KBNODE pub_root = NULL;
  const char *s;
  PKT_public_key *pri_psk = NULL;
  PKT_public_key *sub_psk = NULL;
  struct revocation_key *revkey;
  int did_sub = 0;
  u32 timestamp;
  char *cache_nonce = NULL;

  if (outctrl->dryrun)
    {
      log_info("dry-run mode - key generation skipped\n");
      return;
    }

  if ( outctrl->use_files )
    {
      if ( outctrl->pub.newfname )
        {
          iobuf_close(outctrl->pub.stream);
          outctrl->pub.stream = NULL;
          if (outctrl->pub.fname)
            iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE,
                         0, (char*)outctrl->pub.fname);
          xfree( outctrl->pub.fname );
          outctrl->pub.fname =  outctrl->pub.newfname;
          outctrl->pub.newfname = NULL;

          if (is_secured_filename (outctrl->pub.fname) )
            {
              outctrl->pub.stream = NULL;
              gpg_err_set_errno (EPERM);
            }
          else
            outctrl->pub.stream = iobuf_create (outctrl->pub.fname, 0);
          if (!outctrl->pub.stream)
            {
              log_error(_("can't create '%s': %s\n"), outctrl->pub.newfname,
                        strerror(errno) );
              return;
            }
          if (opt.armor)
            {
              outctrl->pub.afx->what = 1;
              push_armor_filter (outctrl->pub.afx, outctrl->pub.stream);
            }
        }
      assert( outctrl->pub.stream );
      if (opt.verbose)
        log_info (_("writing public key to '%s'\n"), outctrl->pub.fname );
    }


  /* We create the packets as a tree of kbnodes.  Because the
     structure we create is known in advance we simply generate a
     linked list.  The first packet is a dummy packet which we flag as
     deleted.  The very first packet must always be a KEY packet.  */

  start_tree (&pub_root);

  timestamp = get_parameter_u32 (para, pKEYCREATIONDATE);
  if (!timestamp)
    timestamp = make_timestamp ();

  /* Note that, depending on the backend (i.e. the used scdaemon
     version), the card key generation may update TIMESTAMP for each
     key.  Thus we need to pass TIMESTAMP to all signing function to
     make sure that the binding signature is done using the timestamp
     of the corresponding (sub)key and not that of the primary key.
     An alternative implementation could tell the signing function the
     node of the subkey but that is more work than just to pass the
     current timestamp.  */

  if (!card)
    err = do_create (get_parameter_algo( para, pKEYTYPE, NULL ),
                     get_parameter_uint( para, pKEYLENGTH ),
                     get_parameter_value (para, pKEYCURVE),
                     pub_root,
                     timestamp,
                     get_parameter_u32( para, pKEYEXPIRE ), 0,
                     outctrl->keygen_flags,
                     get_parameter_passphrase (para),
                     &cache_nonce);
  else
    err = gen_card_key (PUBKEY_ALGO_RSA, 1, 1, pub_root,
                        &timestamp,
                        get_parameter_u32 (para, pKEYEXPIRE));

  /* Get the pointer to the generated public key packet.  */
  if (!err)
    {
      pri_psk = pub_root->next->pkt->pkt.public_key;
      assert (pri_psk);
    }

  if (!err && (revkey = get_parameter_revkey (para, pREVOKER)))
    err = write_direct_sig (pub_root, pri_psk, revkey, timestamp, cache_nonce);

  if (!err && (s = get_parameter_value (para, pUSERID)))
    {
      write_uid (pub_root, s );
      err = write_selfsigs (pub_root, pri_psk,
                            get_parameter_uint (para, pKEYUSAGE), timestamp,
                            cache_nonce);
    }

  /* Write the auth key to the card before the encryption key.  This
     is a partial workaround for a PGP bug (as of this writing, all
     versions including 8.1), that causes it to try and encrypt to
     the most recent subkey regardless of whether that subkey is
     actually an encryption type.  In this case, the auth key is an
     RSA key so it succeeds. */

  if (!err && card && get_parameter (para, pAUTHKEYTYPE))
    {
      err = gen_card_key (PUBKEY_ALGO_RSA, 3, 0, pub_root,
                          &timestamp,
                          get_parameter_u32 (para, pKEYEXPIRE));
      if (!err)
        err = write_keybinding (pub_root, pri_psk, NULL,
                                PUBKEY_USAGE_AUTH, timestamp, cache_nonce);
    }

  if (!err && get_parameter (para, pSUBKEYTYPE))
    {
      sub_psk = NULL;
      if (!card)
        {
          err = do_create (get_parameter_algo (para, pSUBKEYTYPE, NULL),
                           get_parameter_uint (para, pSUBKEYLENGTH),
                           get_parameter_value (para, pSUBKEYCURVE),
                           pub_root,
                           timestamp,
                           get_parameter_u32 (para, pSUBKEYEXPIRE), 1,
                           outctrl->keygen_flags,
                           get_parameter_passphrase (para),
                           &cache_nonce);
          /* Get the pointer to the generated public subkey packet.  */
          if (!err)
            {
              kbnode_t node;

              for (node = pub_root; node; node = node->next)
                if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
                  sub_psk = node->pkt->pkt.public_key;
              assert (sub_psk);
            }
        }
      else
        {
          if ((s = get_parameter_value (para, pCARDBACKUPKEY)))
            {
              /* A backup of the encryption key has been requested.
                 Generate the key in software and import it then to
                 the card.  Write a backup file. */
              err = gen_card_key_with_backup
                (PUBKEY_ALGO_RSA, 2, 0, pub_root, timestamp,
                 get_parameter_u32 (para, pKEYEXPIRE), para);
            }
          else
            {
              err = gen_card_key (PUBKEY_ALGO_RSA, 2, 0, pub_root,
                                  &timestamp,
                                  get_parameter_u32 (para, pKEYEXPIRE));
            }
        }

      if (!err)
        err = write_keybinding (pub_root, pri_psk, sub_psk,
                                get_parameter_uint (para, pSUBKEYUSAGE),
                                timestamp, cache_nonce);
      did_sub = 1;
    }

  if (!err && outctrl->use_files)  /* Direct write to specified files.  */
    {
      err = write_keyblock (outctrl->pub.stream, pub_root);
      if (err)
        log_error ("can't write public key: %s\n", gpg_strerror (err));
    }
  else if (!err) /* Write to the standard keyrings.  */
    {
      KEYDB_HANDLE pub_hd = keydb_new ();

      err = keydb_locate_writable (pub_hd, NULL);
      if (err)
        log_error (_("no writable public keyring found: %s\n"),
                   gpg_strerror (err));

      if (!err && opt.verbose)
        {
          log_info (_("writing public key to '%s'\n"),
                    keydb_get_resource_name (pub_hd));
        }

      if (!err)
        {
          err = keydb_insert_keyblock (pub_hd, pub_root);
          if (err)
            log_error (_("error writing public keyring '%s': %s\n"),
                       keydb_get_resource_name (pub_hd), gpg_strerror (err));
        }

      keydb_release (pub_hd);

      if (!err)
        {
          int no_enc_rsa;
          PKT_public_key *pk;

          no_enc_rsa = ((get_parameter_algo (para, pKEYTYPE, NULL)
                         == PUBKEY_ALGO_RSA)
                        && get_parameter_uint (para, pKEYUSAGE)
                        && !((get_parameter_uint (para, pKEYUSAGE)
                              & PUBKEY_USAGE_ENC)) );

          pk = find_kbnode (pub_root, PKT_PUBLIC_KEY)->pkt->pkt.public_key;

          keyid_from_pk (pk, pk->main_keyid);
          register_trusted_keyid (pk->main_keyid);

          update_ownertrust (pk, ((get_ownertrust (pk) & ~TRUST_MASK)
                                  | TRUST_ULTIMATE ));

          gen_standard_revoke (pk, cache_nonce);

          if (!opt.batch)
            {
              tty_printf (_("public and secret key created and signed.\n") );
              tty_printf ("\n");
              list_keyblock_direct (pub_root, 0, 1, 1);
            }


          if (!opt.batch
              && (get_parameter_algo (para, pKEYTYPE, NULL) == PUBKEY_ALGO_DSA
                  || no_enc_rsa )
              && !get_parameter (para, pSUBKEYTYPE) )
            {
              tty_printf(_("Note that this key cannot be used for "
                           "encryption.  You may want to use\n"
                           "the command \"--edit-key\" to generate a "
                           "subkey for this purpose.\n") );
            }
        }
    }

  if (err)
    {
      if (opt.batch)
        log_error ("key generation failed: %s\n", gpg_strerror (err) );
      else
        tty_printf (_("Key generation failed: %s\n"), gpg_strerror (err) );
      write_status_error (card? "card_key_generate":"key_generate", err);
      print_status_key_not_created ( get_parameter_value (para, pHANDLE) );
    }
  else
    {
      PKT_public_key *pk = find_kbnode (pub_root,
                                        PKT_PUBLIC_KEY)->pkt->pkt.public_key;
      print_status_key_created (did_sub? 'B':'P', pk,
                                get_parameter_value (para, pHANDLE));
    }

  release_kbnode (pub_root);
  xfree (cache_nonce);
}


/* Add a new subkey to an existing key.  Returns 0 if a new key has
   been generated and put into the keyblocks.  */
gpg_error_t
generate_subkeypair (ctrl_t ctrl, kbnode_t keyblock)
{
  gpg_error_t err = 0;
  kbnode_t node;
  PKT_public_key *pri_psk = NULL;
  PKT_public_key *sub_psk = NULL;
  int algo;
  unsigned int use;
  u32 expire;
  unsigned int nbits = 0;
  char *curve = NULL;
  u32 cur_time;
  char *hexgrip = NULL;
  char *serialno = NULL;

  /* Break out the primary key.  */
  node = find_kbnode (keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; primary key missing in keyblock!\n");
      err = gpg_error (GPG_ERR_BUG);
      goto leave;
    }
  pri_psk = node->pkt->pkt.public_key;

  cur_time = make_timestamp ();

  if (pri_psk->timestamp > cur_time)
    {
      ulong d = pri_psk->timestamp - cur_time;
      log_info ( d==1 ? _("key has been created %lu second "
                          "in future (time warp or clock problem)\n")
                 : _("key has been created %lu seconds "
                     "in future (time warp or clock problem)\n"), d );
      if (!opt.ignore_time_conflict)
        {
          err = gpg_error (GPG_ERR_TIME_CONFLICT);
          goto leave;
        }
    }

  if (pri_psk->version < 4)
    {
      log_info (_("Note: creating subkeys for v3 keys "
                  "is not OpenPGP compliant\n"));
      err = gpg_error (GPG_ERR_CONFLICT);
      goto leave;
    }

  err = hexkeygrip_from_pk (pri_psk, &hexgrip);
  if (err)
    goto leave;
  if (agent_get_keyinfo (NULL, hexgrip, &serialno))
    {
      tty_printf (_("Secret parts of primary key are not available.\n"));
      goto leave;
    }
  if (serialno)
    tty_printf (_("Secret parts of primary key are stored on-card.\n"));

  xfree (hexgrip);
  hexgrip = NULL;
  algo = ask_algo (ctrl, 1, NULL, &use, &hexgrip);
  assert (algo);

  if (hexgrip)
    nbits = 0;
  else if (algo == PUBKEY_ALGO_ECDSA
           || algo == PUBKEY_ALGO_EDDSA
           || algo == PUBKEY_ALGO_ECDH)
    curve = ask_curve (&algo, 0);
  else
    nbits = ask_keysize (algo, 0);

  expire = ask_expire_interval (0, NULL);
  if (!cpr_enabled() && !cpr_get_answer_is_yes("keygen.sub.okay",
                                               _("Really create? (y/N) ")))
    {
      err = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  if (hexgrip)
    err = do_create_from_keygrip (ctrl, algo, hexgrip,
                                  keyblock, cur_time, expire, 1);
  else
    err = do_create (algo, nbits, curve,
                     keyblock, cur_time, expire, 1, 0, NULL, NULL);
  if (err)
    goto leave;

  /* Get the pointer to the generated public subkey packet.  */
  for (node = keyblock; node; node = node->next)
    if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
      sub_psk = node->pkt->pkt.public_key;

  /* Write the binding signature.  */
  err = write_keybinding (keyblock, pri_psk, sub_psk, use, cur_time, NULL);
  if (err)
    goto leave;

  write_status_text (STATUS_KEY_CREATED, "S");

 leave:
  xfree (curve);
  xfree (hexgrip);
  xfree (serialno);
  if (err)
    log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );
  return err;
}


#ifdef ENABLE_CARD_SUPPORT
/* Generate a subkey on a card. */
gpg_error_t
generate_card_subkeypair (kbnode_t pub_keyblock,
                          int keyno, const char *serialno)
{
  gpg_error_t err = 0;
  kbnode_t node;
  PKT_public_key *pri_pk = NULL;
  int algo;
  unsigned int use;
  u32 expire;
  u32 cur_time;
  struct para_data_s *para = NULL;

  assert (keyno >= 1 && keyno <= 3);

  para = xtrycalloc (1, sizeof *para + strlen (serialno) );
  if (!para)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  para->key = pSERIALNO;
  strcpy (para->u.value, serialno);

  /* Break out the primary secret key */
  node = find_kbnode (pub_keyblock, PKT_PUBLIC_KEY);
  if (!node)
    {
      log_error ("Oops; publkic key lost!\n");
      err = gpg_error (GPG_ERR_INTERNAL);
      goto leave;
    }
  pri_pk = node->pkt->pkt.public_key;

  cur_time = make_timestamp();
  if (pri_pk->timestamp > cur_time)
    {
      ulong d = pri_pk->timestamp - cur_time;
      log_info (d==1 ? _("key has been created %lu second "
                         "in future (time warp or clock problem)\n")
                     : _("key has been created %lu seconds "
                         "in future (time warp or clock problem)\n"), d );
	if (!opt.ignore_time_conflict)
          {
	    err = gpg_error (GPG_ERR_TIME_CONFLICT);
	    goto leave;
          }
    }

  if (pri_pk->version < 4)
    {
      log_info (_("Note: creating subkeys for v3 keys "
                  "is not OpenPGP compliant\n"));
      err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      goto leave;
    }

  algo = PUBKEY_ALGO_RSA;
  expire = ask_expire_interval (0, NULL);
  if (keyno == 1)
    use = PUBKEY_USAGE_SIG;
  else if (keyno == 2)
    use = PUBKEY_USAGE_ENC;
  else
    use = PUBKEY_USAGE_AUTH;
  if (!cpr_enabled() && !cpr_get_answer_is_yes("keygen.cardsub.okay",
                                               _("Really create? (y/N) ")))
    {
      err = gpg_error (GPG_ERR_CANCELED);
      goto leave;
    }

  /* Note, that depending on the backend, the card key generation may
     update CUR_TIME.  */
  err = gen_card_key (algo, keyno, 0, pub_keyblock, &cur_time, expire);
  /* Get the pointer to the generated public subkey packet.  */
  if (!err)
    {
      PKT_public_key *sub_pk = NULL;

      for (node = pub_keyblock; node; node = node->next)
        if (node->pkt->pkttype == PKT_PUBLIC_SUBKEY)
          sub_pk = node->pkt->pkt.public_key;
      assert (sub_pk);
      err = write_keybinding (pub_keyblock, pri_pk, sub_pk,
                              use, cur_time, NULL);
    }

 leave:
  if (err)
    log_error (_("Key generation failed: %s\n"), gpg_strerror (err) );
  else
    write_status_text (STATUS_KEY_CREATED, "S");
  release_parameter_list (para);
  return err;
}
#endif /* !ENABLE_CARD_SUPPORT */

/*
 * Write a keyblock to an output stream
 */
static int
write_keyblock( IOBUF out, KBNODE node )
{
  for( ; node ; node = node->next )
    {
      if(!is_deleted_kbnode(node))
	{
	  int rc = build_packet( out, node->pkt );
	  if( rc )
	    {
	      log_error("build_packet(%d) failed: %s\n",
			node->pkt->pkttype, gpg_strerror (rc) );
	      return rc;
	    }
	}
    }

  return 0;
}


/* Note that timestamp is an in/out arg. */
static gpg_error_t
gen_card_key (int algo, int keyno, int is_primary, kbnode_t pub_root,
              u32 *timestamp, u32 expireval)
{
#ifdef ENABLE_CARD_SUPPORT
  gpg_error_t err;
  struct agent_card_genkey_s info;
  PACKET *pkt;
  PKT_public_key *pk;

  if (algo != PUBKEY_ALGO_RSA)
    return gpg_error (GPG_ERR_PUBKEY_ALGO);

  pk = xtrycalloc (1, sizeof *pk );
  if (!pk)
    return gpg_error_from_syserror ();
  pkt = xtrycalloc (1, sizeof *pkt);
  if (!pkt)
    {
      xfree (pk);
      return gpg_error_from_syserror ();
    }

  /* Note: SCD knows the serialnumber, thus there is no point in passing it.  */
  err = agent_scd_genkey (&info, keyno, 1, NULL, *timestamp);
  /*  The code below is not used because we force creation of
   *  the a card key (3rd arg).
   * if (gpg_err_code (rc) == GPG_ERR_EEXIST)
   *   {
   *     tty_printf ("\n");
   *     log_error ("WARNING: key does already exists!\n");
   *     tty_printf ("\n");
   *     if ( cpr_get_answer_is_yes( "keygen.card.replace_key",
   *                                 _("Replace existing key? ")))
   *       rc = agent_scd_genkey (&info, keyno, 1);
   *   }
  */
  if (!err && (!info.n || !info.e))
    {
      log_error ("communication error with SCD\n");
      gcry_mpi_release (info.n);
      gcry_mpi_release (info.e);
      err =  gpg_error (GPG_ERR_GENERAL);
    }
  if (err)
    {
      log_error ("key generation failed: %s\n", gpg_strerror (err));
      xfree (pkt);
      xfree (pk);
      return err;
    }

  /* Send the learn command so that the agent creates a shadow key for
     card key.  We need to do that now so that we are able to create
     the self-signatures. */
  err = agent_scd_learn (NULL, 0);
  if (err)
    {
      /* Oops: Card removed during generation.  */
      log_error (_("OpenPGP card not available: %s\n"), gpg_strerror (err));
      xfree (pkt);
      xfree (pk);
      return err;
    }

  if (*timestamp != info.created_at)
    log_info ("NOTE: the key does not use the suggested creation date\n");
  *timestamp = info.created_at;

  pk->timestamp = info.created_at;
  pk->version = 4;
  if (expireval)
    pk->expiredate = pk->timestamp + expireval;
  pk->pubkey_algo = algo;
  pk->pkey[0] = info.n;
  pk->pkey[1] = info.e;

  pkt->pkttype = is_primary ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
  pkt->pkt.public_key = pk;
  add_kbnode (pub_root, new_kbnode (pkt));

  return 0;
#else
  (void)algo;
  (void)keyno;
  (void)is_primary;
  (void)pub_root;
  (void)timestamp;
  (void)expireval;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif /*!ENABLE_CARD_SUPPORT*/
}



static int
gen_card_key_with_backup (int algo, int keyno, int is_primary,
                          KBNODE pub_root, u32 timestamp,
                          u32 expireval, struct para_data_s *para)
{
#if ENABLE_CARD_SUPPORT && 0
  /* FIXME: Move this to gpg-agent.  */
  int rc;
  const char *s;
  PACKET *pkt;
  PKT_secret_key *sk, *sk_unprotected = NULL, *sk_protected = NULL;
  PKT_public_key *pk;
  size_t n;
  int i;
  unsigned int nbits;

  /* Get the size of the key directly from the card.  */
  {
    struct agent_card_info_s info;

    memset (&info, 0, sizeof info);
    if (!agent_scd_getattr ("KEY-ATTR", &info)
        && info.key_attr[1].algo)
      nbits = info.key_attr[1].nbits;
    else
      nbits = 1024; /* All pre-v2.0 cards.  */
    agent_release_card_info (&info);
  }

  /* Create a key of this size in memory.  */
  rc = generate_raw_key (algo, nbits, timestamp,
                         &sk_unprotected, &sk_protected);
  if (rc)
    return rc;

  /* Store the key to the card. */
  rc = save_unprotected_key_to_card (sk_unprotected, keyno);
  if (rc)
    {
      log_error (_("storing key onto card failed: %s\n"), gpg_strerror (rc));
      free_secret_key (sk_unprotected);
      free_secret_key (sk_protected);
      write_status_errcode ("save_key_to_card", rc);
      return rc;
    }

  /* Get rid of the secret key parameters and store the serial numer. */
  sk = sk_unprotected;
  n = pubkey_get_nskey (sk->pubkey_algo);
  for (i=pubkey_get_npkey (sk->pubkey_algo); i < n; i++)
    {
      gcry_mpi_release (sk->skey[i]);
      sk->skey[i] = NULL;
    }
  i = pubkey_get_npkey (sk->pubkey_algo);
  sk->skey[i] = gcry_mpi_set_opaque (NULL, xstrdup ("dummydata"), 10*8);
  sk->is_protected = 1;
  sk->protect.s2k.mode = 1002;
  s = get_parameter_value (para, pSERIALNO);
  assert (s);
  for (sk->protect.ivlen=0; sk->protect.ivlen < 16 && *s && s[1];
       sk->protect.ivlen++, s += 2)
    sk->protect.iv[sk->protect.ivlen] = xtoi_2 (s);

  /* Now write the *protected* secret key to the file.  */
  {
    char name_buffer[50];
    char *fname;
    IOBUF fp;
    mode_t oldmask;

    keyid_from_sk (sk, NULL);
    snprintf (name_buffer, sizeof name_buffer, "sk_%08lX%08lX.gpg",
              (ulong)sk->keyid[0], (ulong)sk->keyid[1]);

    fname = make_filename (backup_dir, name_buffer, NULL);
    /* Note that the umask call is not anymore needed because
       iobuf_create now takes care of it.  However, it does not harm
       and thus we keep it.  */
    oldmask = umask (077);
    if (is_secured_filename (fname))
      {
        fp = NULL;
        gpg_err_set_errno (EPERM);
      }
    else
      fp = iobuf_create (fname, 1);
    umask (oldmask);
    if (!fp)
      {
        rc = gpg_error_from_syserror ();
	log_error (_("can't create backup file '%s': %s\n"),
                   fname, strerror(errno) );
        xfree (fname);
        free_secret_key (sk_unprotected);
        free_secret_key (sk_protected);
        return rc;
      }

    pkt = xcalloc (1, sizeof *pkt);
    pkt->pkttype = PKT_SECRET_KEY;
    pkt->pkt.secret_key = sk_protected;
    sk_protected = NULL;

    rc = build_packet (fp, pkt);
    if (rc)
      {
        log_error("build packet failed: %s\n", gpg_strerror (rc));
        iobuf_cancel (fp);
      }
    else
      {
        unsigned char array[MAX_FINGERPRINT_LEN];
        char *fprbuf, *p;

        iobuf_close (fp);
        iobuf_ioctl (NULL, IOBUF_IOCTL_INVALIDATE_CACHE, 0, (char*)fname);
        log_info (_("Note: backup of card key saved to '%s'\n"), fname);

        fingerprint_from_sk (sk, array, &n);
        p = fprbuf = xmalloc (MAX_FINGERPRINT_LEN*2 + 1 + 1);
        for (i=0; i < n ; i++, p += 2)
          sprintf (p, "%02X", array[i]);
        *p++ = ' ';
        *p = 0;

        write_status_text_and_buffer (STATUS_BACKUP_KEY_CREATED,
                                      fprbuf,
                                      fname, strlen (fname),
                                      0);
        xfree (fprbuf);
      }
    free_packet (pkt);
    xfree (pkt);
    xfree (fname);
    if (rc)
      {
        free_secret_key (sk_unprotected);
        return rc;
      }
  }

  /* Create the public key from the secret key. */
  pk = xcalloc (1, sizeof *pk );
  pk->timestamp = sk->timestamp;
  pk->version = sk->version;
  if (expireval)
      pk->expiredate = sk->expiredate = sk->timestamp + expireval;
  pk->pubkey_algo = sk->pubkey_algo;
  n = pubkey_get_npkey (sk->pubkey_algo);
  for (i=0; i < n; i++)
    pk->pkey[i] = mpi_copy (sk->skey[i]);

  /* Build packets and add them to the node lists.  */
  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_PUBLIC_KEY : PKT_PUBLIC_SUBKEY;
  pkt->pkt.public_key = pk;
  add_kbnode(pub_root, new_kbnode( pkt ));

  pkt = xcalloc (1,sizeof *pkt);
  pkt->pkttype = is_primary ? PKT_SECRET_KEY : PKT_SECRET_SUBKEY;
  pkt->pkt.secret_key = sk;
  add_kbnode(sec_root, new_kbnode( pkt ));

  return 0;
#else
# if __GCC__ && ENABLE_CARD_SUPPORT
#  warning Card support still missing
# endif
  (void)algo;
  (void)keyno;
  (void)is_primary;
  (void)pub_root;
  (void)timestamp;
  (void)expireval;
  (void)para;
  return gpg_error (GPG_ERR_NOT_SUPPORTED);
#endif /*!ENABLE_CARD_SUPPORT*/
}


#if 0
int
save_unprotected_key_to_card (PKT_public_key *sk, int keyno)
{
  int rc;
  unsigned char *rsa_n = NULL;
  unsigned char *rsa_e = NULL;
  unsigned char *rsa_p = NULL;
  unsigned char *rsa_q = NULL;
  size_t rsa_n_len, rsa_e_len, rsa_p_len, rsa_q_len;
  unsigned char *sexp = NULL;
  unsigned char *p;
  char numbuf[55], numbuf2[50];

  assert (is_RSA (sk->pubkey_algo));
  assert (!sk->is_protected);

  /* Copy the parameters into straight buffers. */
  gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_n, &rsa_n_len, sk->skey[0]);
  gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_e, &rsa_e_len, sk->skey[1]);
  gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_p, &rsa_p_len, sk->skey[3]);
  gcry_mpi_aprint (GCRYMPI_FMT_USG, &rsa_q, &rsa_q_len, sk->skey[4]);
  if (!rsa_n || !rsa_e || !rsa_p || !rsa_q)
    {
      rc = GPG_ERR_INV_ARG;
      goto leave;
    }

   /* Put the key into an S-expression. */
  sexp = p = xmalloc_secure (30
                             + rsa_n_len + rsa_e_len + rsa_p_len + rsa_q_len
                             + 4*sizeof (numbuf) + 25 + sizeof(numbuf) + 20);

  p = stpcpy (p,"(11:private-key(3:rsa(1:n");
  sprintf (numbuf, "%u:", (unsigned int)rsa_n_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_n, rsa_n_len);
  p += rsa_n_len;

  sprintf (numbuf, ")(1:e%u:", (unsigned int)rsa_e_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_e, rsa_e_len);
  p += rsa_e_len;

  sprintf (numbuf, ")(1:p%u:", (unsigned int)rsa_p_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_p, rsa_p_len);
  p += rsa_p_len;

  sprintf (numbuf, ")(1:q%u:", (unsigned int)rsa_q_len);
  p = stpcpy (p, numbuf);
  memcpy (p, rsa_q, rsa_q_len);
  p += rsa_q_len;

  p = stpcpy (p,"))(10:created-at");
  sprintf (numbuf2, "%lu", (unsigned long)sk->timestamp);
  sprintf (numbuf, "%lu:", (unsigned long)strlen (numbuf2));
  p = stpcpy (stpcpy (stpcpy (p, numbuf), numbuf2), "))");

  /* Fixme: Unfortunately we don't have the serialnumber available -
     thus we can't pass it down to the agent. */
  rc = agent_scd_writekey (keyno, NULL, sexp, p - sexp);

 leave:
  xfree (sexp);
  xfree (rsa_n);
  xfree (rsa_e);
  xfree (rsa_p);
  xfree (rsa_q);
  return rc;
}
#endif /*ENABLE_CARD_SUPPORT*/
