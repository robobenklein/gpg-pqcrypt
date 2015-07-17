/* main.h
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
 *               2008, 2009, 2010 Free Software Foundation, Inc.
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
#ifndef G10_MAIN_H
#define G10_MAIN_H

#include "types.h"
#include "iobuf.h"
#include "keydb.h"
#include "util.h"

/* It could be argued that the default cipher should be 3DES rather
   than AES128, and the default compression should be 0
   (i.e. uncompressed) rather than 1 (zip).  However, the real world
   issues of speed and size come into play here. */

#if GPG_USE_AES128
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_AES
#elif GPG_USE_CAST5
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_CAST5
#else
# define DEFAULT_CIPHER_ALGO     CIPHER_ALGO_3DES
#endif

#define DEFAULT_DIGEST_ALGO     ((GNUPG)? DIGEST_ALGO_SHA256:DIGEST_ALGO_SHA1)
#define DEFAULT_S2K_DIGEST_ALGO DIGEST_ALGO_SHA1
#ifdef HAVE_ZIP
# define DEFAULT_COMPRESS_ALGO   COMPRESS_ALGO_ZIP
#else
# define DEFAULT_COMPRESS_ALGO   COMPRESS_ALGO_NONE
#endif


#define S2K_DIGEST_ALGO (opt.s2k_digest_algo?opt.s2k_digest_algo:DEFAULT_S2K_DIGEST_ALGO)


/* Various data objects.  */

typedef struct
{
  int header_okay;
  PK_LIST pk_list;
  DEK *symkey_dek;
  STRING2KEY *symkey_s2k;
  cipher_filter_context_t cfx;
} encrypt_filter_context_t;


struct groupitem
{
  char *name;
  strlist_t values;
  struct groupitem *next;
};


/*-- gpg.c --*/
extern int g10_errors_seen;

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 )
  void g10_exit(int rc) __attribute__ ((noreturn));
#else
  void g10_exit(int rc);
#endif
void print_pubkey_algo_note (pubkey_algo_t algo);
void print_cipher_algo_note (cipher_algo_t algo);
void print_digest_algo_note (digest_algo_t algo);
void print_md5_rejected_note (void);

/*-- armor.c --*/
char *make_radix64_string( const byte *data, size_t len );

/*-- misc.c --*/
void trap_unaligned(void);
int disable_core_dumps(void);
void register_secured_file (const char *fname);
void unregister_secured_file (const char *fname);
int  is_secured_file (int fd);
int  is_secured_filename (const char *fname);
u16 checksum_u16( unsigned n );
u16 checksum( byte *p, unsigned n );
u16 checksum_mpi( gcry_mpi_t a );
u32 buffer_to_u32( const byte *buffer );
const byte *get_session_marker( size_t *rlen );

enum gcry_cipher_algos map_cipher_openpgp_to_gcry (cipher_algo_t algo);
#define openpgp_cipher_open(_a,_b,_c,_d) \
  gcry_cipher_open((_a),map_cipher_openpgp_to_gcry((_b)),(_c),(_d))
#define openpgp_cipher_get_algo_keylen(_a) \
  gcry_cipher_get_algo_keylen(map_cipher_openpgp_to_gcry((_a)))
#define openpgp_cipher_get_algo_blklen(_a) \
  gcry_cipher_get_algo_blklen(map_cipher_openpgp_to_gcry((_a)))
int openpgp_cipher_blocklen (cipher_algo_t algo);
int openpgp_cipher_test_algo(cipher_algo_t algo);
const char *openpgp_cipher_algo_name (cipher_algo_t algo);

pubkey_algo_t map_pk_gcry_to_openpgp (enum gcry_pk_algos algo);
int openpgp_pk_test_algo (pubkey_algo_t algo);
int openpgp_pk_test_algo2 (pubkey_algo_t algo, unsigned int use);
int openpgp_pk_algo_usage ( int algo );
const char *openpgp_pk_algo_name (pubkey_algo_t algo);

enum gcry_md_algos map_md_openpgp_to_gcry (digest_algo_t algo);
int openpgp_md_test_algo (digest_algo_t algo);
const char *openpgp_md_algo_name (int algo);

struct expando_args
{
  PKT_public_key *pk;
  PKT_public_key *pksk;
  byte imagetype;
  int validity_info;
  const char *validity_string;
  const byte *namehash;
};

char *pct_expando(const char *string,struct expando_args *args);
void deprecated_warning(const char *configname,unsigned int configlineno,
			const char *option,const char *repl1,const char *repl2);
void deprecated_command (const char *name);
void obsolete_scdaemon_option (const char *configname,
                               unsigned int configlineno, const char *name);

int string_to_cipher_algo (const char *string);
int string_to_digest_algo (const char *string);

const char *compress_algo_to_string(int algo);
int string_to_compress_algo(const char *string);
int check_compress_algo(int algo);
int default_cipher_algo(void);
int default_compress_algo(void);
const char *compliance_option_string(void);
void compliance_failure(void);

struct parse_options
{
  char *name;
  unsigned int bit;
  char **value;
  char *help;
};

char *optsep(char **stringp);
char *argsplit(char *string);
int parse_options(char *str,unsigned int *options,
		  struct parse_options *opts,int noisy);
const char *get_libexecdir (void);
int path_access(const char *file,int mode);

int pubkey_get_npkey (pubkey_algo_t algo);
int pubkey_get_nskey (pubkey_algo_t algo);
int pubkey_get_nsig (pubkey_algo_t algo);
int pubkey_get_nenc (pubkey_algo_t algo);

/* Temporary helpers. */
unsigned int pubkey_nbits( int algo, gcry_mpi_t *pkey );
int mpi_print (estream_t stream, gcry_mpi_t a, int mode);
unsigned int ecdsa_qbits_from_Q (unsigned int qbits);


/*-- status.c --*/
void set_status_fd ( int fd );
int  is_status_enabled ( void );
void write_status ( int no );
void write_status_error (const char *where, gpg_error_t err);
void write_status_errcode (const char *where, int errcode);
void write_status_text ( int no, const char *text );
void write_status_strings (int no, const char *text,
                           ...) GNUPG_GCC_A_SENTINEL(0);
void write_status_buffer ( int no,
                           const char *buffer, size_t len, int wrap );
void write_status_text_and_buffer ( int no, const char *text,
                                    const char *buffer, size_t len, int wrap );

void write_status_begin_signing (gcry_md_hd_t md);


int cpr_enabled(void);
char *cpr_get( const char *keyword, const char *prompt );
char *cpr_get_no_help( const char *keyword, const char *prompt );
char *cpr_get_utf8( const char *keyword, const char *prompt );
char *cpr_get_hidden( const char *keyword, const char *prompt );
void cpr_kill_prompt(void);
int  cpr_get_answer_is_yes_def (const char *keyword, const char *prompt,
                                int def_yes);
int  cpr_get_answer_is_yes( const char *keyword, const char *prompt );
int  cpr_get_answer_yes_no_quit( const char *keyword, const char *prompt );
int  cpr_get_answer_okay_cancel (const char *keyword,
                                 const char *prompt,
                                 int def_answer);

/*-- helptext.c --*/
void display_online_help( const char *keyword );

/*-- encode.c --*/
int setup_symkey (STRING2KEY **symkey_s2k,DEK **symkey_dek);
int encrypt_symmetric (const char *filename );
int encrypt_store (const char *filename );
int encrypt_crypt (ctrl_t ctrl, int filefd, const char *filename,
                   strlist_t remusr, int use_symkey, pk_list_t provided_keys,
                   int outputfd);
void encrypt_crypt_files (ctrl_t ctrl,
                          int nfiles, char **files, strlist_t remusr);
int encrypt_filter (void *opaque, int control,
		    iobuf_t a, byte *buf, size_t *ret_len);


/*-- sign.c --*/
int complete_sig (PKT_signature *sig, PKT_public_key *pksk, gcry_md_hd_t md,
                  const char *cache_nonce);
int sign_file (ctrl_t ctrl, strlist_t filenames, int detached, strlist_t locusr,
	       int do_encrypt, strlist_t remusr, const char *outfile );
int clearsign_file( const char *fname, strlist_t locusr, const char *outfile );
int sign_symencrypt_file (const char *fname, strlist_t locusr);

/*-- sig-check.c --*/
int check_revocation_keys (PKT_public_key *pk, PKT_signature *sig);
int check_backsig(PKT_public_key *main_pk,PKT_public_key *sub_pk,
		  PKT_signature *backsig);
int check_key_signature( KBNODE root, KBNODE node, int *is_selfsig );
int check_key_signature2( KBNODE root, KBNODE node, PKT_public_key *check_pk,
			  PKT_public_key *ret_pk, int *is_selfsig,
			  u32 *r_expiredate, int *r_expired );

/*-- delkey.c --*/
gpg_error_t delete_keys (strlist_t names, int secret, int allow_both);

/*-- keyedit.c --*/
void keyedit_menu (ctrl_t ctrl, const char *username, strlist_t locusr,
		   strlist_t commands, int quiet, int seckey_check );
void keyedit_passwd (ctrl_t ctrl, const char *username);
void keyedit_quick_adduid (ctrl_t ctrl, const char *username,
                           const char *newuid);
void keyedit_quick_sign (ctrl_t ctrl, const char *fpr,
                         strlist_t uids, strlist_t locusr, int local);
void show_basic_key_info (KBNODE keyblock);

/*-- keygen.c --*/
u32 parse_expire_string(const char *string);
u32 ask_expire_interval(int object,const char *def_expire);
u32 ask_expiredate(void);
void quick_generate_keypair (const char *uid);
void generate_keypair (ctrl_t ctrl, int full, const char *fname,
                       const char *card_serialno, int card_backup_key);
int keygen_set_std_prefs (const char *string,int personal);
PKT_user_id *keygen_get_std_prefs (void);
int keygen_add_key_expire( PKT_signature *sig, void *opaque );
int keygen_add_std_prefs( PKT_signature *sig, void *opaque );
int keygen_upd_std_prefs( PKT_signature *sig, void *opaque );
int keygen_add_keyserver_url(PKT_signature *sig, void *opaque);
int keygen_add_notations(PKT_signature *sig,void *opaque);
int keygen_add_revkey(PKT_signature *sig, void *opaque);
gpg_error_t make_backsig (PKT_signature *sig, PKT_public_key *pk,
                          PKT_public_key *sub_pk, PKT_public_key *sub_psk,
                          u32 timestamp, const char *cache_nonce);
gpg_error_t generate_subkeypair (ctrl_t ctrl, kbnode_t pub_keyblock);
#ifdef ENABLE_CARD_SUPPORT
gpg_error_t generate_card_subkeypair (kbnode_t pub_keyblock,
                                      int keyno, const char *serialno);
int save_unprotected_key_to_card (PKT_public_key *sk, int keyno);
#endif


/*-- openfile.c --*/
int overwrite_filep( const char *fname );
char *make_outfile_name( const char *iname );
char *ask_outfile_name( const char *name, size_t namelen );
int open_outfile (int inp_fd, const char *iname, int mode,
                  int restrictedperm, iobuf_t *a);
char *get_matching_datafile (const char *sigfilename);
iobuf_t open_sigfile (const char *sigfilename, progress_filter_context_t *pfx);
void try_make_homedir( const char *fname );
char *get_openpgp_revocdir (const char *home);

/*-- seskey.c --*/
void make_session_key( DEK *dek );
gcry_mpi_t encode_session_key( int openpgp_pk_algo, DEK *dek, unsigned nbits );
gcry_mpi_t encode_md_value (PKT_public_key *pk,
                            gcry_md_hd_t md, int hash_algo );

/*-- import.c --*/
typedef gpg_error_t (*import_screener_t)(kbnode_t keyblock, void *arg);

int parse_import_options(char *str,unsigned int *options,int noisy);
void import_keys (ctrl_t ctrl, char **fnames, int nnames,
		  void *stats_hd, unsigned int options);
int import_keys_stream (ctrl_t ctrl, iobuf_t inp, void *stats_hd,
                        unsigned char **fpr,
			size_t *fpr_len, unsigned int options);
int import_keys_es_stream (ctrl_t ctrl, estream_t fp, void *stats_handle,
                           unsigned char **fpr, size_t *fpr_len,
                           unsigned int options,
                           import_screener_t screener, void *screener_arg);
gpg_error_t import_old_secring (ctrl_t ctrl, const char *fname);
void *import_new_stats_handle (void);
void import_release_stats_handle (void *p);
void import_print_stats (void *hd);

int collapse_uids( KBNODE *keyblock );


/*-- export.c --*/
int parse_export_options(char *str,unsigned int *options,int noisy);
int export_pubkeys (ctrl_t ctrl, strlist_t users, unsigned int options );
int export_pubkeys_stream (ctrl_t ctrl, iobuf_t out, strlist_t users,
			   kbnode_t *keyblock_out, unsigned int options );
gpg_error_t export_pubkey_buffer (ctrl_t ctrl, const char *keyspec,
                                  unsigned int options,
                                  kbnode_t *r_keyblock,
                                  void **r_data, size_t *r_datalen);
int export_seckeys (ctrl_t ctrl, strlist_t users);
int export_secsubkeys (ctrl_t ctrl, strlist_t users);

/*-- dearmor.c --*/
int dearmor_file( const char *fname );
int enarmor_file( const char *fname );

/*-- revoke.c --*/
struct revocation_reason_info;
int gen_standard_revoke (PKT_public_key *psk, const char *cache_nonce);
int gen_revoke( const char *uname );
int gen_desig_revoke( const char *uname, strlist_t locusr);
int revocation_reason_build_cb( PKT_signature *sig, void *opaque );
struct revocation_reason_info *
		ask_revocation_reason( int key_rev, int cert_rev, int hint );
void release_revocation_reason_info( struct revocation_reason_info *reason );

/*-- keylist.c --*/
void public_key_list (ctrl_t ctrl, strlist_t list, int locate_mode );
void secret_key_list (ctrl_t ctrl, strlist_t list );
void print_subpackets_colon(PKT_signature *sig);
void reorder_keyblock (KBNODE keyblock);
void list_keyblock_direct (kbnode_t keyblock, int secret, int has_secret,
                           int fpr);
void print_fingerprint (estream_t fp, PKT_public_key *pk, int mode);
void print_revokers (estream_t fp, PKT_public_key *pk);
void show_policy_url(PKT_signature *sig,int indent,int mode);
void show_keyserver_url(PKT_signature *sig,int indent,int mode);
void show_notation(PKT_signature *sig,int indent,int mode,int which);
void dump_attribs (const PKT_user_id *uid, PKT_public_key *pk);
void set_attrib_fd(int fd);
void print_seckey_info (PKT_public_key *pk);
void print_pubkey_info (estream_t fp, PKT_public_key *pk);
void print_card_key_info (estream_t fp, KBNODE keyblock);

/*-- verify.c --*/
void print_file_status( int status, const char *name, int what );
int verify_signatures (ctrl_t ctrl, int nfiles, char **files );
int verify_files (ctrl_t ctrl, int nfiles, char **files );
int gpg_verify (ctrl_t ctrl, int sig_fd, int data_fd, estream_t out_fp);

/*-- decrypt.c --*/
int decrypt_message (ctrl_t ctrl, const char *filename );
gpg_error_t decrypt_message_fd (ctrl_t ctrl, int input_fd, int output_fd);
void decrypt_messages (ctrl_t ctrl, int nfiles, char *files[]);

/*-- plaintext.c --*/
int hash_datafiles( gcry_md_hd_t md, gcry_md_hd_t md2,
		    strlist_t files, const char *sigfilename, int textmode);
int hash_datafile_by_fd ( gcry_md_hd_t md, gcry_md_hd_t md2, int data_fd,
                          int textmode );
PKT_plaintext *setup_plaintext_name(const char *filename,IOBUF iobuf);

/*-- server.c --*/
int gpg_server (ctrl_t);
gpg_error_t gpg_proxy_pinentry_notify (ctrl_t ctrl,
                                       const unsigned char *line);

#ifdef ENABLE_CARD_SUPPORT
/*-- card-util.c --*/
void change_pin (int no, int allow_admin);
void card_status (estream_t fp, char *serialno, size_t serialnobuflen);
void card_edit (ctrl_t ctrl, strlist_t commands);
gpg_error_t  card_generate_subkey (KBNODE pub_keyblock);
int  card_store_subkey (KBNODE node, int use);
#endif

#define S2K_DECODE_COUNT(_val) ((16ul + ((_val) & 15)) << (((_val) >> 4) + 6))

/*-- migrate.c --*/
void migrate_secring (ctrl_t ctrl);


#endif /*G10_MAIN_H*/
