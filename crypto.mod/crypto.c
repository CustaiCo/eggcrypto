/*
 * crypto.c -- it's my mod
 *   nonsensical encryption module
 */
/*
 * Copyright (C) CustaiCo
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define MODULE_NAME "crypto"
#define MAKING_CRYPTO

#include "src/mod/module.h"
#include "../irc.mod/irc.h"
#include "../server.mod/server.h"
#include "tweetnacl.h"
#include "tweetnacl.c"
#include "crypto.h"
#include <stdlib.h>
#include <fcntl.h>

#undef global
static Function *global = NULL;
static Function *irc_funcs = NULL;
static Function *server_funcs = NULL; 

static int crypto_expmem()
{
  int size = 0;
  return size;
}

static void crypto_report(int idx, int details)
{
  if (details) {
    int size = crypto_expmem();

    dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
  }
}

static cmd_t crypt_pubs[] = {
  /* command  flags  function     tcl-name */
  {"!salsa",  "",  pub_salsa,   NULL},
  {NULL,      NULL,  NULL,        NULL}  /* Mark end. */
};

static cmd_t crypt_msgs[] = {
  /* command  flags  function     tcl-name */
  {"!salsa",  "",   msg_salsa,   NULL},
  {NULL,      NULL,  NULL,        NULL}  /* Mark end. */
};

static char *crypto_close()
{
  rem_builtins(H_pub, crypt_pubs);
  rem_builtins(H_msg, crypt_msgs);
  module_undepend(MODULE_NAME);
  return NULL;
}

/* Define the prototype here, to avoid warning messages in the
 * crypto_table.
*/ EXPORT_SCOPE char *crypto_start();

static Function crypto_table[] = {
  (Function) crypto_start,
  (Function) crypto_close,
  (Function) crypto_expmem,
  (Function) crypto_report,
};

static void bind_crypto_commands()
{
  add_builtins(H_msg, crypt_msgs);
  add_builtins(H_pub, crypt_pubs);
}

char *crypto_start(Function *global_funcs)
{
  global = global_funcs;

  // register module
  module_register(MODULE_NAME, crypto_table, 0, 1);

  if (!module_depend(MODULE_NAME, "eggdrop", 106, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.6.0 or later.";
  }
  if (!(server_funcs = module_depend(MODULE_NAME, "server", 1, 3))) {
    module_undepend(MODULE_NAME);
    return "This module requires server mod to work!";
  }
  if (!(irc_funcs = module_depend(MODULE_NAME, "irc", 1, 4))) {
    module_undepend(MODULE_NAME);
    return "This module requires irc mod to work!";
  }
  bind_crypto_commands();

  return NULL;
}

// since I have no way to tell tweetnacl
// that my randomness failed, I just panic
// if something goes bad
void randombytes(u8* buf, u64 len)
{
  int fd;

  if((fd = open("/dev/urandom", O_RDONLY)) == -1 )
    fatal("NO /dev/urandom -- BYE!",0);

  if(read(fd,buf,len)!=len)
    fatal("/dev/urandom RAN OUT OF BITS -- BYE!",0);

  close(fd);
}

static int pub_salsa(char *nick, char *host, char *hand, char *channel, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, channel, "%s@#%s salsa", nick, channel);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", channel);
  return process_salsa(return_message,text);
}

static int msg_salsa(char *nick, char *host, struct userrec *u, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, "*", "PM %s salsa", nick);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", nick);
  return process_salsa(return_message,text);
}

static int process_salsa(const char* return_message, char* text)
{
  char *ciphertext;
  char *plaintext;
  int plen;
  char *key;
  int klen;
  char *nonce;
  int nlen;
  unsigned char key_bytes[crypto_stream_KEYBYTES];
  unsigned char nonce_bytes[crypto_stream_NONCEBYTES];
  if(parse_plaintext_arguments( text, &key, &klen, &nonce, &nlen, &plaintext, &plen ) < 0)
  {
    dprintf(DP_HELP, "%s :!salsa key nonce plaintext\n", return_message);
    return TCL_OK;
  }
  // since we are not doing any key/nonce processing at this time
  // we need to make sure they aren't too long
  if(klen > crypto_stream_KEYBYTES)
  {
    dprintf(DP_HELP, "%s :key can be no longer than %d\n", return_message, crypto_stream_KEYBYTES);
    return TCL_OK;
  }

  if(nlen > crypto_stream_NONCEBYTES)
  {
    dprintf(DP_HELP, "%s :nonce can be no longer than %d\n", return_message, crypto_stream_NONCEBYTES);
    return TCL_OK;
  }

  // zero out these key and nonce buffers, since my initial implementation just 
  // directly takes the bytes of what you give it
  // otherwise the key/nonce are not well defined
  memset(&key_bytes, 0, crypto_stream_KEYBYTES);
  memset(&nonce_bytes, 0, crypto_stream_NONCEBYTES);
 
  memcpy(&key_bytes, key, klen);
  memcpy(&nonce_bytes, nonce, nlen);

  if((ciphertext = get_printable_ciphertext(key_bytes,nonce_bytes,(unsigned char*)plaintext,plen)) == NULL )
  {
    dprintf(DP_HELP, "%s :crypto fail! Contact CustaiCo\n", return_message);
    return TCL_OK;
  }
  // TODO: length checking
  dprintf(DP_SERVER, "%s :%s\n", return_message, ciphertext);

  nfree(ciphertext);
  return TCL_OK;
}


/*
 * this returns a pointer to a "printable" ciphertext string
 * that is null terminated. It is the callers responcibility
 * to free the string after use. There are no promises between
 * the relation of the message and the length of the string 
 * returned
 * 
 * if there is an error during encryption return is null
 */
static char* get_printable_ciphertext(const unsigned char* key, 
    const unsigned char* nonce, const unsigned char* plaintext, 
    int plen)
{
  unsigned char *cipherbytes;
  char *print_bytes;

  cipherbytes = nmalloc(plen);
  if(crypto_stream_xor(cipherbytes,plaintext,plen,nonce,key))
  {
    putlog(LOG_MISC, "*", "*** Encryption failure!" );
    nfree(cipherbytes);
    return NULL;
  }

  // current strategy -- use the crappy base64 encoding that 
  // eggdrop provides. This will at most use 2x the space of the
  // original.. i hope
  print_bytes = nmalloc(plen*2+1);
  *(print_bytes+plen*2) = '\0';
  int j = 0;
  // this %D format string is an unpadded base64 encode
  // and the return is the offset from the start of the buffer to
  // the null terminator
  int i = 0;
  for(i = 0; i < plen; i++)
    j = simple_sprintf((print_bytes+j),"%D", cipherbytes[i]);
  
  return print_bytes;
}

static int parse_plaintext_arguments( char *text, char **key, int* klen, 
    char** nonce, int* nlen, char** plaintext, int* plen ) 
{
  char *temp;

  // grab the key
  *key = text;
  if((temp = strchr( text, ' ' )) == NULL )
    return -1;
  *temp = '\0';
  *klen = temp-*key;

  // and the nonce
  *nonce = temp+1;
  if((temp = strchr( text, ' ' )) == NULL )
    return -1;
  *temp = '\0';
  *nlen = temp-*key;
  
  // leftovers are the plaintext
  *plaintext = temp+1;
  *plen = strlen(*plaintext);
  return 0;
}


// vim:et:ts=2:sw=2:ai