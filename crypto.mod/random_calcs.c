/*
 * random_cals.c
 *   allows you to get random numbers, should allow choices between
 *   other random stuff as well later on 
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

#include <stdint.h>
#include <errno.h>
#include "random_calcs.h"
#include "tweetnacl.h"

#define RANDOM_BUFFER_SIZE 512

static int pub_random_int(char *nick, char *host, char *hand, char *channel, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, channel, "%s@#%s randomint", nick, channel);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", channel);
  return print_random_integer(return_message,text);
}

static int msg_random_int(char *nick, char *host, char *hand, char *channel, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, channel, "%s@#%s randomint", nick, channel);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", channel);
  return print_random_integer(return_message,text);
}

static int print_random_integer(const char* handle, const char* text)
{
  uint64_t maxnumber;
  uint64_t returnvalue;

  errno = 0;
  maxnumber = strtoull(text, NULL, 0);
  if(errno)
  {
    char *msg = strerror(errno);
    dprintf(DP_HELP, "%s :%s\n", handle, msg);
    return TCL_OK;
  }

  returnvalue = get_really_random(maxnumber);
  dprintf(DP_SERVER, "%s :%d\n", handle, returnvalue);
  
  return TCL_OK;
}


/*
 * The proper way to get a random integer when
 * you are limited to getting a number of bytes
 * is to get a random value between 0 and and 
 * the smallest power of two that is above the 
 * requested value, then throw out any values
 * that are too large 
 */
static uint64_t get_really_random(uint64_t max) 
{
  unsigned int bitsneeded = 0;
  unsigned char* randomness;
  uint64_t returnvalue;
  int i;

  // this way I don't use any randomness if none is needed
  // and don't have to worry about wierd degenerate cases
  if(max==0)
  {
    return 0;
  }

  i = 0;
  while(max >> bitsneeded)
  {
    bitsneeded++;
    // this is needed because >> 64 is undefined
    if(bitsneeded == 64)
      break;
  }
  
  do
  {
    returnvalue = 0;

    /* Grab some randomness. I don't need to free this
     * or allocate it  b/c it's actually just a 
     * pointer to a buffer maintained elsewhere
     */
    randomness = get_randombytes((bitsneeded/8)+1);
    // this acutally should never happen but if it does
    // i will log it and return a 'random number'
    if(randomness == NULL)
    {
      putlog(LOG_MISC, "*","randomness generation returns null!");
      return 42;
    }

    for(i = 0; i<((bitsneeded/8)+1); i++)
      returnvalue |= randomness[i] << i;

    if(bitsneeded%8)
      returnvalue >>= (8 - (bitsneeded % 8));

  } while(returnvalue >= max);

  return returnvalue;
}

// returns null in error condition
static unsigned char* get_randombytes(unsigned int bytes_needed)
{
  static unsigned char random_buffer[RANDOM_BUFFER_SIZE];
  static unsigned char key[crypto_stream_salsa20_KEYBYTES];
  // this is cheating, but since crypto_stream_salsa20_NONCEBYTES is 8
  // this will work
  static uint64_t nonce = 0;
  static int available_bytes = -1;
  unsigned char* ret;

  if(bytes_needed > RANDOM_BUFFER_SIZE)
    return NULL;
  
  // this handles the initialization of the key
  if(available_bytes < 0)
    randombytes((u8 *)&key,crypto_stream_salsa20_KEYBYTES);

  if(bytes_needed < available_bytes)
  {
    if(crypto_stream_salsa20(random_buffer, RANDOM_BUFFER_SIZE, 
            (unsigned char*) &nonce, key))
      return NULL; // something very bad has happened
    available_bytes = RANDOM_BUFFER_SIZE;
    nonce++;
  }

  ret = random_buffer + (RANDOM_BUFFER_SIZE-available_bytes);
  available_bytes -= bytes_needed;
  return ret;
}

// vim:et:ts=2:sw=2:ai
