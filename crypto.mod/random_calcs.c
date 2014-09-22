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

#include <inttypes.h>
#include <errno.h>
#include <locale.h>
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

static int msg_random_int(char *nick, char *host, struct userrec *u, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, "*", "%s randomint", nick);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", nick);
  return print_random_integer(return_message,text);
}

static int pub_dice(char *nick, char *host, char *hand, char *channel, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, channel, "%s@#%s dice", nick, channel);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", channel);
  return print_dice_roll(return_message,text);
}

static int msg_dice(char *nick, char *host, struct userrec *u, char *text)
{
  char return_message[MAX_MESSAGE];
  putlog(LOG_CMDS, "*", "%s dice", nick);
  egg_snprintf(return_message, MAX_MESSAGE,"PRIVMSG %s", nick);
  return print_dice_roll(return_message,text);
}

/*
 * eggdrop insists on using a stupid LC_NUMERIC locale
 * even if the environment says to use something else
 * these two helper functions temporarily fix things
 * for outputing strigns
 */
static char* fix_locale()
{
  char *old;
  char *save;
  old = setlocale(LC_NUMERIC,NULL);
  save = nstrdup(old);
  if(save == NULL)
    fatal("Out of memory", 0);
  setlocale(LC_NUMERIC,"en_US.utf8");
  return save;
}

static void unfix_locale(char* old)
{
  setlocale(LC_NUMERIC,old);
  nfree(old);
}

static int print_dice_roll(const char* handle, const char* text)
{
  long number_rolls;
  long dice_size;
  char *end;
  char *second;
  uint64_t results = 0;

  errno = 0;
  number_rolls = strtol(text,&end,10);
  if(errno)
  {
    char *msg = strerror(errno);
    dprintf(DP_HELP, "%s :%s\n", handle, msg);
    return TCL_OK;
  }
  if(text == end || end[0] == '\0' || (end[0] != 'D' && end[0] != 'd'))
  {
    dprintf(DP_HELP, "%s :Syntax !roll 3d7\n", handle);
    return TCL_OK;
  }
  // this is b/c if you ask for near LONG_MAX rolls, it 
  // crushes the machine
  if(number_rolls > (RANDOM_BUFFER_SIZE * 10))
  {
    char *l = fix_locale();
    dprintf(DP_HELP, "%s :I will not roll more than %'d times. It's bad for my brain.\n", handle, RANDOM_BUFFER_SIZE *10 );
    unfix_locale(l);
    return TCL_OK;
  }
  second = end+1;
  errno = 0;
  dice_size = strtol(second,&end,10);
  if(errno)
  {
    char *msg = strerror(errno);
    dprintf(DP_HELP, "%s :%s\n", handle, msg);
    return TCL_OK;
  }
  if(second == end)
  {
    dprintf(DP_HELP, "%s :Syntax !roll 3d7\n", handle);
    return TCL_OK;
  }
  if(dice_size < 1 || number_rolls < 0 || dice_size == LONG_MAX || number_rolls == LONG_MAX)
  {
    char *l = fix_locale();
    dprintf(DP_HELP, "%s :natural numbers lower than %'ld, please\n", handle, LONG_MAX);
    unfix_locale(l);
    return TCL_OK;
  }
  while(number_rolls--)
     results += get_really_random(dice_size-1) + 1;

  char *l = fix_locale();
  dprintf(DP_SERVER, "%s :the dice say %'" PRIu64 " \n", handle, results);
  unfix_locale(l);
  return TCL_OK;
}


static int print_random_integer(const char* handle, const char* text)
{
  uint64_t maxnumber;
  uint64_t returnvalue;
  char *end;

  errno = 0;
  maxnumber = strtoull(text, &end, 0);
  if(errno)
  {
    char *msg = strerror(errno);
    dprintf(DP_HELP, "%s :%s\n", handle, msg);
    return TCL_OK;
  }
  // for some reason errno is not set if there are no numbers
  if(text == end)
  {
    dprintf(DP_HELP, "%s :'%s' does not seem to be numeric\n", handle, text);
    return TCL_OK;
  }

  returnvalue = get_really_random(maxnumber);
  char *l = fix_locale();
  dprintf(DP_SERVER, "%s :%'" PRIu64 "\n", handle, returnvalue);
  unfix_locale(l);
  
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
  unsigned int bytesneeded = 0;
  unsigned char* randomness;
  uint64_t returnvalue;
  unsigned int i;

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

  bytesneeded = (bitsneeded / CHAR_BIT) + ((bitsneeded % CHAR_BIT) ? 1 : 0);
  
  do
  {
    returnvalue = 0;

    /* Grab some randomness. I don't need to free this
     * or allocate it  b/c it's actually just a 
     * pointer to a buffer maintained elsewhere
     */
    randomness = get_randombytes(bytesneeded);
    // this acutally should never happen but if it does
    // i will log it and return a 'random number'
    if(randomness == NULL)
    {
      putlog(LOG_MISC, "*","randomness generation returns null!");
      return 42;
    }

    for(i = 0; i<bytesneeded; i++)
      returnvalue |= ((uint64_t)randomness[i] << (uint64_t)(i*CHAR_BIT));

    if(bitsneeded%CHAR_BIT)
      returnvalue >>= (CHAR_BIT-(bitsneeded%CHAR_BIT));

  } while(returnvalue > max);

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
    randombytes(key,crypto_stream_salsa20_KEYBYTES);

  if((int)bytes_needed > available_bytes)
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
