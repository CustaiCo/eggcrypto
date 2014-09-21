static int print_random_integer(const char* handle, const char* text);
static int msg_random_int(char *nick, char *host, char *hand, char *channel, char *text);
static int pub_random_int(char *nick, char *host, char *hand, char *channel, char *text);
static uint64_t get_really_random(uint64_t max);
static unsigned char* get_randombytes(unsigned int bytes_needed);
