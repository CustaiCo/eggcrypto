#define MAX_MESSAGE 50
static void bind_crypto_commands();
static int pub_salsa(char *, char *, char *, char *, char *);
static int msg_salsa(char *, char *, struct userrec *, char *);
static int process_salsa(const char*, char*);
static int parse_plaintext_arguments(char *, char **, int*, char**, int*, char**, int*);
static char* get_printable_ciphertext(const unsigned char* key, 
    const unsigned char* nonce, const unsigned char* plaintext, 
    int plen);
