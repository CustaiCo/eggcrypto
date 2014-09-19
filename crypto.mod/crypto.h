#define MAX_MESSAGE 50

// some defines for how we process the ciphertext
#define B64_TEXT    0x0001

static void bind_crypto_commands();
static int pub_salsa(char *, char *, char *, char *, char *);
static int msg_salsa(char *, char *, struct userrec *, char *);
static int process_salsa(const char*, char*,short);
static int parse_plaintext_arguments(char *, char **, int*, char**, int*, char**, int*);
static unsigned char* get_ciphertext(const unsigned char* key, 
    const unsigned char* nonce, const unsigned char* plaintext, 
    int plen);
static int pub_salsa64(char*, char *, char*, char *, char* );
static int msg_salsa64(char*, char *, struct userrec*, char* );
