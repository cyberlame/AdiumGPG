#ifndef AdiumGPG_gpg_util_h
#define AdiumGPG_gpg_util_h

typedef struct _key_entry {
    struct _key_entry *next;
    gpgme_key_t key;
} key_entry_t;

gboolean init_gpgme();
char *gpg_encrypt_msg(const char *msg, const char *fpr);
char *gpg_decrypt_msg(const char *data, long *plain_size);
int gpg_list_keys(key_entry_t **head);

#endif
