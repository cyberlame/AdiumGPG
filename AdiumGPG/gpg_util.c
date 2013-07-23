#include "gpg_util.h"
#include "util.h"

char *get_passphrase(const char *key_id);

gboolean init_gpgme() {
    gpgme_error_t err;
    
    gpgme_check_version(NULL);
    
    setlocale(LC_ALL, "");
    gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
    
    err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
    if (err) {
        return FALSE;
    }
    return TRUE;
}

static gpgme_error_t passphrase_cb(void *opaque, const char *uid_hint,
                            const char *passphrase_info,
                            int last_was_bad, int fd)
{
    log_write("info: %s\n", passphrase_info);
    log_write("uid: %s\n", uid_hint);
    char *passphrase = get_passphrase(passphrase_info);
    if (!passphrase) {
        if (write(fd, "\n", 1) != 1) {
            return gpgme_error_from_errno(errno);
        }
        return 0;
    }

    const char *begin = passphrase;
    size_t offset = 0;
    size_t size = strlen(begin);
    
    do {
        const char *ptr = begin + offset;
        int c = (int) write(fd, ptr, size - offset);
        if (c <= 0) break;
        offset += c;
    } while (offset < size);
    g_free(passphrase);

    if (offset != size) {
        return gpgme_error_from_errno(errno);
    }    
    if (write(fd, "\n", 1) != 1) {
        return gpgme_error_from_errno(errno);
    }
    return 0;
}

static const char k_begin_gpg_message[] = "-----BEGIN PGP MESSAGE-----\n";
static const char k_end_gpg_message[] = "\n-----END PGP MESSAGE-----";

static char *add_gpg_headers(const char *str) {
    size_t total_size = strlen(str);
    total_size += sizeof(k_begin_gpg_message)-1;
    total_size += sizeof(k_end_gpg_message)-1;
    total_size += 3;
    
    char *msg = malloc(total_size);
    strcpy(msg, k_begin_gpg_message);
    strcat(msg, "\n");
    strcat(msg, str);
    strcat(msg, k_end_gpg_message);
    strcat(msg, "\n");
    return msg;
}

static char *drop_gpg_headers(const char *str) {
    const char *end = strstr(str, k_end_gpg_message);
    const char *pos = strstr(str, k_begin_gpg_message);
    if (!pos || !end) {
        return 0;
    }
    pos = strstr(pos, "\n\n");
    if (!pos) return 0;
    pos += 2;
    if (pos >= end) return 0;
    
    size_t msg_size = end - pos;
    char *msg = malloc(msg_size + 1);
    memcpy(msg, pos, msg_size);
    msg[msg_size] = 0;
    
    return msg;
}

char *gpg_encrypt_msg(const char *msg, const char *fpr) {
    gpgme_ctx_t ctx;
    gpgme_data_t plain, cipher;
    gpgme_error_t err;
    char *temp, *str;
    char *ret = 0;
    gpgme_key_t key_arr[2] = {0, 0};
    size_t n = 0;
    
    err = gpgme_new(&ctx);
    if (err) {
        return 0;
    }
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_armor(ctx, 1);
    
    err = gpgme_get_key(ctx, fpr, &key_arr[0], 0);
    if (err) {
        gpgme_release(ctx);
        return 0;
    }
    
    err = gpgme_data_new_from_mem(&plain, msg, strlen(msg), 0);
    if (err) {
        goto end;
    }
    gpgme_data_new(&cipher);
    
    err = gpgme_op_encrypt(ctx, key_arr, GPGME_ENCRYPT_ALWAYS_TRUST, plain, cipher);
    gpgme_data_release(plain);
    if (err) {
        gpgme_data_release(cipher);
        goto end;
    }
    
    temp = gpgme_data_release_and_get_mem(cipher, &n);
    if (!temp) {
        goto end;
    }
    
    str = strndup(temp, n);
    gpgme_free(temp);
    if (!str) {
        goto end;
    }
    
    ret = drop_gpg_headers(str);
    free(str);
    
end:
    gpgme_key_unref(key_arr[0]);
    gpgme_release(ctx);
    return ret;
}

char *gpg_decrypt_msg(const char *data, long *plain_size) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    size_t n = 0;
    char *temp, *str, *msg;
    gpgme_data_t plain, cipher;
    
    msg = add_gpg_headers(data);
    if (!msg) {
        return 0;
    }
    
    err = gpgme_new(&ctx);
    if (err) {
        return 0;
    }
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_armor(ctx, 1);
//    char *p = getenv("GPG_AGENT_INFO");
//    if (p) {
//        log_write("GPG_AGENT_INFO: %s\n", p);
//    } else {
//        setenv("GPG_AGENT_INFO", "/tmp/gpg-3FhMq6/S.gpg-agent:22765:1", 1);
//        log_write("NO GPG AGENT INFO FOUND\n");
//    }
    gpgme_set_passphrase_cb(ctx, &passphrase_cb, 0);
    
    gpgme_data_new_from_mem(&cipher, msg, strlen(msg), 0);
    gpgme_data_new(&plain);
    
    err = gpgme_op_decrypt(ctx, cipher, plain);
    gpgme_decrypt_result_t res = gpgme_op_decrypt_result(ctx);
    gpgme_recipient_t recipient = res->recipients;
    while (recipient) {
        log_write(">>> recipient keyid: %s\n", recipient->keyid);
        recipient = recipient->next;
    }
    gpgme_data_release(cipher);
    free(msg);
    
    if (err) {
        log_write("gpgme_op_decrypt error: %s\n", gpgme_strerror(err));
        gpgme_data_release(plain);
        gpgme_release(ctx);
        return 0;
    }
    
    temp = gpgme_data_release_and_get_mem(plain, &n);
    if (!temp) {
        gpgme_release(ctx);
        return 0;
    }
    *plain_size = n;
    str = strndup(temp, n);
    free(temp);
    
    gpgme_release(ctx);
    return str;
}

int gpg_list_keys(key_entry_t **head) {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_keylist_mode_t mode = 0;

    *head = 0;
    err = gpgme_new(&ctx);
    if (err) {
        return 0;
    }
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_keylist_mode(ctx, mode);
    err = gpgme_op_keylist_start(ctx, 0, 0);
    if (err) {
        return 0;
    }
    
    int count = 0;
    key_entry_t *key_entry_prev = 0;
    while (1) {
        gpgme_key_t key;
        err = gpgme_op_keylist_next(ctx, &key);
        if (err) {
            break;
        }
        
        key_entry_t *key_entry = g_new(key_entry_t, 1);
        key_entry->next = 0;
        key_entry->key = key;
        
        if (key_entry_prev)
            key_entry_prev->next = key_entry;

        key_entry_prev = key_entry;
        if (!*head) *head = key_entry;
        
        ++count;
    }
    
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
    return count;
}
