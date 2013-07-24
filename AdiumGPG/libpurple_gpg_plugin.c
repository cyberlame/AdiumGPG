#include <libpurple/plugin.h>
#include <libpurple/notify.h>
#include <libpurple/version.h>
#include <libpurple/xmlnode.h>
#include <libpurple/jabber.h>
#include "util.h"
#include "gpg_util.h"

static const char k_error_body[] =
"[ERROR: This message is encrypted, and you are unable to decrypt it.]";

// AdiumGPG_Plugin.m
gboolean is_encryption_enabled(const char *from, const char *to, char **fpr);
void notify_message(const char *from, const char *to, gboolean encrypted);

void xmlnode_clear_data(xmlnode *node) {
    xmlnode *data_node, *sibling = NULL;
    if (!node) return;

    data_node = node->child;
    while (data_node) {
        if (data_node->type != XMLNODE_TYPE_DATA) {
            sibling = data_node;
            data_node = data_node->next;
            continue;
        }
        
        if (node->lastchild == data_node) {
            node->lastchild = sibling;
        }
        if (sibling == NULL) {
            node->child = data_node->next;
            xmlnode_free(data_node);
            data_node = node->child;
        } else {
            sibling->next = data_node->next;
            xmlnode_free(data_node);
            data_node = sibling->next;
        }
    }
}

static gboolean
jabber_message_received(PurpleConnection *pc, const char *type,
                        const char *id, const char *from,
                        const char *to, xmlnode *message, gpointer data)
{
    int c = 0;
    char *temp = xmlnode_to_str(message, &c);
    if (temp) {
        log_write("[msg recv] from: %s, to: %s\nsize: %d\nmessage: %s\n", from, to, c, temp);
        g_free(temp);
    }
    
    xmlnode *body = xmlnode_get_child(message, "body");
    xmlnode *x_node = xmlnode_get_child(message, "x");
    if (!x_node) {
        log_write("x node not found\n");
        if (body) notify_message(from, to, FALSE);
        return FALSE;
    }
    char *cipher_text = xmlnode_get_data(x_node);
    if (!cipher_text) {
        return FALSE;
    }
    notify_message(from, to, TRUE);

    long n = 0;
    char *plain = gpg_decrypt_msg(cipher_text, &n);
    if (!plain) {
        return FALSE;
    }
    
    if (!body) {
        body = xmlnode_new_child(message, "body");
    } else {
        xmlnode_clear_data(body);
    }
    log_write("plain: |%s|\n", plain);

    xmlnode_free(x_node);
    xmlnode_insert_data(body, plain, n);
    return FALSE;
}

void jabber_send_signal_cb(PurpleConnection *pc, xmlnode **packet,
                           gpointer unused)
{
    if (!packet || !*packet) return;
    if (!PURPLE_CONNECTION_IS_VALID(pc)) return;

    if (g_str_equal((*packet)->name, "message")) {
        const char *from = pc->account->username;
        const char *to = xmlnode_get_attrib(*packet, "to");
        
        xmlnode *body_node = xmlnode_get_child(*packet, "body");
        if (!from || !to || !body_node) {
            return;
        }

        char *fpr = 0;
        if (!is_encryption_enabled(from, to, &fpr) || !fpr) {
            return;
        }

        const char *plain = xmlnode_get_data(body_node);
        char *cipher_text = gpg_encrypt_msg(plain, fpr);
        free(fpr);
        xmlnode_free(body_node);

        body_node = xmlnode_new("body");
        xmlnode_insert_data(body_node, k_error_body, -1);
        xmlnode_insert_child(*packet, body_node);
        
        if (cipher_text) {
            xmlnode *x_node = xmlnode_new("x");
            xmlnode_insert_data(x_node, cipher_text, -1);
            xmlnode_insert_child(*packet, x_node);
            free(cipher_text);
        }

        int n = 0;
        char *temp = xmlnode_to_str(*packet, &n);
        if (temp) {
            log_write("[msg send]: %s\n", temp);
            g_free(temp);
        }
    }
}

static gboolean plugin_load(PurplePlugin *plugin) {
    void *jabber_handle = purple_plugins_find_with_id("prpl-jabber");
    if (!jabber_handle) {
        return FALSE;
    }
    log_write("handle: %p\n", jabber_handle);
    purple_signal_connect_priority(jabber_handle, "jabber-receiving-message",
                        plugin, PURPLE_CALLBACK(jabber_message_received), 0,
                        PURPLE_SIGNAL_PRIORITY_HIGHEST);

    purple_signal_connect(jabber_handle, "jabber-sending-xmlnode",
                        plugin, PURPLE_CALLBACK(jabber_send_signal_cb), 0);

    log_write("libpurple plugin_load OK\n");
    return TRUE;
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    NULL,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,
    
    "adium-gpg",
    "GPG Encryption for Adium",
    "0.5",
    
    "adium GPG plugin",
    "adium GPG plugin",
    "cyberlame",
    "https://github.com/cyberlame",
    
    plugin_load,
    NULL,
    NULL,
    
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void init_plugin(PurplePlugin *plugin) {
    log_write("%s\n", __FUNCTION__);
}

PURPLE_INIT_PLUGIN(adium_gpg, init_plugin, info)
