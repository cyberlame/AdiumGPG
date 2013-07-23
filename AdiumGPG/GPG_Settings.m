#import <AIUtilities/AIMenuAdditions.h>
#import <Adium/AIPreferenceControllerProtocol.h>
#import "AdiumGPG_Plugin.h"
#import "GPG_Settings.h"

#include "util.h"
#include "gpg_util.h"

typedef struct _menu_key_entry_t {
    long tag;
    gpgme_key_t key;
} menu_key_entry_t;

extern AdiumGPG_Plugin *gpg_plugin;

@implementation GPG_Settings

static GPG_Settings *this_instance = nil;

+ (void) initInstance {
    if (!this_instance) {
        this_instance = (GPG_Settings*)[[GPG_Settings preferencePaneForPlugin:self] retain];
    }
}

+ (void) pluginUnloaded {
    if (!this_instance) return;
    this_instance->unloaded = YES;
}

- (void) dealloc {
    log_write("dealloc\n");
    [super dealloc];
}

- (NSString*) label {
    return @"GPG";
}

- (NSString*) nibName {
    if (unloaded) {
        return @"GPG_Settings_Unloaded";
    }
    return @"GPG_Settings";
}

- (NSImage *) image {
    return [NSImage imageNamed:@"lock-locked"];
}

- (AIPreferenceCategory) category {
    return AIPref_Advanced;
}

- (NSString *)paneIdentifier {
	return @"GPG_Settings";
}

- (void)viewDidLoad {
    log_write("did load\n");
    [self initKeys];
    [self _menuItemSelect: fisrtMenuItem];
    [super viewDidLoad];
}

- (void)viewWillClose {
    log_write("view close\n");
    [self clearSecretKeyList];
    [super viewWillClose];
}

- (void) initKeys {
    log_write(">>> init keys\n");
    popupMenu = [[NSMenu alloc] init];
    NSMenuItem *item;
    keysFprs = [[NSMutableArray alloc] init];
    fisrtMenuItem = nil;

    secret_keys_list = 0;
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_keylist_mode_t mode = 0;

    err = gpgme_new(&ctx);
    if (err) {
        return;
    }
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_keylist_mode(ctx, mode);
    err = gpgme_op_keylist_start(ctx, 0, 1);
    if (err) {
        return;
    }

    int count = 0;
    while (1) {
        gpgme_key_t key;
        err = gpgme_op_keylist_next(ctx, &key);
        if (err) {
            break;
        }
        ++count;
        if (!key->uids->uid || !key->subkeys->fpr)
            continue;

        log_write("%d: secret key: %s, %s\n", count, key->uids->uid,
                  key->subkeys->keyid);

        item = [[NSMenuItem alloc]
                initWithTitle:MK_NSString(key->uids->uid)
                target:self
                action:@selector(menuItemSelect:)
                keyEquivalent:@""];

        [item setTag:count];
        [item setEnabled:YES];
        [popupMenu addItem:item];
        if (!fisrtMenuItem) fisrtMenuItem = item;

        menu_key_entry_t *menu_key_entry = g_new(menu_key_entry_t, 1);
        menu_key_entry->tag = count;
        menu_key_entry->key = key;

        secret_keys_list = g_list_append(secret_keys_list, menu_key_entry);
    }

    [popupBn setMenu:popupMenu];

    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
}


- (void) clearSecretKeyList {
    g_list_foreach_(secret_keys_list) {
        menu_key_entry_t *key_entry = list->data;
        if (!key_entry) continue;
        gpgme_key_unref(key_entry->key);
        g_free(key_entry);
    }
    g_list_free(secret_keys_list);
    secret_keys_list = 0;
}

- (menu_key_entry_t*) findMenuKeyEntry: (long)tag {
    g_list_foreach_(secret_keys_list) {
        menu_key_entry_t *key_entry = list->data;
        if (!key_entry) continue;
        if (key_entry->tag == tag) {
            return key_entry;
        }
    }
    return 0;
}

- (BOOL) validateMenuItem:(NSMenuItem *)menuItem {
    return YES;
}

- (void) _menuItemSelect: (NSMenuItem*) item {
    log_write("select: %s\n", MK_CSTR([item title]));

    menu_key_entry_t *key_entry = [self findMenuKeyEntry: item.tag];
    if (!key_entry) return;

    NSString *passphrase = [adium.preferenceController
                            preferenceForKey:MK_NSString(key_entry->key->subkeys->keyid)
                            group:@"GPG"];
    log_write("found passphrase: %s\n", MK_CSTR(passphrase));
    if (!passphrase) passphrase = @"";

    [passphraseField setStringValue:passphrase];
    [saveStatus setStringValue:@""];
}

- (void) menuItemSelect: (id)sender {
    [self _menuItemSelect:sender];
}

- (BOOL) testPassphrase: (const char*) fpr {
    log_write("testing for: %s\n", fpr);
    const char plain[] = "test message";
    char *cipher = gpg_encrypt_msg(plain, fpr);

    long n = 0;
    char *temp = gpg_decrypt_msg(cipher, &n);
    if (!temp) {
        return NO;
    }

    if (strcmp(plain, temp)) {
        free(temp);
        return NO;
    }
    free(temp);
    return YES;
}

- (IBAction) savePasshprase:(id)sender {
    NSMenuItem *item = [popupBn selectedItem];
    if (!item) {
        log_write("item not found\n");
        return;
    }
    if (!item.tag) return;

    menu_key_entry_t *key_entry = [self findMenuKeyEntry: item.tag];
    if (!key_entry) {
        log_write("*** key entry for tag: %d not found\n", item.tag);
        return;
    }

    NSString *passphrase = [passphraseField stringValue];
    log_write("save %s passhprase: %s\n",
              key_entry->key->subkeys->keyid,
              MK_CSTR(passphrase));

    [adium.preferenceController
     setPreference:passphrase
     forKey:MK_NSString(key_entry->key->subkeys->keyid)
     group:@"GPG"];

    if (![self testPassphrase: key_entry->key->subkeys->fpr]) {
        [adium.preferenceController
         setPreference:nil
         forKey:MK_NSString(key_entry->key->subkeys->keyid)
         group:@"GPG"];
        [saveStatus setStringValue:@"FAIL"];
        return;
    }
    [saveStatus setStringValue:@"OK"];
}


- (void) windowWillClose:(NSNotification *)notification {
    log_write("will close\n");
}

@end
