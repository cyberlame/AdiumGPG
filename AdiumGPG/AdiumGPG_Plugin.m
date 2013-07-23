#import <Adium/AIMenuControllerProtocol.h>
#import <Adium/AIToolbarControllerProtocol.h>
#import <Adium/AIContactControllerProtocol.h>
#import <Adium/AIPreferenceControllerProtocol.h>
#import <Adium/AIListContact.h>
#import <Adium/AIService.h>
#import <Adium/AIChat.h>
#import <Adium/AIContentMessage.h>
#import <AIUtilities/AIMenuAdditions.h>
#import <AIUtilities/AIToolbarUtilities.h>
#import <AIUtilities/AIImageAdditions.h>
#import <AIUtilities/MVMenuButton.h>

#import "AdiumGPG_Plugin.h"
#import "SelectContactKey.h"
#import "GPG_Settings.h"

#include "libpurple_gpg_plugin.h"
#include "util.h"
#include "gpg_util.h"

#define JABBER_SERVICE_ID @"libpurple-Jabber"

typedef enum {
    MenuItemTag_Context = 1,
    MenuItemTag_GPG_Chat_Enable,
    MenuItemTag_GPG_Chat_Disable
} MenuItemTag;

typedef enum {
    libpurple_status_none = 0,
    libpurple_status_enable_gpg,
    libpurple_status_enable_gpg_done,
    libpurple_status_disable_gpg,
} libpurple_status_id;

AdiumGPG_Plugin *gpg_plugin = nil;

// |info| format: 518515960E521D54 EAA9C086E7A06654 1 0
//                ^- secret keyid    ^- pub keyid
char *get_passphrase(const char *info) {
    const char *ptr = strchr(info, ' ');
    if (!ptr) return 0;
    ptr++;
    const char *ptr_last = ptr;
    if (*ptr_last) {
        ptr_last = strchr(ptr, ' ');
    }
    static const int keyid_size = sizeof("EAA9C086E7A06654")-1;
    if (ptr_last - ptr != keyid_size) {
        return 0;
    }
    gchar *keyid = g_strndup(ptr, keyid_size);
    log_write("%s\n", keyid);
    
    NSString *temp = [adium.preferenceController
                      preferenceForKey:MK_NSString(keyid) group:@"GPG"];
    g_free(keyid);
    if (!temp) {
        return 0;
    }
    if ([temp length] == 0) {
        return 0;
    }
    log_write("keyid: %s, passphrase: %s\n", keyid, MK_CSTR(temp));
    return g_strdup(MK_CSTR(temp));
}

libpurple_status_t *init_libpurple_status(const char *from, const char* to) {
    libpurple_status_t *st = g_new0(libpurple_status_t, 1);
    st->from   = jid_strip(from);
    st->to     = jid_strip(to);
    st->status = 0;
    return st;
}

void delete_libpurple_status(libpurple_status_t *st) {
    if (st->from) g_free(st->from);
    if (st->to) g_free(st->to);
    g_free(st);
}

gboolean is_encryption_enabled(const char *from, const char *to, char **fpr) {
    *fpr = 0;
    key_entry_t *head = 0;
    if (!gpg_plugin) {
        return FALSE;
    }

    gchar *temp_from = jid_strip(from);
    gchar *temp_to = jid_strip(to);
    NSString *key_id_string = [gpg_plugin getGPGKeyId:temp_from to:temp_to];
    g_free(temp_from);
    g_free(temp_to);
    if (!key_id_string) {
        return FALSE;
    }

    int keys_count = gpg_list_keys(&head);
    if (!keys_count)
        return FALSE;

    const char *jid_key_id = MK_CSTR(key_id_string);

    gboolean ret = FALSE;
    key_entry_t *key_entry = head;
    while (key_entry) {
        key_entry_t *current = key_entry;
        key_entry = key_entry->next;

        if (!*fpr) {
            if (current->key->subkeys->keyid &&
                current->key->subkeys->fpr &&
                g_str_equal(current->key->subkeys->keyid, jid_key_id))
            {
                *fpr = g_strdup(current->key->subkeys->fpr);
                ret = TRUE;
            }
        }
        gpgme_key_unref(current->key);
        g_free(current);
    }

    if (ret) {
        log_write("gpg key found for: %s\nfpr: %s, for id: %s\n",
                  to, *fpr, jid_key_id);
    } else {
        log_write("gpg key not found for: %s\n", to);
    }
    return ret;
}

void notify_message(const char *from, const char *to, gboolean encrypted) {
    if (!gpg_plugin) return;
    libpurple_status_t *st = init_libpurple_status(from, to);
    st->status = encrypted?1:0;
    [gpg_plugin notifyLibpurpleMessage:st];
}

BOOL isContactJabber(AIListObject *obj) {
    return [obj.service.serviceCodeUniqueID isEqualToString:JABBER_SERVICE_ID];
}

//------------------------------------------------------------------------------
@implementation AdiumGPG_Plugin

- (void) installPlugin {
    gboolean res = init_gpgme();
    if (!res) {
        log_write("*** init gpgme failed\n");
        return;
    }
    gpg_plugin = self;
    libpurple_status_list = 0;
    last_active_chat = nil;

    img_locked   = [[NSImage imageNamed:@"lock-locked" forClass:[self class]] retain];
    img_unlocked = [[NSImage imageNamed:@"lock-unlocked" forClass:[self class]] retain];

    [self initContextMenuItem];
    [self initToolbarItem];

    [adium.contentController registerContentFilter:self
                                            ofType:AIFilterContent
                                         direction:AIFilterIncoming];
//    [adium.chatController registerChatObserver:self];
    gpg_settings = (GPG_Settings*)[[GPG_Settings preferencePane] retain];
}

// why this not called (adium 1.5.7) ?
- (void) uninstallPlugin {
    log_write("uninstall\n");
    [(NSMutableArray*)[adium.preferenceController advancedPaneArray]
     removeObject: (AIPreferencePane*)gpg_settings];
    [gpg_settings release];
    gpg_plugin = nil;

    [self uninitToolbarItem];
    [self uninitContextMenuItem];

    [adium.contentController unregisterContentFilter:self];

    [[NSNotificationCenter defaultCenter] removeObserver:self];

    // TODO: clear GPG settings
}

- (void) installLibpurplePlugin {
    log_write("....\n");
    return;
}

- (void) loadLibpurplePlugin {
    // TODO: write purple uninit method
    purple_init_adium_gpg_plugin();
}

//------------------------------------------------------------------------------
- (void) initContextMenuItem {
    if (gpg_menuItem) {
        return;
    }
    gpg_menuItem = [[NSMenuItem alloc]
                        initWithTitle:@"GPG Select key"
                        target:self
                        action:@selector(selectContactKey:)
                        keyEquivalent:@""];

    [gpg_menuItem setEnabled:YES];
    [adium.menuController addContextualMenuItem:gpg_menuItem
                        toLocation:Context_Contact_ListAction];
}

- (void) uninitContextMenuItem {
    if (gpg_menuItem) {
        [adium.menuController removeMenuItem: gpg_menuItem];
        gpg_menuItem = nil;
    }
}

- (void) initToolbarItem {
    if (gpg_toolbar_item) {
        return;
    }

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(toolbarWillAddItem:)
                                                 name:NSToolbarWillAddItemNotification
                                               object:nil];
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(toolbarDidRemoveItem:)
                                                 name:NSToolbarDidRemoveItemNotification
                                               object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(GPG_UpdateToolbarItem:)
                                                 name:@"GPG_UpdateToolbarItem"
                                               object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(chatWillClose:)
                                                 name:Chat_WillClose
                                               object:nil];
    
    [[NSNotificationCenter defaultCenter] postNotificationName:@"GPG_UpdateToolbarIcon"
                                                        object:nil];
    MVMenuButton *button = [[[MVMenuButton alloc]
                             initWithFrame:NSMakeRect(0,0,32,32)] autorelease];
    [button setImage: img_unlocked];

    gpg_toolbar_item =
        [AIToolbarUtilities toolbarItemWithIdentifier:@"gpg_toolbar_item"
                                                label:@"GPG"
                                         paletteLabel:@"GPG"
                                              toolTip:@"gpg settings"
                                               target:self
                                      settingSelector:@selector(setView:)
                                          itemContent:button
                                               action:@selector(gpgToolbarAction:)
                                                 menu:nil];

    [gpg_toolbar_item setMinSize:NSMakeSize(32,32)];
    [gpg_toolbar_item setMaxSize:NSMakeSize(32,32)];
    [button setToolbarItem:gpg_toolbar_item];
    
    [adium.toolbarController registerToolbarItem:gpg_toolbar_item
                                  forToolbarType:@"MessageWindow"];
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(chatDidBecomeVisible:) name:@"AIChatDidBecomeVisible"
                                               object:nil];
}

- (void) uninitToolbarItem {
    if (gpg_toolbar_item) {
        [adium.toolbarController unregisterToolbarItem:gpg_toolbar_item
                                        forToolbarType:@"MessageWindow"];
        gpg_toolbar_item = nil;
        [[NSNotificationCenter defaultCenter] removeObserver:self];
    }
}

- (void) toolbarWillAddItem:(NSNotification *)notification {
    NSToolbarItem *item = [[notification userInfo] objectForKey:@"item"];
    if (![[item itemIdentifier] isEqualToString:@"gpg_toolbar_item"])
        return;
    [item setEnabled:YES];

    NSMenu *menu = [self toolbarMenu];
    [[item view] setMenu:menu];
}

- (void) GPG_UpdateToolbarItem:(NSNotification *)notification {
    AIChat *chat = last_active_chat;
    if (!chat) return;
    [self updateChatToolbarIcon:chat inWindow:[adium.interfaceController windowForChat:chat]];
}

- (void) chatWillClose:(NSNotification *)notification {
    AIChat *chat = [notification object];
    if (!chat) return;

    libpurple_status_t *st = [self findLibpurpleStatusElementByChat:chat];
    if (st) {
        libpurple_status_list = g_list_remove(libpurple_status_list, st);
        delete_libpurple_status(st);
    }
}

- (void) toolbarDidRemoveItem:(NSNotification *)notification {
    // TODO: write something here ...
}

- (void)updateChatToolbarIcon:(AIChat *)chat inWindow:(NSWindow *)window {
    log_write("update chat icon\n");
    AIListContact *contact = chat.listObject.parentContact;
    log_write("contact uid: %s\n", [contact.UID UTF8String]);

    NSToolbar *toolbar = [window toolbar];
    NSEnumerator *enumerator = [[toolbar items] objectEnumerator];
    NSToolbarItem *item;
    BOOL found = NO;

    while ((item = [enumerator nextObject])) {
        if ([[item itemIdentifier] isEqualToString:@"gpg_toolbar_item"]) {
            found = YES;
            break;
        }
    }
    if (!found) {
        return;
    }
    if (!isContactJabber(contact)) {
        [item setEnabled:NO];
        return;
    }

    int gpg_status = [[contact preferenceForKey:@"gpg_status" group:@"GPG"] intValue];
    log_write("%s - gpg_status: %d\n", [contact.UID UTF8String], gpg_status);
    if (gpg_status) {
        [(MVMenuButton *)[item view] setImage:img_locked];
    } else {
        [(MVMenuButton *)[item view] setImage:img_unlocked];
    }
}

- (void)chatDidBecomeVisible:(NSNotification *)notification {
    AIChat *chat = [notification object];
    NSWindow *chatWindow = [[notification userInfo] objectForKey:@"NSWindow"];
    last_active_chat = chat;
    [self updateChatToolbarIcon:chat inWindow:chatWindow];
}

- (void) gpgToolbarAction:(id) sender {
    log_write("selectContactKey sender: %s\n", MK_CSTR([sender className]));
}

- (NSMenu*) toolbarMenu {
    if (gpg_chat_menu) {
        return [[gpg_chat_menu copy] autorelease];
    }
    gpg_chat_menu = [[NSMenu alloc] init];
    [gpg_chat_menu setTitle:@"gpg_chat_menu"];
    
    NSMenuItem *item;

    item = [[NSMenuItem alloc] initWithTitle:@"Enable"
                                      target:self
                                      action:@selector(enableGPG:)
                               keyEquivalent:@""];
    
    [item setTag:MenuItemTag_GPG_Chat_Enable];
    [gpg_chat_menu addItem:item];
    
    item = [[NSMenuItem alloc] initWithTitle:@"Disable"
                                      target:self
                                      action:@selector(disableGPG:)
                               keyEquivalent:@""];

    [item setTag:MenuItemTag_GPG_Chat_Disable];
    [gpg_chat_menu addItem:item];
    
    item = [[NSMenuItem alloc] initWithTitle:@"Select key"
                                      target:self
                                      action:@selector(selectContactKeyChat:)
                               keyEquivalent:@""];
    
    [gpg_chat_menu addItem:item];
    
    return [[gpg_chat_menu copy] autorelease];
}

- (void) selectContactKeyChat: (id) sender {
    AIChat *chat = adium.interfaceController.activeChat;
    AIListContact *contact = chat.listObject.parentContact;
    [SelectContactKey show:contact forChat:chat];
}

- (void) selectContactKey: (id) sender {
    log_write("selectContactKey sender: %s\n", [[sender className] UTF8String]);
    AIListObject *listObject = adium.menuController.currentContextMenuObject;
    log_write("UID: %s\n", [listObject.UID UTF8String]);
    
    [SelectContactKey show:listObject forChat:nil];
}

- (void) enableGPG: (id) sender {
    AIChat *chat = adium.interfaceController.activeChat;
    AIListContact *contact = chat.listObject.parentContact;
    [contact setPreference:[NSNumber numberWithInteger:1] forKey:@"gpg_status" group:@"GPG"];
    int val = [[contact preferenceForKey:@"gpg_status" group:@"GPG"] intValue];
    log_write("+++ %s, status: %d\n", [contact.UID UTF8String], val);
    
    [self updateChatToolbarIcon:chat
                       inWindow:[adium.interfaceController windowForChat:chat]];
}

- (void) disableGPG: (id) sender {
    AIChat *chat = adium.interfaceController.activeChat;
    AIListContact *contact = chat.listObject.parentContact;
    [contact setPreference:[NSNumber numberWithInteger:0] forKey:@"gpg_status" group:@"GPG"];

    [self updateChatToolbarIcon:chat
                       inWindow:[adium.interfaceController windowForChat:chat]];
}

- (BOOL)validateMenuItem:(NSMenuItem *)menuItem {
    if ([menuItem tag] == MenuItemTag_Context) {
        AIListObject *listObject = adium.menuController.currentContextMenuObject;
        if (!isContactJabber(listObject))
            return NO;
        return YES;
    }
    log_write("validate: %s\n", MK_CSTR([menuItem title]));
//    if ([[menuItem title] isEqualToString:@"GPG Settings"]) {
//        return YES;
//    }

    if (![[menuItem.menu title] compare:@"gpg_chat_menu"]) {
        AIListContact *contact = adium.interfaceController.activeChat.listObject.parentContact;

        if (!isContactJabber(contact))
            return NO;
            
        log_write("... %s\n", [contact.UID UTF8String]);
        int gpg_status = [[contact preferenceForKey:@"gpg_status" group:@"GPG"] intValue];
        NSString *key_id = [[contact preferenceForKey:@"gpg_key_id" group:@"GPG"] string];
        if (key_id) {
            log_write("key selected: %s\n", [key_id UTF8String]);
        } else {
            log_write("*** key_id non set\n");
        }
        
        MenuItemTag tag = (MenuItemTag)[menuItem tag];
        switch (tag) {
            case MenuItemTag_GPG_Chat_Enable:
                if (gpg_status) {
                    [menuItem setState:1];
                } else {
                    [menuItem setState:0];
                }
                if (!key_id) return NO;
                break;

            case MenuItemTag_GPG_Chat_Disable:
                if (!gpg_status) {
                    [menuItem setState:1];
                } else {
                    [menuItem setState:0];
                }
                break;
                
            default:
                break;
        }
        return YES;
    }
    
    return YES;
}

-(libpurple_status_t*) findLibpurpleStatusElement: (const char *)from to:(const char *)toJid {
    GList *entry = libpurple_status_list;
    for (; entry; entry = g_list_next(entry)) {
        libpurple_status_t *st = entry->data;
        if (!st) continue;
        log_write(". %s %s\n", st->from, st->to);
        if (g_str_equal(st->from, from) &&
            g_str_equal(st->to, toJid)) {
            return st;
        }
    }
    return 0;
}

-(libpurple_status_t*) findLibpurpleStatusElementByChat: (AIChat*)chat {
    GList *entry = libpurple_status_list;
    for (; entry; entry = g_list_next(entry)) {
        libpurple_status_t *st = entry->data;
        if (!st) continue;
        if (st->chat == chat) {
            return st;
        }
    }
    return 0;
}

- (NSAttributedString *) filterAttributedString:
    (NSAttributedString *)inAttributedString context:(id)context {
    if (![context isKindOfClass:[AIContentMessage class]]) {
        return inAttributedString;
    }
    AIContentMessage *message = context;
    if (![message.destination.service.serviceCodeUniqueID
         isEqualToString:JABBER_SERVICE_ID]) {
        return inAttributedString;
    }
    int gpg_status = [[message.source preferenceForKey:@"gpg_status" group:@"GPG"] intValue];
    
    const char *from = MK_CSTR(message.source.UID);
    const char *toJid = MK_CSTR(message.destination.UID);
    log_write("filter: from: |%s| to: |%s|\n", from, toJid);

    NSString *msg = nil;
    libpurple_status_t *st = [self findLibpurpleStatusElement:from to:toJid];
    if (st) {
        st->chat = message.chat;
        log_write("st status: %d\n", st->status);
        if (st->status == libpurple_status_enable_gpg) {
            st->status = libpurple_status_enable_gpg_done;
            msg = @"[GPG] incomming messages encrypted";
            
        } else if (st->status == libpurple_status_disable_gpg) {
            st->status = libpurple_status_none;
            msg = @"[GPG] incoming messages NOT encrypted";
            
        } else if (gpg_status) {
            if (st->status == libpurple_status_none) {
                msg = @"[GPG] warning: incoming messages NOT encrypted";
            }
        }
    }

    if (msg) {
        [adium.contentController displayEvent:msg ofType:@"encryption" inChat:message.chat];
    }
    return inAttributedString;
}

- (CGFloat)filterPriority {
    return HIGHEST_FILTER_PRIORITY;
}

- (AIListContact*) getContactByJID: (NSString*)from to:(NSString*)to {
    for (AIListContact *contact in adium.contactController.allContacts) {
        if (!isContactJabber(contact)) {
            continue;
        }
        log_write("---| %s %s\n", [contact.account.UID UTF8String], [contact.UID UTF8String]);
        if (!isContactJabber(contact.account)) {
            continue;
        }

        if ([contact.account.UID isEqualToString:from] &&
            [contact.UID isEqualToString:to]) {
            return contact;
        }
    }
    return nil;
}

- (NSString*) getGPGKeyId: (const char*)from to:(const char*)to {
    AIListContact *contact = [self getContactByJID: MK_NSString(from) to:MK_NSString(to)];
    if (!contact) return nil;
    
    int gpg_status = [[contact preferenceForKey:@"gpg_status" group:@"GPG"] intValue];
    if (!gpg_status) return nil;

    NSString *key_id = [contact preferenceForKey:@"gpg_key_id" group:@"GPG"];
    return key_id;
}

- (void) notifyLibpurpleMessage: (libpurple_status_t*)st {
    libpurple_status_t *st_ = [self findLibpurpleStatusElement:st->from to:st->to];
    if (st_) {
        if (st->status) {
            // GPG on
            log_write("[+] gpg on, old status: %d\n", st_->status);
            if (st_->status != libpurple_status_enable_gpg_done) {
                st_->status = libpurple_status_enable_gpg;
            }
        } else {
            // GPG off
            log_write("[-] gpg off, old status: %d\n", st_->status);
            if (st_->status != libpurple_status_none) {
                st_->status = libpurple_status_disable_gpg;
            }
        }

        delete_libpurple_status(st);
        return;
    }

    log_write("new libpurple status element from:%s to:%s\n", st->from, st->to);
    libpurple_status_list = g_list_append(libpurple_status_list, st);
}

@end
