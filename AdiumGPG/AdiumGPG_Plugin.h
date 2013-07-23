#import <Adium/AIPlugin.h>
#import <Adium/AIContentControllerProtocol.h>
#import <AdiumLibpurple/AILibpurplePlugin.h>

typedef struct _libpurple_status {
    gchar *from;
    gchar *to;
    int status;
    AIChat *chat;
} libpurple_status_t;

@class GPG_Settings;

@interface AdiumGPG_Plugin : AIPlugin<AILibpurplePlugin, AIContentFilter> {
@private
    NSImage *img_locked;
    NSImage *img_unlocked;
    NSMenu *gpg_chat_menu;
    AIChat *last_active_chat;
    GList *libpurple_status_list;
    GPG_Settings *gpg_settings;
    NSToolbarItem *gpg_toolbar_item;
    NSMenuItem *gpg_menuItem;
}

- (NSString*) getGPGKeyId: (const char*)from to:(const char*)to;
- (void) notifyLibpurpleMessage: (libpurple_status_t*)st;

@end
