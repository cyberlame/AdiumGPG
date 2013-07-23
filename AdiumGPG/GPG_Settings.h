#import <Adium/AIAdvancedPreferencePane.h>

@interface GPG_Settings : AIAdvancedPreferencePane {
    IBOutlet NSPopUpButton *popupBn;
    IBOutlet NSSecureTextField *passphraseField;
    IBOutlet NSTextField *saveStatus;

    NSMenu *popupMenu;
    NSMenuItem *fisrtMenuItem;
    NSMutableArray *keysFprs;
    GList *secret_keys_list;
    BOOL unloaded;
}

+ (void) initInstance;
+ (void) pluginUnloaded;
- (IBAction) savePasshprase:(id)sender;

@end
