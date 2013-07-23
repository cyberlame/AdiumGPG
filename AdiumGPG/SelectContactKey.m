#import <Adium/AIAdiumProtocol.h>
#import <Adium/AIPreferenceControllerProtocol.h>
#import <Adium/AIMenuControllerProtocol.h>
#import <Adium/AIContactControllerProtocol.h>
#import <Adium/AIChatControllerProtocol.h>
#import <Adium/AIListObject.h>
#import <Adium/AIListContact.h>
#import <Adium/AIService.h>
#import "SelectContactKey.h"
#import "AdiumGPG_Plugin.h"

#include "util.h"
#include "gpg_util.h"

extern AdiumGPG_Plugin *gpg_plugin;

//------------------------------------------------------------------------------
// KeyEntry
//------------------------------------------------------------------------------
@interface KeyEntry : NSObject {
@public
    NSString *key_id;
    NSString *hint;
    NSString *fpr;
}

@property (nonatomic, copy) NSString *key_id;
@property (nonatomic, copy) NSString *hint;
@property (nonatomic, copy) NSString *fpr;

@end

@implementation KeyEntry
@synthesize key_id;
@synthesize hint;
@synthesize fpr;
@end



//------------------------------------------------------------------------------
// SelectContactKey
//------------------------------------------------------------------------------
@implementation SelectContactKey

@synthesize list_object;
@synthesize chat;

static SelectContactKey *this_instance = nil;

+ (void) show: (AIListObject*)listObject forChat:(AIChat*)chat {
    if (this_instance) {
        SelectContactKey *temp = this_instance;
        this_instance = nil;
        [temp close];
        [temp release];
    }
    
    this_instance = [[SelectContactKey alloc] initWithWindowNibName:@"SelectContactKey"];
    
    this_instance.list_object = listObject;
    this_instance.chat = chat;
    [this_instance initKeyList];
    
    [this_instance showWindow:nil];
}

- (id) initWithWindow:(NSWindow *)window {
    return [super initWithWindow:window];
}

- (void) initKeyList {
    if (data) [data release];
    if (data_filtered) [data_filtered release];
    data = [[NSMutableArray alloc] init];
    
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_keylist_mode_t mode = 0;

    err = gpgme_new(&ctx);
    if (err) {
        return;
    }
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_set_keylist_mode(ctx, mode);
    err = gpgme_op_keylist_start(ctx, 0, 0);
    if (err) {
        return;
    }

    while (1) {
        gpgme_key_t key;
        err = gpgme_op_keylist_next(ctx, &key);
        if (err) {
            break;
        }

        KeyEntry *key_entry = [KeyEntry alloc];
        key_entry.key_id = MK_NSString(key->subkeys->keyid);
        key_entry.hint = MK_NSString(key->uids->uid);
        key_entry.fpr = MK_NSString(key->subkeys->fpr);

        [data addObject:key_entry];
        gpgme_key_unref(key);
    }

    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);

    data_filtered = [data mutableCopy];
}

- (void) windowDidLoad {
    [super windowDidLoad];    
    NSString *title = [@"GPG key for: " stringByAppendingString:list_object.UID];
    [[self window] setTitle:title];
    [unset_key_button setEnabled:NO];

    [self updateSelection];
}

- (void) updateSelection {
    NSString *key_id = [list_object preferenceForKey:@"gpg_key_id" group:@"GPG"];
    if (!key_id)
        return;
    [unset_key_button setEnabled:YES];

    NSIndexSet *indexes = nil;
    [current_key setStringValue:key_id];
    int idx = 0;
    for (KeyEntry *key_entry in data_filtered) {
        if (![key_entry.key_id compare:key_id]) {
            if (![view isRowSelected:idx])
                indexes = [NSIndexSet indexSetWithIndex:idx];
            break;
        }
        ++idx;
    }
    
    if (indexes)
        [view selectRowIndexes: indexes byExtendingSelection:YES];    
}

- (void) windowWillClose:(NSNotification *)notification {
    if (this_instance) {
        this_instance = nil;
        [list_object release];
        [self release];
    }
}

-(NSInteger) numberOfRowsInTableView:(NSTableView *)tableView {
    return [data_filtered count];
}

- (id) tableView:(NSTableView *)tableView
    objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row
{
    if (row > [data_filtered count]) {
        return nil;
    }
    
    KeyEntry *key_entry = [data_filtered objectAtIndex:row];
    NSString *identifier = [tableColumn identifier];
    return [key_entry valueForKey:identifier];
}

-(IBAction) filter:(id)sender {
    NSString *string = [sender stringValue];
    log_write("predicate: %s\n", [string UTF8String]);
    
    data_filtered = [data mutableCopy];
    if ([string length] > 0) {
        NSPredicate *pred = [NSPredicate predicateWithFormat:
                             @"(key_id contains[c] %@) or (hint contains[c] %@)",
                             string, string];

        [data_filtered filterUsingPredicate:pred];
    }
    [view reloadData];
}

- (IBAction) selectKey:(id)sender {
    NSInteger idx = [view selectedRow];
    log_write("selected row: %d\n", idx);
    if (idx == -1) {
        return;
    }
    KeyEntry *key_entry = [data_filtered objectAtIndex:idx];
    NSString *key_id = key_entry.key_id;
    
    [list_object setPreference:key_id forKey:@"gpg_key_id" group:@"GPG"];
    [this_instance close];
}

- (IBAction) unsetKey:(id)sender {
    [list_object setPreference:nil forKey:@"gpg_key_id" group:@"GPG"];
    [list_object setPreference:[NSNumber numberWithInt:0] forKey:@"gpg_status" group:@"GPG"];

    [[NSNotificationCenter defaultCenter] postNotificationName:@"GPG_UpdateToolbarItem" object:nil];
    [this_instance close];
}

@end
