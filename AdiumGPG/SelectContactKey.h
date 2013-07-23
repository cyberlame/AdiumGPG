#import <Foundation/Foundation.h>

@class AIListObject;
@class AIChat;

@interface SelectContactKey : NSWindowController<NSTableViewDataSource, NSWindowDelegate> {
    IBOutlet NSTableView *view;
    IBOutlet NSButton *unset_key_button;
    IBOutlet NSTextField *current_key;
    NSMutableArray *data;
    NSMutableArray *data_filtered;
    AIChat *chat;
    AIListObject *list_object;
}

@property (nonatomic, retain) AIListObject *list_object;
@property (nonatomic, retain) AIChat *chat;

+ (void) show: (AIListObject*)listObject forChat:(AIChat*)chat;

- (IBAction) filter:(id)sender;
- (IBAction) selectKey:(id)sender;
@end
