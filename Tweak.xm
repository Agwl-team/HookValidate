#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <substrate.h>
#import <dlfcn.h>

#pragma mark - HEX工具
static NSString *hexString(const void *data, size_t len) {
    if (!data || len == 0) return @"";
    const unsigned char *p = (const unsigned char *)data;
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < len; i++) {
        [out appendFormat:@"%02x", p[i]];
    }
    return out;
}

#pragma mark - 获取当前可用窗口（兼容 iOS 13+）
static UIWindow *getKeyWindow() {
    UIApplication *app = [UIApplication sharedApplication];

    for (UIWindowScene *scene in app.connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *window in scene.windows) {
                if (window.isKeyWindow) {
                    return window;
                }
            }
        }
    }
    return nil;
}

#pragma mark - 弹窗
static void showAlert(NSString *title, NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{

        UIWindow *window = getKeyWindow();
        if (!window) return;

        UIViewController *root = window.rootViewController;
        if (!root) return;

        while (root.presentedViewController) {
            root = root.presentedViewController;
        }

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];

        [root presentViewController:alert animated:YES completion:nil];
    });
}

#pragma mark - 原函数
static CCCryptorStatus (*orig_CCCrypt)(
    CCOperation op,
    CCAlgorithm alg,
    CCOptions options,
    const void *key,
    size_t keyLength,
    const void *iv,
    const void *dataIn,
    size_t dataInLength,
    void *dataOut,
    size_t dataOutAvailable,
    size_t *dataOutMoved
);

#pragma mark - 限流控制
static int dumpCount = 0;
static BOOL alertShown = NO;

#pragma mark - Hook函数
CCCryptorStatus hook_CCCrypt(
    CCOperation op,
    CCAlgorithm alg,
    CCOptions options,
    const void *key,
    size_t keyLength,
    const void *iv,
    const void *dataIn,
    size_t dataInLength,
    void *dataOut,
    size_t dataOutAvailable,
    size_t *dataOutMoved
) {

    if (alg == kCCAlgorithmAES) {

        // 限制最多打印 10 次（防止卡死）
        if (dumpCount++ < 10) {

            NSString *type = (op == kCCEncrypt) ? @"Encrypt" : @"Decrypt";
            NSString *keyHex = hexString(key, keyLength);
            NSString *ivHex  = iv ? hexString(iv, 16) : @"NULL";

            NSString *msg = [NSString stringWithFormat:
                @"AES %@\n\nKEY:\n%@\n\nIV:\n%@",
                type, keyHex, ivHex
            ];

            NSLog(@"%@", msg);

            // 写文件
            NSString *path = @"/var/mobile/aes_dump.log";
            NSString *old = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
            NSString *newLog = old ? [old stringByAppendingFormat:@"\n%@\n", msg] : msg;
            [newLog writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];

            // 只弹一次
            if (!alertShown) {
                alertShown = YES;
                showAlert(@"AES Dump", msg);
            }
        }
    }

    return orig_CCCrypt(op, alg, options, key, keyLength, iv,
                       dataIn, dataInLength,
                       dataOut, dataOutAvailable, dataOutMoved);
}

#pragma mark - 初始化
__attribute__((constructor))
static void init() {

    NSLog(@"[*] AES Dump dylib Loaded");

    void *handle = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW);

    if (!handle) {
        NSLog(@"[-] Failed to load CommonCrypto");
        return;
    }

    void *cccrypt = dlsym(handle, "CCCrypt");

    if (cccrypt) {
        MSHookFunction(cccrypt, (void *)hook_CCCrypt, (void **)&orig_CCCrypt);
        NSLog(@"[+] Hook CCCrypt success");
    } else {
        NSLog(@"[-] CCCrypt not found");
    }
}