#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <substrate.h>
#import <dlfcn.h>

#pragma mark - HEX
static NSString *hexString(const void *data, size_t len) {
    if (!data || len == 0) return @"";
    const unsigned char *p = data;
    NSMutableString *out = [NSMutableString string];
    for (int i = 0; i < len; i++) {
        [out appendFormat:@"%02x", p[i]];
    }
    return out;
}

#pragma mark - 安全获取VC
static UIViewController *getTopVC() {
    UIWindow *window = nil;

    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *w in scene.windows) {
                if (w.isKeyWindow) {
                    window = w;
                    break;
                }
            }
        }
        if (window) break;
    }

    if (!window) return nil;

    UIViewController *root = window.rootViewController;
    if (!root) return nil;

    while (root.presentedViewController) {
        root = root.presentedViewController;
    }

    return root;
}

#pragma mark - 安全弹窗（不会崩）
static void safeAlert(NSString *msg) {

    dispatch_async(dispatch_get_main_queue(), ^{

        UIViewController *vc = getTopVC();
        if (!vc) return; // ❗关键：不强行弹

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"AES Dump"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];

        [vc presentViewController:alert animated:YES completion:nil];
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

static int dumpCount = 0;
static BOOL shown = NO;

#pragma mark - Hook
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

        if (dumpCount++ < 5) {

            NSString *msg = [NSString stringWithFormat:
                @"AES %s\n\nKEY:\n%@\n\nIV:\n%@",
                op == kCCEncrypt ? "Encrypt" : "Decrypt",
                hexString(key, keyLength),
                iv ? hexString(iv, 16) : @"NULL"
            ];

            NSLog(@"%@", msg);

            // 写文件（最稳）
            NSString *path = @"/var/mobile/aes.log";
            NSFileHandle *file = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!file) {
                [msg writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                [file seekToEndOfFile];
                [file writeData:[[msg stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
                [file closeFile];
            }

            // ❗只在 UI 准备好时弹一次
            if (!shown) {
                shown = YES;
                safeAlert(msg);
            }
        }
    }

    return orig_CCCrypt(op, alg, options, key, keyLength, iv,
                       dataIn, dataInLength,
                       dataOut, dataOutAvailable, dataOutMoved);
}

#pragma mark - 延迟 Hook（关键）
static void hookCrypto() {

    void *handle = dlopen("/usr/lib/system/libcommonCrypto.dylib", RTLD_NOW);
    if (!handle) return;

    void *sym = dlsym(handle, "CCCrypt");
    if (sym) {
        MSHookFunction(sym, (void *)hook_CCCrypt, (void **)&orig_CCCrypt);
        NSLog(@"[+] CCCrypt Hooked");
    }
}

#pragma mark - 延迟初始化（避免闪退）
__attribute__((constructor))
static void init() {

    NSLog(@"[*] AES Dump Loaded");

    // ❗延迟 3 秒再 Hook（关键）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        hookCrypto();
    });
}