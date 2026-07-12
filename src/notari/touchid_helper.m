// notari-touchid-helper: present the Touch ID sheet, report the verdict.
// Usage: notari-touchid-helper "<reason string>"
// Exit: 0 ok, 1 cancel, 2 not available, 3 auth failed, 4 lockout, 5 timeout/other.
// Prints a one-word reason to stdout for the caller's audit log. Pattern follows
// pinentry-touchid (LAContext from a compiled native binary presents fine from
// a terminal; interpreter-hosted evaluatePolicy from python-build-standalone
// does not).
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *reason = argc > 1
            ? [NSString stringWithUTF8String:argv[1]]
            : @"release a notari-blocked tool call";
        LAContext *ctx = [[LAContext alloc] init];
        NSError *err = nil;
        if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                              error:&err]) {
            printf("not_available\n");
            return 2;
        }
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block BOOL okOut = NO;
        __block NSInteger codeOut = 0;
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:reason
                      reply:^(BOOL ok, NSError *evalErr) {
            okOut = ok;
            codeOut = evalErr ? evalErr.code : 0;
            dispatch_semaphore_signal(sema);
        }];
        // Apple's sheet self-cancels around 30s; allow 35 then call it a timeout.
        if (dispatch_semaphore_wait(sema,
                dispatch_time(DISPATCH_TIME_NOW, 35LL * NSEC_PER_SEC)) != 0) {
            printf("timeout\n");
            return 5;
        }
        if (okOut) { printf("ok\n"); return 0; }
        switch (codeOut) {
            case LAErrorUserCancel:
            case LAErrorSystemCancel:
            case LAErrorAppCancel:            printf("user_canceled\n"); return 1;
            case LAErrorBiometryLockout:      printf("lockout\n");       return 4;
            case LAErrorAuthenticationFailed: printf("auth_failed\n");   return 3;
            case LAErrorBiometryNotAvailable:
            case LAErrorBiometryNotEnrolled:
            case LAErrorNotInteractive:       printf("not_available\n"); return 2;
            default: printf("error:%ld\n", (long)codeOut);               return 5;
        }
    }
}
