
#ifdef RCT_NEW_ARCH_ENABLED
#import "RNSodiumReactNativeSpec.h"

@interface SodiumReactNative : NSObject <NativeSodiumReactNativeSpec>
#else
#import <React/RCTBridgeModule.h>

@interface SodiumReactNative : NSObject <RCTBridgeModule>
#endif

@end
