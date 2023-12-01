

package com.sodiumreactnative.jni;

public class SodiumReactNative extends SodiumReactNativeJNI {

  public final static void loadLibrary() {
    System.loadLibrary("sodium-jni");
    sodium_init();
  }
}
