package com.google.crypto.tink.signature

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link com.google.crypto.tink.PublicKeySign} and {@link 
 * com.google.crypto.tink.PublicKeyVerify} key types supported in a particular release of Tink.
 *
 * <p>To register all PublicKeySign and PublicKeyVerify key types provided in the latest Tink
 * version one can do:
 *
 * <pre>{@code
 * SignatureConfig.init();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of PublicKeySign or PublicKeyVerify,
 * see {@link PublicKeySignFactory} or {@link PublicKeyVerifyFactory}.
 *
 * @since 1.0.0
 */
object SignatureConfig {
  val ED25519_PUBLIC_KEY_TYPE_URL: String = new Ed25519PublicKeyManager().getKeyType
  val ED25519_PRIVATE_KEY_TYPE_URL: String = new Ed25519PrivateKeyManager().getKeyType

  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances needed to handle PublicKeySign
   * and PublicKeyVerify key types supported in Tink.
   *
   * @since 1.2.0
   */
  def register(): Unit = {
    PublicKeySignWrapper.register()
    PublicKeyVerifyWrapper.register()

    Ed25519PrivateKeyManager.registerPair(/*newKeyAllowed=*/ true)
  }
}
