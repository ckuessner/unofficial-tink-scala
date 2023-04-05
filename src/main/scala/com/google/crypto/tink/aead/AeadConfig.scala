package com.google.crypto.tink.aead

import java.security.GeneralSecurityException

object AeadConfig {
  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of
   * {@link com.google.crypto.tink.KeyManager} needed to handle Aead key types supported in Tink.
   *
   * @since 1.2.0
   */
  @throws[GeneralSecurityException]
  def register(): Unit = {
    AeadWrapper.register()

    ChaCha20Poly1305KeyManager.register(/*newKeyAllowed=*/ true)
    XChaCha20Poly1305KeyManager.register(/*newKeyAllowed=*/ true)
  }

}
