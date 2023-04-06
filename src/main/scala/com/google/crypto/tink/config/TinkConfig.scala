package com.google.crypto.tink.config

import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.signature.SignatureConfig

import java.security.GeneralSecurityException

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of all key types supported in a particular release of Tink.
 *
 * <p>To register all key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * TinkConfig.register();
 * }
 *
 * @since 1.0.0
 */
object TinkConfig {
  /**
   * Tries to register with the {@link Registry} all instances of needed to handle all key types supported in Tink.
   *
   * @since 1.2.0
   */
  @throws[GeneralSecurityException]
  def register(): Unit = {
    AeadConfig.register()
    SignatureConfig.register()
  }
}
