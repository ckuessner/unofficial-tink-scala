package com.google.crypto.tink

import com.google.crypto.tink.aead.{ChaCha20Poly1305KeyManager, XChaCha20Poly1305KeyManager}
import com.google.crypto.tink.signature.{Ed25519PrivateKeyManager, Ed25519PublicKeyManager}

import java.security.GeneralSecurityException

object KeyTemplates {
  val templates: Map[String, KeyTemplate] = Map(
    "XCHACHA20_POLY1305_RAW" -> XChaCha20Poly1305KeyManager.rawXChaCha20Poly1305Template,
    "XCHACHA20_POLY1305" -> XChaCha20Poly1305KeyManager.xChaCha20Poly1305Template,
    "CHACHA20_POLY1305_RAW" -> ChaCha20Poly1305KeyManager.rawChaCha20Poly1305Template,
    "CHACHA20_POLY1305" -> ChaCha20Poly1305KeyManager.chaCha20Poly1305Template,
    "ED25519_RAW" -> Ed25519PrivateKeyManager.rawEd25519Template,
    "ED25519" -> Ed25519PrivateKeyManager.ed25519Template,
  )

  @throws[GeneralSecurityException]
  def get(name: String): KeyTemplate = {
    templates.get(name) match
      case Some(template) => template
      case None => throw GeneralSecurityException("cannot find key template: " + name)
  }

}