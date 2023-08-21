package com.google.crypto.tink.signature

import com.google.crypto.tink.Key
import com.google.crypto.tink.util.SecretBytes

private[signature] class Ed25519PrivateKey(val privateBytes: SecretBytes, val publicKey: Ed25519PublicKey) extends SignaturePrivateKey {

  override def getPublicKey: Ed25519PublicKey = publicKey

  override def equalsKey(other: Key): Boolean = {
    if (!other.isInstanceOf[Ed25519PrivateKey]) false
    else {
      val otherKey = other.asInstanceOf[Ed25519PrivateKey]
      otherKey.publicKey.equalsKey(getPublicKey) && privateBytes.equalsSecretBytes(otherKey.privateBytes)
    }
  }
}
