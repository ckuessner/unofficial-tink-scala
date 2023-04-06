package com.google.crypto.tink

import com.google.crypto.tink.aead.{AeadConfig, XChaCha20Poly1305KeyManager, XChaCha20Poly1305KeyManagerTest}
import com.google.crypto.tink.signature.{Ed25519PrivateKeyManager, SignatureConfig}
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import org.junit.Assert
import org.junit.Assert.{assertArrayEquals, assertEquals}
import org.scalatest.flatspec.AnyFlatSpecLike

import java.security.GeneralSecurityException

class UsageExamplesTest extends AnyFlatSpecLike {
  "Ed25519 Signature example" should "work" in {
    // Register Ed25519 with the registry
    SignatureConfig.register()

    // Create the key
    val privateKeysetHandle: KeysetHandle = KeysetHandle.generateNew(KeyTemplates.get("ED25519"))
    // Create the signer from the key
    val publicKeySign: PublicKeySign = privateKeysetHandle.getPrimitive(classOf[PublicKeySign])
    // Use the signer (that uses the generated key) to sign a message
    val message = "Hello World".getBytes
    val signature = publicKeySign.sign(message)

    // (optional) Get a KeysetHandle containing only the public key from the KeysetHandle containing the private key
    val publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle
    // Create the corresponding verifier from the public key
    val publicKeyVerify: PublicKeyVerify = publicKeysetHandle.getPrimitive(classOf[PublicKeyVerify])
    // Verify the signature of the message
    publicKeyVerify.verify(signature, message)

    // Should throw if signature is wrong
    {
      val wrongSignature = signature.clone()
      wrongSignature(7) = (signature(7) ^ 0x10).toByte
      assertThrows[GeneralSecurityException](publicKeyVerify.verify(wrongSignature, message))
    }

    // Should throw if message is wrong
    {
      val wrongMessage = message.clone()
      wrongMessage(7) = (wrongMessage(7) ^ 0x42).toByte
      assertThrows[GeneralSecurityException](publicKeyVerify.verify(signature, wrongMessage))
    }
  }

  "XChaCha20-Poly1305 AEAD example" should "work" in {
    // Register Ed25519 with the registry
    AeadConfig.register()

    // Create the key
    val keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("XCHACHA20_POLY1305"))

    val message = "Hello World".getBytes
    val associatedData = "42".getBytes

    // Get AEAD primitive
    val aead = keysetHandle.getPrimitive(classOf[Aead])

    // Encrypt
    val ciphertext = aead.encrypt(message, associatedData)

    // Decrypt
    val plaintext = aead.decrypt(ciphertext, associatedData)
    assertArrayEquals(message, plaintext)

    // Does not decrypt with invalid ciphertext
    {
      val wrongCiphertext = ciphertext.clone()
      wrongCiphertext(7) = (wrongCiphertext(7) ^ 1).toByte
      assertThrows[GeneralSecurityException](aead.decrypt(wrongCiphertext, associatedData))
    }

    // Does not decrypt with invalid associated data
    {
      val wrongAssociatedData = "21".getBytes
      assertThrows[GeneralSecurityException](aead.decrypt(ciphertext, wrongAssociatedData))
    }
  }

  "ChaCha20-Poly1305 AEAD example" should "work" in {
    // Register Ed25519 with the registry
    AeadConfig.register()

    // Create the key
    val keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("CHACHA20_POLY1305"))

    val message = "Hello World".getBytes
    val associatedData = "42".getBytes

    // Get AEAD primitive
    val aead = keysetHandle.getPrimitive(classOf[Aead])

    // Encrypt
    val ciphertext = aead.encrypt(message, associatedData)

    // Decrypt
    val plaintext = aead.decrypt(ciphertext, associatedData)
    assertArrayEquals(message, plaintext)

    // Does not decrypt with invalid ciphertext
    {
      val wrongCiphertext = ciphertext.clone()
      wrongCiphertext(7) = (wrongCiphertext(7) ^ 1).toByte
      assertThrows[GeneralSecurityException](aead.decrypt(wrongCiphertext, associatedData))
    }

    // Does not decrypt with invalid associated data
    {
      val wrongAssociatedData = "21".getBytes
      assertThrows[GeneralSecurityException](aead.decrypt(ciphertext, wrongAssociatedData))
    }
  }
}
