package com.google.crypto.tink.proto

import com.google.crypto.tink.proto.Ed25519PrivateKey.{Builder, newBuilder}
import com.google.protobuf.ByteString


// The private key is 32 bytes of cryptographically secure random data.
// See https://tools.ietf.org/html/rfc8032#section-5.1.5.
case class Ed25519PrivateKey(keyValue: ByteString, publicKey: Ed25519PublicKey) extends PrivateKeyProto {
  def getKeyValue: ByteString = keyValue

  def getPublicKey: Ed25519PublicKey = publicKey

  def toBuilder: Builder = {
    val builder = newBuilder
    builder.publicKey = publicKey
    builder.keyValue = keyValue
    builder
  }
}

object Ed25519PrivateKey {
  class Builder {
    var keyValue: ByteString = scala.compiletime.uninitialized
    var publicKey: Ed25519PublicKey = scala.compiletime.uninitialized

    def setKeyValue(keyValue: ByteString): Builder = {
      if (keyValue == null) throw new NullPointerException()
      this.keyValue = keyValue
      this
    }

    def setPublicKey(publicKey: Ed25519PublicKey): Builder = {
      if (publicKey == null) throw new NullPointerException()
      this.publicKey = publicKey
      this
    }

    def build: Ed25519PrivateKey = {
      new Ed25519PrivateKey(keyValue, publicKey)
    }

  }

  def newBuilder: Builder = new Builder()

  val getDefaultInstance: Ed25519PrivateKey = Ed25519PrivateKey(ByteString.EMPTY, Ed25519PublicKey.getDefaultInstance)
}
