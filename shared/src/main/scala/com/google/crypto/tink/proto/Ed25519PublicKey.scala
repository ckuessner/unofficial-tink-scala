package com.google.crypto.tink.proto

import com.google.protobuf.ByteString

// The public key is 32 bytes, encoded according to
// https://tools.ietf.org/html/rfc8032#section-5.1.2.
case class Ed25519PublicKey(keyValue: ByteString) extends PublicKeyProto {
  def getKeyValue: ByteString = keyValue
}

object Ed25519PublicKey {
  class Builder {
    var keyValue: ByteString = scala.compiletime.uninitialized

    def setKeyValue(keyValue: ByteString): Builder = {
      if (keyValue == null) throw new NullPointerException()
      this.keyValue = keyValue
      this
    }

    def build: Ed25519PublicKey = {
      new Ed25519PublicKey(keyValue)
    }

  }

  def newBuilder: Builder = new Builder()

  val getDefaultInstance: Ed25519PublicKey = new Ed25519PublicKey(ByteString.EMPTY)
}
