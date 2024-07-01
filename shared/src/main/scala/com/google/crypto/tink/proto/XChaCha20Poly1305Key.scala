package com.google.crypto.tink.proto

import com.google.protobuf.ByteString

case class XChaCha20Poly1305Key(keyValue: ByteString) extends KeyProto {
  def getKeyValue: ByteString = keyValue
}

object XChaCha20Poly1305Key {
  class Builder {
    private var keyValue: ByteString = scala.compiletime.uninitialized

    def setKeyValue(keyValue: ByteString): Builder = {
      if (keyValue == null) throw NullPointerException()
      this.keyValue = keyValue
      this
    }

    def build: XChaCha20Poly1305Key = {
      new XChaCha20Poly1305Key(keyValue)
    }
  }

  def getDefaultInstance: XChaCha20Poly1305Key = {
    new XChaCha20Poly1305Key(ByteString.EMPTY)
  }
  def newBuilder: Builder = {
    new Builder()
  }
}
