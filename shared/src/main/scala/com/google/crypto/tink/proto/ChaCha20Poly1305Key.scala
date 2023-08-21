package com.google.crypto.tink.proto

import com.google.protobuf.ByteString

case class ChaCha20Poly1305Key(keyValue: ByteString) extends KeyProto {
  def getKeyValue: ByteString = keyValue
}

object ChaCha20Poly1305Key {
  class Builder {
    private var keyValue: ByteString = ByteString.EMPTY

    def setKeyValue(keyValue: ByteString): Builder = {
      if (keyValue == null) throw new NullPointerException()
      this.keyValue = keyValue
      this
    }

    def build(): ChaCha20Poly1305Key = {
      new ChaCha20Poly1305Key(keyValue)
    }
  }

  def newBuilder: Builder = new Builder()

  val getDefaultInstance: ChaCha20Poly1305Key = new ChaCha20Poly1305Key(ByteString.EMPTY)
}
