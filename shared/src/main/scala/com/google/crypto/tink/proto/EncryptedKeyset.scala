package com.google.crypto.tink.proto

import com.google.protobuf.ByteString

case class EncryptedKeyset(encryptedKeyset: ByteString, keysetInfo: KeysetInfo) {
  def getEncryptedKeyset: ByteString = encryptedKeyset
}
