package com.google.crypto.tink.proto

import com.google.crypto.tink.proto.KeyData.{Builder, KeyMaterialType}
import com.google.protobuf.ByteString

case class KeyData(typeUrl: String, value: KeyProto, keyMaterialType: KeyMaterialType) {
  def getTypeUrl: String = typeUrl

  def getValue: KeyProto = value

  def getKeyMaterialType: KeyMaterialType = keyMaterialType

  def toBuilder: Builder = {
    new Builder(typeUrl, value, keyMaterialType)
  }
}

object KeyData {

  enum KeyMaterialType extends Enum[KeyMaterialType] {
    case UNKNOWN_KEYMATERIAL
    case SYMMETRIC
    case ASYMMETRIC_PRIVATE
    case ASYMMETRIC_PUBLIC
    case REMOTE
    case UNRECOGNIZED
  }

  class Builder(var typeUrl: String = null, var value: KeyProto = null, var keyMaterialType: KeyMaterialType = null) {
    def setTypeUrl(typeUrl: String): Builder = {
      if (typeUrl == null) throw new NullPointerException()
      this.typeUrl = typeUrl
      this
    }

    def setValue(value: KeyProto): Builder = {
      if (value == null) throw new NullPointerException()
      this.value = value
      this
    }

    def setKeyMaterialType(keyMaterialType: KeyMaterialType): Builder = {
      if (keyMaterialType == null) throw new NullPointerException()
      this.keyMaterialType = keyMaterialType
      this
    }

    def build(): KeyData = new KeyData(typeUrl, value, keyMaterialType)
  }

  def newBuilder: Builder = new Builder()

}