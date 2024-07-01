package com.google.crypto.tink.proto

import com.google.crypto.tink.proto.KeysetInfo.KeyInfo

import scala.collection.mutable

case class KeysetInfo(primaryKeyId: Int, keyInfo: List[KeyInfo]) {
  def getPrimaryKeyId: Int = primaryKeyId

  def getKeyInfo(keyId: Int): KeyInfo = keyInfo(keyId)
}

object KeysetInfo {
  class Builder {
    var primaryKeyId: Int = -1
    var keyInfo: mutable.ListBuffer[KeyInfo] = mutable.ListBuffer.empty

    def setPrimaryKeyId(primaryKeyId: Int): Builder = {
      this.primaryKeyId = primaryKeyId
      this
    }

    def addKeyInfo(keyInfo: KeyInfo): Builder = {
      this.keyInfo.addOne(keyInfo)
      this
    }

    def build(): KeysetInfo = {
      new KeysetInfo(primaryKeyId, keyInfo.toList)
    }
  }

  def newBuilder: Builder = new Builder()

  case class KeyInfo(typeUrl: String, status: KeyStatusType, keyId: Int, outputPrefixType: OutputPrefixType) {
    def getTypeUrl: String = typeUrl

    def getStatus: KeyStatusType = status

    def getKeyId: Int = keyId

    def getOutputPrefixType: OutputPrefixType = outputPrefixType
  }

  object KeyInfo {
    class Builder {
      var typeUrl: String = scala.compiletime.uninitialized
      var status: KeyStatusType = scala.compiletime.uninitialized
      var keyId: Int = -1
      var outputPrefixType: OutputPrefixType = scala.compiletime.uninitialized

      def setTypeUrl(typeUrl: String): Builder = {
        this.typeUrl = typeUrl
        this
      }

      def setStatus(status: KeyStatusType): Builder = {
        this.status = status
        this
      }

      def setKeyId(keyId: Int): Builder = {
        this.keyId = keyId
        this
      }

      def setOutputPrefixType(outputPrefixType: OutputPrefixType): Builder = {
        this.outputPrefixType = outputPrefixType
        this
      }

      def build(): KeyInfo = {
        new KeyInfo(typeUrl, status, keyId, outputPrefixType)
      }
    }

    def newBuilder: Builder = new Builder()

  }

}