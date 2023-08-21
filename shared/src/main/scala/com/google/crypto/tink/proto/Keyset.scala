package com.google.crypto.tink.proto

import com.google.crypto.tink.SecretKeyAccess
import com.google.crypto.tink.util.SecretBytes

import scala.collection.mutable
import scala.jdk.CollectionConverters.*

case class Keyset(primaryKeyId: Int, keys: List[Keyset.Key]) {
  def getPrimaryKeyId: Int = primaryKeyId

  def getKeyCount: Int = keys.length

  def getKey(index: Int): Keyset.Key = keys(index)

  // TODO: Change to scala collection
  def getKeyList: java.util.List[Keyset.Key] = keys.asJava

  def toBuilder: Keyset.Builder = {
    new Keyset.Builder(
      primaryKeyId,
      mutable.ListBuffer.from(keys)
    )
  }
}

object Keyset {

  class Builder(private var primaryKeyId: Int = 0,
                private val keys: mutable.ListBuffer[Keyset.Key] = mutable.ListBuffer.empty) {
    def getPrimaryKeyId: Int = primaryKeyId

    def setPrimaryKeyId(id: Int): Builder = {
      this.primaryKeyId = id
      this
    }

    def getKeyCount: Int = keys.length

    def getKeyList: List[Keyset.Key] = keys.toList

    def getKey(index: Int): Keyset.Key = keys(index)

    def addKey(keysetKey: Keyset.Key): Builder = {
      keys.addOne(keysetKey)
      this
    }

    def removeKey(index: Int): Builder = {
      keys.remove(index)
      this
    }

    def setKey(index: Int, key: Keyset.Key): Builder = {
      keys(index) = key
      this
    }

    def build: Keyset = {
      new Keyset(primaryKeyId, keys.toList)
    }
  }

  def newBuilder: Builder = new Builder()

  case class Key(keyData: KeyData, status: KeyStatusType, keyId: Int, outputPrefixType: OutputPrefixType) {
    def getKeyData: KeyData = keyData

    def hasKeyData: Boolean = keyData != null

    def getStatus: KeyStatusType = status

    def getKeyId: Int = keyId

    def getOutputPrefixType: OutputPrefixType = outputPrefixType

    def toBuilder: Key.Builder = new Key.Builder(keyData, status, keyId, outputPrefixType)
  }

  object Key {
    class Builder(private var keyData: Option[KeyData] = None,
                  private var status: Option[KeyStatusType] = None,
                  private var keyId: Int = 0,
                  private var outputPrefixType: Option[OutputPrefixType] = None) {

      def this(keyData: KeyData, keyStatusType: KeyStatusType, keyId: Int, outputPrefixType: OutputPrefixType) = {
        this(Option(keyData), Option(keyStatusType), keyId, Option(outputPrefixType))
      }

      def setKeyData(keyData: KeyData): Builder = {
        this.keyData = Option(keyData)
        this
      }

      def clearKeyData(): Builder = {
        this.keyData = None
        this
      }

      def setStatus(status: KeyStatusType): Builder = {
        this.status = Option(status)
        this
      }

      def setKeyId(keyId: Int): Builder = {
        this.keyId = keyId
        this
      }

      def setOutputPrefixType(outputPrefixType: OutputPrefixType): Builder = {
        this.outputPrefixType = Option(outputPrefixType)
        this
      }

      def build: Keyset.Key = {
        new Keyset.Key(keyData.orNull, status.get, keyId, outputPrefixType.get)
      }

    }

    def newBuilder: Builder = new Builder()
  }

}