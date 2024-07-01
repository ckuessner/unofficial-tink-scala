package com.google.crypto.tink.proto

import com.google.protobuf.ByteString

case class KeyTemplate(typeUrl: String, outputPrefixType: OutputPrefixType) {
  def getTypeUrl: String = typeUrl

  def getOutputPrefixType: OutputPrefixType = outputPrefixType
}

object KeyTemplate {
  def newBuilder: Builder = new Builder()

  class Builder {
    var typeUrl: String = scala.compiletime.uninitialized
    var outputPrefixType: OutputPrefixType = scala.compiletime.uninitialized

    def setTypeUrl(typeUrl: String): Builder = {
      if (typeUrl == null) throw NullPointerException()
      this.typeUrl = typeUrl
      this
    }

    def setOutputPrefixType(outputPrefixType: OutputPrefixType): Builder = {
      if (outputPrefixType == null) throw NullPointerException()
      this.outputPrefixType = outputPrefixType
      this
    }

    def build: KeyTemplate = {
      new KeyTemplate(typeUrl, outputPrefixType)
    }

  }
}