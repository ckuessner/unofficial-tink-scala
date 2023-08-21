package com.google.crypto.tink.signature

import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.proto.OutputPrefixType.*
import com.google.crypto.tink.signature.Ed25519Parameters.Variant

import java.security.GeneralSecurityException

case class Ed25519Parameters(variant: Variant) extends SignatureParameters {
  override def hasIdRequirement: Boolean = variant != Variant.NO_PREFIX

  override def toKeyTemplate: KeyTemplate = {
    KeyTemplate.create(
      "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
      if (variant == Variant.NO_PREFIX) KeyTemplate.OutputPrefixType.RAW else KeyTemplate.OutputPrefixType.TINK
    )
  }
}

object Ed25519Parameters {
  def create(variant: Variant): Ed25519Parameters = {
    Ed25519Parameters(variant)
  }

  enum Variant {
    case TINK
    case NO_PREFIX
    case CRUNCHY
    case LEGACY
  }
}