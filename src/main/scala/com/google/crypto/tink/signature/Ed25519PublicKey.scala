package com.google.crypto.tink.signature

import com.google.crypto.tink.Key
import com.google.crypto.tink.signature.Ed25519Parameters.Variant
import com.google.crypto.tink.util.Bytes
import com.google.protobuf.ByteString

import java.nio.ByteBuffer
import java.util.Objects

private[signature] class Ed25519PublicKey(val publicBytes: ByteString, val parameters: Ed25519Parameters, val idRequirementOrNull: Integer) extends SignaturePublicKey {
  override val getOutputPrefix: Bytes = {
    parameters.variant match {
      case Variant.NO_PREFIX => Bytes.copyFrom(Array.empty[Byte])
      case Variant.TINK => Bytes.copyFrom(ByteBuffer.allocate(5).put(1.toByte).putInt(idRequirementOrNull).array())
      case Variant.CRUNCHY => Bytes.copyFrom(ByteBuffer.allocate(5).put(0.toByte).putInt(idRequirementOrNull).array())
      case Variant.LEGACY => Bytes.copyFrom(ByteBuffer.allocate(5).put(0.toByte).putInt(idRequirementOrNull).array())
    }
  }

  override def getParameters: SignatureParameters = parameters

  override def getIdRequirementOrNull: Integer = idRequirementOrNull

  override def equalsKey(other: Key): Boolean = {
    if (!other.isInstanceOf[Ed25519PublicKey]) false
    else {
      val otherKey = other.asInstanceOf[Ed25519PublicKey]
      otherKey.parameters.equals(parameters) &&
        Objects.equals(otherKey.idRequirementOrNull, idRequirementOrNull) &&
        otherKey.publicBytes == publicBytes
    }
  }
}
