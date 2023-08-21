package com.google.crypto.tink.signature

import com.google.crypto.tink.Key
import com.google.crypto.tink.signature.Ed25519Parameters.Variant
import com.google.crypto.tink.util.Bytes
import com.google.protobuf.ByteString

import java.nio.ByteBuffer
import java.util.Objects

private[signature] class Ed25519PublicKey(val publicBytes: ByteString,
                                          val parameters: Ed25519Parameters,
                                          val idRequirement: Option[Int]) extends SignaturePublicKey {
  override val getOutputPrefix: Bytes = {
    parameters.variant match {
      case Variant.NO_PREFIX => Bytes.copyFrom(Array.empty[Byte])
      case Variant.TINK => Bytes.copyFrom(ByteBuffer.allocate(5).put(1.toByte).putInt(idRequirement.get).array())
      case Variant.CRUNCHY => Bytes.copyFrom(ByteBuffer.allocate(5).put(0.toByte).putInt(idRequirement.get).array())
      case Variant.LEGACY => Bytes.copyFrom(ByteBuffer.allocate(5).put(0.toByte).putInt(idRequirement.get).array())
    }
  }

  override def getParameters: SignatureParameters = parameters

  override def getIdRequirement: Option[Int] = idRequirement

  override def getIdRequirementOrNull: Integer = if idRequirement.isEmpty then null else Int.box(idRequirement.get)

  override def equalsKey(other: Key): Boolean = {
    if (!other.isInstanceOf[Ed25519PublicKey]) false
    else {
      val otherKey = other.asInstanceOf[Ed25519PublicKey]
      otherKey.parameters.equals(parameters) &&
        otherKey.idRequirement == idRequirement &&
        otherKey.publicBytes == publicBytes
    }
  }
}
