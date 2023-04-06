package com.google.crypto.tink.signature

import com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii
import com.google.crypto.tink.internal.{KeyParser, KeySerializer, ProtoKeySerialization, ProtoParametersSerialization}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.proto.OutputPrefixType.*
import com.google.crypto.tink.signature.Ed25519Parameters.Variant
import com.google.crypto.tink.util.{Bytes, SecretBytes}
import com.google.crypto.tink.{SecretKeyAccess, proto}
import com.google.protobuf.ByteString

import java.security.GeneralSecurityException

object Ed25519ProtoSerialization {
  private val PRIVATE_TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
  private val PRIVATE_TYPE_URL_BYTES = toBytesFromPrintableAscii(PRIVATE_TYPE_URL)
  private val PUBLIC_TYPE_URL = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
  private val PUBLIC_TYPE_URL_BYTES = toBytesFromPrintableAscii(PUBLIC_TYPE_URL)

  def toVariant(outputPrefixType: OutputPrefixType): Ed25519Parameters.Variant = outputPrefixType match
    case TINK => Variant.TINK
    case LEGACY => Variant.LEGACY
    case CRUNCHY => Variant.CRUNCHY
    case RAW => Variant.NO_PREFIX
    case _ => throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType)

  def toOutputPrefixType(variant: Variant): OutputPrefixType = variant match
    case Variant.TINK => OutputPrefixType.TINK
    case Variant.NO_PREFIX => OutputPrefixType.RAW
    case Variant.CRUNCHY => OutputPrefixType.CRUNCHY
    case Variant.LEGACY => OutputPrefixType.LEGACY

  val PUBLIC_KEY_SERIALIZER: KeySerializer[Ed25519PublicKey, ProtoKeySerialization] = KeySerializer.create(
    serializePublicKey,
    classOf[Ed25519PublicKey],
    classOf[ProtoKeySerialization]
  )

  val PRIVATE_KEY_SERIALIZER: KeySerializer[Ed25519PrivateKey, ProtoKeySerialization] = KeySerializer.create(
    serializePrivateKey,
    classOf[Ed25519PrivateKey],
    classOf[ProtoKeySerialization]
  )

  val PUBLIC_KEY_PARSER: KeyParser[ProtoKeySerialization] = KeyParser.create(
    parsePublicKey,
    PUBLIC_TYPE_URL_BYTES,
    classOf[ProtoKeySerialization]
  )

  val PRIVATE_KEY_PARSER: KeyParser[ProtoKeySerialization] = KeyParser.create(
    parsePrivateKey,
    PRIVATE_TYPE_URL_BYTES,
    classOf[ProtoKeySerialization]
  )

  def serializePublicKey(pubKey: Ed25519PublicKey, unused: SecretKeyAccess): ProtoKeySerialization = ProtoKeySerialization.create(
    PUBLIC_TYPE_URL,
    com.google.crypto.tink.proto.Ed25519PublicKey(pubKey.publicBytes),
    KeyMaterialType.ASYMMETRIC_PUBLIC,
    toOutputPrefixType(pubKey.parameters.variant),
    pubKey.idRequirementOrNull
  )

  def parsePublicKey(serialization: ProtoKeySerialization, unused: SecretKeyAccess): Ed25519PublicKey = {
    if (serialization.getTypeUrl != PUBLIC_TYPE_URL) {
      throw new IllegalArgumentException(s"Wrong type URL to parse Ed25519PublicKey: ${serialization.getTypeUrl}")
    }
    if (!serialization.getValue.isInstanceOf[com.google.crypto.tink.proto.Ed25519PublicKey]) {
      throw new IllegalArgumentException(s"Wrong proto key type while parsing Ed25519PublicKey: ${serialization.getValue.getClass}")
    }
    val outputPrefixType = serialization.getOutputPrefixType

    new Ed25519PublicKey(
      serialization.getValue.asInstanceOf[proto.Ed25519PublicKey].keyValue,
      Ed25519Parameters.create(toVariant(outputPrefixType)),
      serialization.getIdRequirementOrNull
    )
  }

  def serializePrivateKey(key: Ed25519PrivateKey, access: SecretKeyAccess): ProtoKeySerialization = ProtoKeySerialization.create(
    PRIVATE_TYPE_URL,
    com.google.crypto.tink.proto.Ed25519PrivateKey(
      ByteString.copyFrom(key.privateBytes.toByteArray(SecretKeyAccess.requireAccess(access))),
      com.google.crypto.tink.proto.Ed25519PublicKey(key.publicKey.publicBytes),
    ),
    KeyMaterialType.ASYMMETRIC_PUBLIC,
    toOutputPrefixType(key.publicKey.parameters.variant),
    key.getIdRequirementOrNull
  )

  def parsePrivateKey(serialization: ProtoKeySerialization, access: SecretKeyAccess): Ed25519PrivateKey = {
    if (serialization.getTypeUrl != PRIVATE_TYPE_URL) {
      throw new IllegalArgumentException(s"Wrong proto key type URL while parsing Ed25519PrivateKey: ${serialization.getValue.getClass}")
    }
    if (!serialization.getValue.isInstanceOf[com.google.crypto.tink.proto.Ed25519PrivateKey]) {
      throw new IllegalArgumentException(s"Wrong proto key type while parsing Ed25519PrivateKey: ${serialization.getValue.getClass}")
    }
    SecretKeyAccess.requireAccess(access)
    try {
      val protoKey = serialization.getValue.asInstanceOf[com.google.crypto.tink.proto.Ed25519PrivateKey]
      val parameters = Ed25519Parameters.create(toVariant(serialization.getOutputPrefixType))
      val parsedPubKey = new Ed25519PublicKey(protoKey.publicKey.keyValue, parameters, serialization.getIdRequirementOrNull)
      new Ed25519PrivateKey(SecretBytes.copyFrom(protoKey.keyValue.toByteArray, access), parsedPubKey)
    } catch {
      case e: Throwable => throw new GeneralSecurityException("Parsing PrivateEd25519Key failed")
    }
  }
}
