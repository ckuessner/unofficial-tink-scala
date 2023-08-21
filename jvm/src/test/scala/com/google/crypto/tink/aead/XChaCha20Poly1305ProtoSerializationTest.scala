// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package com.google.crypto.tink.aead

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.internal.{ProtoKeySerialization, ProtoParametersSerialization, SerializationRegistry}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.util.SecretBytes
import com.google.crypto.tink.{InsecureSecretKeyAccess, Key, Parameters}
import com.google.protobuf.ByteString
import org.junit.Assert.{assertThrows, assertTrue}
import org.junit.experimental.theories.{DataPoints, FromDataPoints, Theories, Theory}
import org.junit.runner.RunWith
import org.junit.{Assert, BeforeClass, Test}

import java.security.GeneralSecurityException

/** Test for XChaCha20Poly1305Serialization. */
@RunWith(classOf[Theories])
@SuppressWarnings(Array("UnnecessarilyFullyQualified")) object XChaCha20Poly1305ProtoSerializationTest {
  private val TYPE_URL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
  private val KEY_BYTES_32 = SecretBytes.randomBytes(32)
  private val KEY_BYTES_32_AS_BYTE_STRING = ByteString.copyFrom(KEY_BYTES_32.toByteArray(InsecureSecretKeyAccess.get))

  @DataPoints(Array("invalidParametersSerializations"))
  def INVALID_PARAMETERS_SERIALIZATIONS: Array[ProtoParametersSerialization] = Array[ProtoParametersSerialization](
    // Unknown output prefix
    ProtoParametersSerialization.create(TYPE_URL, OutputPrefixType.UNKNOWN_PREFIX)
  )

  //@Theory
  //public void testParseInvalidParameters_fails(
  //    @FromDataPoints("invalidParametersSerializations")
  //        ProtoParametersSerialization serializedParameters)
  //    throws Exception {
  //  assertThrows(
  //      GeneralSecurityException.class, () -> SerializationRegistry.parseParameters(serializedParameters));
  //}
  private def createInvalidKeySerializations = try Array[ProtoKeySerialization](
    //// Bad Version Number (1)
    //ProtoKeySerialization.create(
    //    TYPE_URL,
    //    com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder()
    //        .setKeyValue(KEY_BYTES_32_AS_BYTE_STRING)
    //        .build(),
    //    KeyMaterialType.SYMMETRIC,
    //    OutputPrefixType.TINK,
    //    1479),
    // Unknown prefix
    ProtoKeySerialization.create(TYPE_URL, com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(KEY_BYTES_32_AS_BYTE_STRING).build, KeyMaterialType.SYMMETRIC, OutputPrefixType.UNKNOWN_PREFIX, 1479), // Bad Key Length
    ProtoKeySerialization.create(TYPE_URL, com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(new Array[Byte](16))).build, KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK, 1479))
  catch {
    case e: GeneralSecurityException =>
      throw new RuntimeException(e)
  }

  @DataPoints(Array("invalidKeySerializations")) def INVALID_KEY_SERIALIZATIONS: Array[ProtoKeySerialization] = createInvalidKeySerializations
}

@RunWith(classOf[Theories])
@SuppressWarnings(Array("UnnecessarilyFullyQualified"))
final class XChaCha20Poly1305ProtoSerializationTest {
  //@BeforeClass
  //public static void setUp() throws Exception {
  //  XChaCha20Poly1305ProtoSerialization.register(registry);
  //}
  //@Test
  //public void registerTwice() throws Exception {
  //  MutableSerializationRegistry registry = new MutableSerializationRegistry();
  //  XChaCha20Poly1305ProtoSerialization.register(registry);
  //  XChaCha20Poly1305ProtoSerialization.register(registry);
  //}
  //@Test
  //public void serializeParseParameters_noPrefix() throws Exception {
  //  XChaCha20Poly1305Parameters parameters = XChaCha20Poly1305Parameters.create();
  //  ProtoParametersSerialization serialization =
  //      ProtoParametersSerialization.create(
  //          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
  //          OutputPrefixType.RAW,
  //          com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());
  //  ProtoParametersSerialization serialized =
  //      registry.serializeParameters(parameters, ProtoParametersSerialization.class);
  //  assertEqualWhenValueParsed(
  //      com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
  //      serialized,
  //      serialization);
  //  Parameters parsed = registry.parseParameters(serialization);
  //  assertThat(parsed).isEqualTo(parameters);
  //}
  //@Test
  //public void serializeParseParameters_tink() throws Exception {
  //  XChaCha20Poly1305Parameters parameters =
  //      XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.TINK);
  //  ProtoParametersSerialization serialization =
  //      ProtoParametersSerialization.create(
  //          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
  //          OutputPrefixType.TINK,
  //          com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());
  //  ProtoParametersSerialization serialized =
  //      registry.serializeParameters(parameters, ProtoParametersSerialization.class);
  //  assertEqualWhenValueParsed(
  //      com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
  //      serialized,
  //      serialization);
  //  Parameters parsed = registry.parseParameters(serialization);
  //  assertThat(parsed).isEqualTo(parameters);
  //}
  //@Test
  //public void serializeParseParameters_crunchy() throws Exception {
  //  XChaCha20Poly1305Parameters parameters =
  //      XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY);
  //  ProtoParametersSerialization serialization =
  //      ProtoParametersSerialization.create(
  //          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
  //          OutputPrefixType.CRUNCHY,
  //          com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.getDefaultInstance());
  //  ProtoParametersSerialization serialized =
  //      registry.serializeParameters(parameters, ProtoParametersSerialization.class);
  //  assertEqualWhenValueParsed(
  //      com.google.crypto.tink.proto.XChaCha20Poly1305KeyFormat.parser(),
  //      serialized,
  //      serialization);
  //  Parameters parsed = registry.parseParameters(serialization);
  //  assertThat(parsed).isEqualTo(parameters);
  //}
  @Test
  @throws[Exception]
  def serializeParseKey_tink(): Unit = {
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.TINK, XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32, 123)
    val protoXChaCha20Poly1305Key = com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32_AS_BYTE_STRING).build
    val serialization = ProtoKeySerialization.create("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", protoXChaCha20Poly1305Key, KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK, /* idRequirement= */ 123)
    val serialized = SerializationRegistry.serializeKey(key, classOf[ProtoKeySerialization], InsecureSecretKeyAccess.get)
    //assertEqualWhenValueParsed(
    //    com.google.crypto.tink.proto.XChaCha20Poly1305Key.parser(), serialized, serialization);
    val parsed = SerializationRegistry.parseKey(serialization, InsecureSecretKeyAccess.get)
    assertTrue(parsed.equalsKey(key))
  }

  @Test
  @throws[Exception]
  def serializeParseKey_crunchy(): Unit = {
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305Parameters.Variant.CRUNCHY, XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32, 123)
    val protoXChaCha20Poly1305Key = com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32_AS_BYTE_STRING).build
    val serialization = ProtoKeySerialization.create("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", protoXChaCha20Poly1305Key, KeyMaterialType.SYMMETRIC, OutputPrefixType.CRUNCHY, /* idRequirement= */ 123)
    val serialized = SerializationRegistry.serializeKey(key, classOf[ProtoKeySerialization], InsecureSecretKeyAccess.get)
    //assertEqualWhenValueParsed(
    //    com.google.crypto.tink.proto.XChaCha20Poly1305Key.parser(), serialized, serialization);
    val parsed = SerializationRegistry.parseKey(serialization, InsecureSecretKeyAccess.get)
    assertTrue(parsed.equalsKey(key))
  }

  @Test
  @throws[Exception]
  def testParseKeys_noAccess_throws(): Unit = {
    val protoXChaCha20Poly1305Key = com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32_AS_BYTE_STRING).build
    val serialization = ProtoKeySerialization.create("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", protoXChaCha20Poly1305Key, KeyMaterialType.SYMMETRIC, OutputPrefixType.TINK, /* idRequirement= */ 123)
    assertThrows(classOf[GeneralSecurityException], () => SerializationRegistry.parseKey(serialization, null))
  }

  @Test
  @throws[Exception]
  def parseKey_legacy(): Unit = {
    val serialization = ProtoKeySerialization.create(XChaCha20Poly1305ProtoSerializationTest.TYPE_URL, com.google.crypto.tink.proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32_AS_BYTE_STRING).build, KeyMaterialType.SYMMETRIC, OutputPrefixType.LEGACY, 1479)
    // Legacy keys are parsed to crunchy
    val parsed = SerializationRegistry.parseKey(serialization, InsecureSecretKeyAccess.get)
    assertThat(parsed.getParameters.asInstanceOf[XChaCha20Poly1305Parameters].getVariant).isEqualTo(XChaCha20Poly1305Parameters.Variant.CRUNCHY)
  }

  @Test
  @throws[Exception]
  def testSerializeKeys_noAccess_throws(): Unit = {
    val key = XChaCha20Poly1305Key.create(XChaCha20Poly1305ProtoSerializationTest.KEY_BYTES_32)
    assertThrows(classOf[GeneralSecurityException], () => SerializationRegistry.serializeKey(key, classOf[ProtoKeySerialization], null))
  }

  @Theory
  @throws[Exception]
  def testParseInvalidKeys_throws(@FromDataPoints("invalidKeySerializations") serialization: ProtoKeySerialization): Unit = {
    assertThrows(classOf[GeneralSecurityException], () => SerializationRegistry.parseKey(serialization, InsecureSecretKeyAccess.get))
  }
}