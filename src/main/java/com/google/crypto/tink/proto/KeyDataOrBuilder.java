// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/tink.proto

package com.google.crypto.tink.proto;

public interface KeyDataOrBuilder extends
    // @@protoc_insertion_point(interface_extends:google.crypto.tink.KeyData)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Required.
   * </pre>
   *
   * <code>string type_url = 1;</code>
   * @return The typeUrl.
   */
  java.lang.String getTypeUrl();
  /**
   * <pre>
   * Required.
   * </pre>
   *
   * <code>string type_url = 1;</code>
   * @return The bytes for typeUrl.
   */
  com.google.protobuf.ByteString
      getTypeUrlBytes();

  /**
   * <pre>
   * Required.
   * Contains specific serialized *Key proto
   * </pre>
   *
   * <code>bytes value = 2;</code>
   * @return The value.
   */
  com.google.protobuf.ByteString getValue();

  /**
   * <pre>
   * Required.
   * </pre>
   *
   * <code>.google.crypto.tink.KeyData.KeyMaterialType key_material_type = 3;</code>
   * @return The enum numeric value on the wire for keyMaterialType.
   */
  int getKeyMaterialTypeValue();
  /**
   * <pre>
   * Required.
   * </pre>
   *
   * <code>.google.crypto.tink.KeyData.KeyMaterialType key_material_type = 3;</code>
   * @return The keyMaterialType.
   */
  com.google.crypto.tink.proto.KeyData.KeyMaterialType getKeyMaterialType();
}
