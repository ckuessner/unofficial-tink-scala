// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/tink.proto

package com.google.crypto.tink.proto;

public interface KeyTemplateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:google.crypto.tink.KeyTemplate)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Required. The type_url of the key type in format
   * type.googleapis.com/packagename.messagename -- see above for details.
   * This is typically the protobuf type URL of the *Key proto. In particular,
   * this is different of the protobuf type URL of the *KeyFormat proto.
   * </pre>
   *
   * <code>string type_url = 1;</code>
   * @return The typeUrl.
   */
  java.lang.String getTypeUrl();
  /**
   * <pre>
   * Required. The type_url of the key type in format
   * type.googleapis.com/packagename.messagename -- see above for details.
   * This is typically the protobuf type URL of the *Key proto. In particular,
   * this is different of the protobuf type URL of the *KeyFormat proto.
   * </pre>
   *
   * <code>string type_url = 1;</code>
   * @return The bytes for typeUrl.
   */
  com.google.protobuf.ByteString
      getTypeUrlBytes();

  /**
   * <pre>
   * Required. The serialized *KeyFormat proto.
   * </pre>
   *
   * <code>bytes value = 2;</code>
   * @return The value.
   */
  com.google.protobuf.ByteString getValue();

  /**
   * <pre>
   * Required. The type of prefix used when computing some primitives to
   * identify the ciphertext/signature, etc.
   * </pre>
   *
   * <code>.google.crypto.tink.OutputPrefixType output_prefix_type = 3;</code>
   * @return The enum numeric value on the wire for outputPrefixType.
   */
  int getOutputPrefixTypeValue();
  /**
   * <pre>
   * Required. The type of prefix used when computing some primitives to
   * identify the ciphertext/signature, etc.
   * </pre>
   *
   * <code>.google.crypto.tink.OutputPrefixType output_prefix_type = 3;</code>
   * @return The outputPrefixType.
   */
  com.google.crypto.tink.proto.OutputPrefixType getOutputPrefixType();
}
