// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/chacha20_poly1305.proto

package com.google.crypto.tink.proto;

public final class Chacha20Poly1305 {
  private Chacha20Poly1305() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_google_crypto_tink_ChaCha20Poly1305KeyFormat_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_google_crypto_tink_ChaCha20Poly1305KeyFormat_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_google_crypto_tink_ChaCha20Poly1305Key_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_google_crypto_tink_ChaCha20Poly1305Key_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\035proto/chacha20_poly1305.proto\022\022google." +
      "crypto.tink\"\033\n\031ChaCha20Poly1305KeyFormat" +
      "\"9\n\023ChaCha20Poly1305Key\022\017\n\007version\030\001 \001(\r" +
      "\022\021\n\tkey_value\030\002 \001(\014B\\\n\034com.google.crypto" +
      ".tink.protoP\001Z:github.com/google/tink/go" +
      "/proto/chacha20_poly1305_go_protob\006proto" +
      "3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_google_crypto_tink_ChaCha20Poly1305KeyFormat_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_google_crypto_tink_ChaCha20Poly1305KeyFormat_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_google_crypto_tink_ChaCha20Poly1305KeyFormat_descriptor,
        new java.lang.String[] { });
    internal_static_google_crypto_tink_ChaCha20Poly1305Key_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_google_crypto_tink_ChaCha20Poly1305Key_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_google_crypto_tink_ChaCha20Poly1305Key_descriptor,
        new java.lang.String[] { "Version", "KeyValue", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}