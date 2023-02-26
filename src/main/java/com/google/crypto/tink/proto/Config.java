// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/config.proto

package com.google.crypto.tink.proto;

public final class Config {
  private Config() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_google_crypto_tink_KeyTypeEntry_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_google_crypto_tink_KeyTypeEntry_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_google_crypto_tink_RegistryConfig_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_google_crypto_tink_RegistryConfig_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\022proto/config.proto\022\022google.crypto.tink" +
      "\"\212\001\n\014KeyTypeEntry\022\026\n\016primitive_name\030\001 \001(" +
      "\t\022\020\n\010type_url\030\002 \001(\t\022\033\n\023key_manager_versi" +
      "on\030\003 \001(\r\022\027\n\017new_key_allowed\030\004 \001(\010\022\026\n\016cat" +
      "alogue_name\030\005 \001(\t:\002\030\001\"Z\n\016RegistryConfig\022" +
      "\023\n\013config_name\030\001 \001(\t\022/\n\005entry\030\002 \003(\0132 .go" +
      "ogle.crypto.tink.KeyTypeEntry:\002\030\001BQ\n\034com" +
      ".google.crypto.tink.protoP\001Z/github.com/" +
      "google/tink/go/proto/config_go_protob\006pr" +
      "oto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        });
    internal_static_google_crypto_tink_KeyTypeEntry_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_google_crypto_tink_KeyTypeEntry_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_google_crypto_tink_KeyTypeEntry_descriptor,
        new java.lang.String[] { "PrimitiveName", "TypeUrl", "KeyManagerVersion", "NewKeyAllowed", "CatalogueName", });
    internal_static_google_crypto_tink_RegistryConfig_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_google_crypto_tink_RegistryConfig_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_google_crypto_tink_RegistryConfig_descriptor,
        new java.lang.String[] { "ConfigName", "Entry", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}