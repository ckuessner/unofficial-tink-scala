// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: proto/config.proto

package com.google.crypto.tink.proto;

@java.lang.Deprecated public interface RegistryConfigOrBuilder extends
    // @@protoc_insertion_point(interface_extends:google.crypto.tink.RegistryConfig)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string config_name = 1;</code>
   * @return The configName.
   */
  java.lang.String getConfigName();
  /**
   * <code>string config_name = 1;</code>
   * @return The bytes for configName.
   */
  com.google.protobuf.ByteString
      getConfigNameBytes();

  /**
   * <code>repeated .google.crypto.tink.KeyTypeEntry entry = 2;</code>
   */
  java.util.List<com.google.crypto.tink.proto.KeyTypeEntry> 
      getEntryList();
  /**
   * <code>repeated .google.crypto.tink.KeyTypeEntry entry = 2;</code>
   */
  com.google.crypto.tink.proto.KeyTypeEntry getEntry(int index);
  /**
   * <code>repeated .google.crypto.tink.KeyTypeEntry entry = 2;</code>
   */
  int getEntryCount();
  /**
   * <code>repeated .google.crypto.tink.KeyTypeEntry entry = 2;</code>
   */
  java.util.List<? extends com.google.crypto.tink.proto.KeyTypeEntryOrBuilder> 
      getEntryOrBuilderList();
  /**
   * <code>repeated .google.crypto.tink.KeyTypeEntry entry = 2;</code>
   */
  com.google.crypto.tink.proto.KeyTypeEntryOrBuilder getEntryOrBuilder(
      int index);
}