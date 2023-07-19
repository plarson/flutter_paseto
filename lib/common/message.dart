import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

/// A signed or encrypted PASETO message.
@immutable
class Message extends Equatable {
  const Message({
    required this.header,
    required this.package,
    required this.payload,
  });

  /// Standard header for all PASETO messages.
  final Header header;

  /// Unencrypted package that contains the content of the message.
  final Package package;

  /// Signed or encrypted version of the package.
  final Payload payload;

  /// The string if it's a String encoded message.
  String? get stringContent {
    return package.stringContent;
  }

  /// The JSON if it's a JSON encoded message.
  Map<String, dynamic>? get jsonContent {
    return package.jsonContent;
  }

  /// Converts a message to a signed or encrypted Token for the wire.
  Token get toToken {
    return Token(
      header: header,
      payload: payload,
      footer: package.footer,
    );
  }

  /// Encrypts a message using Purpose.local.
  static Future<Message> encryptString(
    String content, {
    required Version version,
    required SecretKey secretKey,
    List<int>? footer,
  }) {
    return _encrypt(
      Package(
        content: utf8.encode(content),
        footer: footer,
      ),
      version: version,
      secretKey: secretKey,
    );
  }

  /// Signs a message using Purpose.public.
  static Future<Message> signString(
    String content, {
    required Version version,
    required KeyPair keyPair,
    List<int>? footer,
  }) {
    return _sign(
      Package(
        content: utf8.encode(content),
        footer: footer,
      ),
      version: version,
      keyPair: keyPair,
    );
  }

  static Future<Message> _encrypt(
    Package package, {
    required Version version,
    required SecretKey secretKey,
  }) async {
    switch (version) {
      case Version.v1:
        return Message(
          header: LocalV1.header,
          package: package,
          payload: await LocalV1.encrypt(
            package,
            secretKey: secretKey,
          ),
        );
      case Version.v2:
        return Message(
          header: LocalV2.header,
          package: package,
          payload: await LocalV2.encrypt(
            package,
            secretKey: secretKey,
          ),
        );
      case Version.v3:
        return Message(
          header: LocalV3.header,
          package: package,
          payload: await LocalV3.encrypt(
            package,
            secretKey: secretKey,
          ),
        );
      case Version.v4:
        return Message(
          header: LocalV4.header,
          package: package,
          payload: await LocalV4.encrypt(
            package,
            secretKey: secretKey,
          ),
        );
    }
  }

  static Future<Message> _sign(
    Package package, {
    required Version version,
    required KeyPair keyPair,
  }) async {
    switch (version) {
      case Version.v1:
        throw Exception('v1 does not support public tokens');
      case Version.v2:
        return Message(
          header: PublicV2.header,
          package: package,
          payload: await PublicV2.sign(
            package,
            keyPair: keyPair,
          ),
        );
      case Version.v3:
        return Message(
          header: PublicV3.header,
          package: package,
          payload: await PublicV3.sign(
            package,
            keyPair: keyPair,
          ),
        );
      case Version.v4:
        return Message(
          header: PublicV4.header,
          package: package,
          payload: await PublicV4.sign(
            package,
            keyPair: keyPair,
          ),
        );
    }
  }

  /// Equatable override.
  @override
  List<Object?> get props => [
        header,
        package,
      ];
}
