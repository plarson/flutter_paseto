import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

@immutable
class Token extends Equatable {
  const Token({
    required this.header,
    required this.payload,
    required this.footer,
  });

  final Header header;
  final Payload payload;
  final List<int>? footer;

  PayloadLocal? get payloadLocal {
    return payload as PayloadLocal;
  }

  PayloadPublic? get payloadPublic {
    return payload as PayloadPublic;
  }

  String get toTokenString {
    var tokenString = header.toTokenString + payload.toTokenString;
    final footer = this.footer;
    if (footer != null && footer.isNotEmpty) {
      tokenString += '.${encodePasetoBase64(footer)}';
    }
    return tokenString;
  }

  Future<Message> decryptLocalMessage({
    required SecretKey secretKey,
  }) async {
    if (header.purpose != Purpose.local) {
      throw UnsupportedError('Unable to decrypt non-local message');
    }
    return Message(
      header: header,
      package: await _decryptPackage(secretKey: secretKey),
      payload: payload,
    );
  }

  Future<Package> _decryptPackage({
    required SecretKey secretKey,
  }) async {
    switch (header.version) {
      case Version.v1:
        return LocalV1.decrypt(
          this,
          secretKey: secretKey,
        );
      case Version.v2:
        return LocalV2.decrypt(
          this,
          secretKey: secretKey,
        );
      case Version.v3:
        return LocalV3.decrypt(
          this,
          secretKey: secretKey,
        );
      case Version.v4:
        throw UnsupportedError('Unsupported version');
    }
  }

  Future<Message> verifyPublicMessage({
    required PublicKey publicKey,
  }) async {
    if (header.purpose != Purpose.public) {
      throw UnsupportedError('Unable to verify non-public message');
    }
    return Message(
      header: header,
      package: await _verifyPackage(publicKey: publicKey),
      payload: payload,
    );
  }

  Future<Package> _verifyPackage({
    required PublicKey publicKey,
  }) async {
    switch (header.version) {
      case Version.v1:
        throw UnsupportedError('v1 does not support public messages.');
      case Version.v2:
        return PublicV2.verify(
          this,
          publicKey: publicKey,
        );
      case Version.v3:
        return PublicV3.verify(
          this,
          publicKey: publicKey,
        );
      case Version.v4:
        throw UnsupportedError('Unsupported version');
    }
  }

  static Future<Token> fromString(String string) async {
    final components = string.split('.');
    if (components.length < 3) {
      throw ArgumentError('Invalid token string', 'string');
    }
    final header = Header(
      version: Version.values.byName(components.first),
      purpose: Purpose.values.byName(components[1]),
    );
    return Token(
      header: header,
      payload: decodePayload(components[2], header: header),
      footer: components.length > 3 ? decodePasetoBase64(components[3]) : null,
    );
  }

  static Payload decodePayload(
    String string, {
    required Header header,
  }) {
    final bytes = decodePasetoBase64(string);
    switch (header.version) {
      case Version.v1:
        return decodePayloadFromBytes(
          bytes,
          nonceLength: LocalV1.nonceLength,
          macLength: LocalV1.macLength,
        );
      case Version.v2:
        switch (header.purpose) {
          case Purpose.local:
            final nonce = bytes.sublist(0, LocalV2.nonceLength);
            final cipherText = bytes.sublist(LocalV2.nonceLength, bytes.length);
            return PayloadLocal(
              secretBox: SecretBox(
                cipherText,
                nonce: nonce,
                mac: Mac.empty,
              ),
              nonce: Mac(nonce),
            );
          case Purpose.public:
            return PayloadPublic(
              message:
                  bytes.sublist(0, bytes.length - PublicV2.signatureLength),
              signature: bytes.sublist(
                bytes.length - PublicV2.signatureLength,
                bytes.length,
              ),
            );
        }
      case Version.v3:
        switch (header.purpose) {
          case Purpose.local:
            final nonce = bytes.sublist(0, LocalV2.nonceLength);
            final cipherText = bytes.sublist(LocalV2.nonceLength, bytes.length);
            return PayloadLocal(
              secretBox: SecretBox(
                cipherText,
                nonce: nonce,
                mac: Mac.empty,
              ),
              nonce: Mac(nonce),
            );
          case Purpose.public:
            return PayloadPublic(
              message:
                  bytes.sublist(0, bytes.length - PublicV2.signatureLength),
              signature: bytes.sublist(
                bytes.length - PublicV2.signatureLength,
                bytes.length,
              ),
            );
        }
      case Version.v4:
        throw UnimplementedError();
    }
  }

  static Payload decodePayloadFromBytes(
    List<int> bytes, {
    required int nonceLength,
    required int macLength,
  }) {
    final nonce = bytes.sublist(0, nonceLength);
    return PayloadLocal(
      secretBox: SecretBox.fromConcatenation(
        bytes,
        nonceLength: nonceLength,
        macLength: macLength,
      ).withNonce(Uint8List.fromList(nonce.sublist(0, nonceLength ~/ 2))),
      nonce: Mac(nonce),
      mac: Hash(bytes.sublist(bytes.length - macLength, bytes.length)),
    );
  }

  Uint8List get standardPreAuthenticationEncoding {
    return preAuthenticationEncoding(
      header: header,
      payload: payload,
      footer: footer,
      implicit: header.version == Version.v4 ? [] : null,
    );
  }

  Uint8List get localAADPreAuthenticationEncoding {
    final payload = payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload.');
    final nonce = payload.nonce;
    if (nonce == null) throw UnsupportedError('Missing nonce.');
    return preAuthenticationEncoding(
      header: header,
      payload: PayloadLocal(
        secretBox: null,
        nonce: nonce,
      ),
      footer: footer,
    );
  }

  static Uint8List preAuthenticationEncoding({
    required Header header,
    required Payload payload,
    List<int>? footer,
    List<int>? implicit,
  }) {
    final components = [
      Uint8List.fromList(header.bytes),
    ];
    if (payload is PayloadLocal) {
      final nonce = payload.nonce;
      if (nonce != null) {
        components.add(Uint8List.fromList(nonce.bytes));
      }
      final secretBox = payload.secretBox;
      if (secretBox != null) {
        components.add(Uint8List.fromList(secretBox.cipherText));
      }
    } else if (payload is PayloadPublic) {
      components.add(Uint8List.fromList(payload.message));
    }
    if (footer != null) {
      components.add(Uint8List.fromList(footer));
    } else {
      components.add(Uint8List(0));
    }
    if (implicit != null) {
      components.add(Uint8List.fromList(implicit));
    }
    return _preAuthenticationEncoding(components);
  }

  static Uint8List _preAuthenticationEncoding(List<Uint8List> components) {
    return Uint8List.fromList(
      _componentLengthToByteData(components.length) +
          components.fold(
            Uint8List.fromList(<int>[]),
            (previousValue, element) =>
                previousValue +
                _componentLengthToByteData(element.length) +
                element,
          ),
    );
  }

  static Uint8List _componentLengthToByteData(int value) {
    return _componentLengthBigIntToByteData(BigInt.from(value));
  }

  static Uint8List _componentLengthBigIntToByteData(BigInt bigInt) {
    var value = bigInt.toUnsigned(64);
    var str = '';
    for (var i = 0; i < 8; i++) {
      if (i == 7) {
        value = value & BigInt.from(127).toUnsigned(64);
      }
      str += String.fromCharCode(
        (value & BigInt.from(255).toUnsigned(64)).toInt(),
      );
      value = value >> 8;
    }
    return Uint8List.fromList(utf8.encode(str));
  }

  @override
  List<Object?> get props => [
        header,
        payload,
        footer,
      ];
}
