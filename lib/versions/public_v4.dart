import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

@immutable
class PublicV4 {
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.public,
  );
  static const signatureLength = 64;

  static Future<Package> verify(
    Token token, {
    required PublicKey publicKey,
  }) async {
    final payload = token.payloadPublic;
    if (payload == null) {
      throw UnsupportedError('Invalid payload');
    }
    final isValid = await Ed25519().verify(
      token.standardPreAuthenticationEncoding,
      signature: Signature(
        payload.signature!,
        publicKey: publicKey,
      ),
    );
    if (!isValid) {
      throw Exception('Invalid signature');
    }
    return Package(
      content: payload.message,
      footer: token.footer,
    );
  }

  Uint8List extractBytesFromPrivateKey(String privateKeyString) {
    return Uint8List.fromList(utf8.encode(privateKeyString));
  }

  static Future<Payload> sign(
    Package package, {
    required KeyPair keyPair,
  }) async {
    final preAuthenticationEncoding = Token.preAuthenticationEncoding(
      header: PublicV4.header,
      payload: PayloadPublic(message: package.content),
      footer: package.footer,
      implicit: [],
    );
    final signature = await Ed25519().sign(
      preAuthenticationEncoding,
      keyPair: keyPair,
    );
    return PayloadPublic(
      message: package.content,
      signature: signature.bytes,
    );
  }
}
