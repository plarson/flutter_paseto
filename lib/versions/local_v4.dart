import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

@immutable
class LocalV4 {
  static const header = Header(
    version: Version.v4,
    purpose: Purpose.local,
  );
  static const nonceLength = 32;
  static const macLength = 32;

  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
  }) async {
    throw UnimplementedError();
  }

  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
  }) async {
    throw UnimplementedError();
  }
}

extension on SecretKey {
  static final encryptionKeyInfo = utf8.encode('paseto-encryption-key');
  static final authenticationKeyInfo = utf8.encode('paseto-auth-key-for-aead');

  Future<SymmetricSubkeysV4> deriveSubkeysV4({
    required Mac nonce,
  }) async {
    final secretKey = await extractBytes();
    final hkdf = Hkdf(
      hmac: Hmac.sha384(),
      outputLength: LocalV4.nonceLength,
    );
    final temp = await hkdf.deriveKey(
      secretKey: SecretKey([]),
      nonce: secretKey,
      info: encryptionKeyInfo + nonce.bytes,
    );
    final encryptionKey = temp.bytes.sublist(0, 32);
    final nonce2 = temp.bytes.sublist(32, 48);
    final authenticationKey = await hkdf.deriveKey(
      secretKey: SecretKey([]),
      nonce: secretKey,
      info: authenticationKeyInfo + nonce.bytes,
    );
    return SymmetricSubkeysV4(
      encryptionKey: SecretKeyData(encryptionKey),
      nonce2: SecretKeyData(nonce2),
      authenticationKey: authenticationKey,
    );
  }
}

@immutable
class SymmetricSubkeysV4 {
  const SymmetricSubkeysV4({
    required this.encryptionKey,
    required this.authenticationKey,
    required this.nonce2,
  });

  final SecretKeyData encryptionKey;
  final SecretKeyData authenticationKey;
  final SecretKeyData nonce2;
}
