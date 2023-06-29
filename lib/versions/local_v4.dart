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
    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type.');
    final secretBox = payload.secretBox;
    final nonce = payload.nonce;
    if (nonce == null) {
      throw Exception('Missing nonce');
    }
    if (secretBox == null) {
      throw Exception('Missing secretBox');
    }
    final cipher = AesCtr.with256bits(
      macAlgorithm: Hmac.sha384(),
    );
    final subkeys = await secretKey.deriveSubkeysV4(nonce: nonce);
    final mac = await cipher.macAlgorithm.calculateMac(
      Token.preAuthenticationEncoding(
        header: header,
        payload: payload,
        footer: token.footer,
      ),
      secretKey: subkeys.authenticationKey,
    );
    if (Hash(mac.bytes) != payload.mac) {
      throw Exception('Invalid mac');
    }
    final content = await cipher.decrypt(
      SecretBox(
        secretBox.cipherText,
        nonce: subkeys.nonce2.bytes,
        mac: Mac.empty,
      ),
      secretKey: subkeys.encryptionKey,
    );
    return Package(
      content: content.sublist(0, content.length - mac.bytes.length),
      footer: token.footer,
    );
  }

  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
  }) async {
    final cipher = AesCtr.with256bits(
      macAlgorithm: Hmac.sha384(),
    );
    final nonceKey = await cipher.newSecretKey();
    final nonce = Mac(await nonceKey.extractBytes());
    final subkeys = await secretKey.deriveSubkeysV4(nonce: nonce);
    final secretBox = await cipher.encrypt(
      package.content,
      nonce: subkeys.nonce2.bytes,
      secretKey: subkeys.encryptionKey,
    );
    final prePayload = PayloadLocal(
      nonce: nonce,
      secretBox: SecretBox(
        secretBox.cipherText + secretBox.mac.bytes,
        nonce: secretBox.nonce,
        mac: secretBox.mac,
      ),
    );
    final mac = await cipher.macAlgorithm.calculateMac(
      Token.preAuthenticationEncoding(
        header: header,
        payload: prePayload,
        footer: package.footer,
      ),
      secretKey: subkeys.authenticationKey,
    );
    return PayloadLocal(
      nonce: prePayload.nonce,
      secretBox: prePayload.secretBox,
      mac: Hash(mac.bytes),
    );
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
