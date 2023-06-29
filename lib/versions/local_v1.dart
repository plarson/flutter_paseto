import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

extension NonceSecretBox on SecretBox {
  SecretBox withNonce(Uint8List nonce) {
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }
}

@immutable
class LocalV1 {
  static const header = Header(
    version: Version.v1,
    purpose: Purpose.local,
  );
  static const macLength = 48;
  static const nonceLength = 32;
  static const halfNonceLength = nonceLength ~/ 2;

  static Payload decodePayload(List<int> bytes) {
    final nonce = bytes.sublist(0, nonceLength);
    return PayloadLocal(
      secretBox: SecretBox.fromConcatenation(
        bytes,
        nonceLength: nonceLength,
        macLength: macLength,
      ).withNonce(Uint8List.fromList(nonce.sublist(0, halfNonceLength))),
      nonce: Mac(nonce),
      mac: Hash(bytes.sublist(bytes.length - macLength, bytes.length)),
    );
  }

  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
  }) async {
    final cipher = AesCtr.with256bits(
      macAlgorithm: Hmac.sha384(),
    );
    final preNonce = await cipher.newSecretKey();
    final nonce = await package.calculateNonce(preNonce: preNonce);
    final subkeys = await secretKey.deriveSubkeysV1(nonce: nonce);
    final secretBox = await cipher.encrypt(
      package.content,
      nonce: nonce.bytes.sublist(halfNonceLength, nonceLength),
      secretKey: subkeys.encryptionKey,
    );
    final mac = await calculateMac(
      Token.preAuthenticationEncoding(
        header: header,
        payload: PayloadLocal(
          secretBox: secretBox,
          nonce: nonce,
        ),
        footer: package.footer,
      ),
      subkeys: subkeys,
    );
    return PayloadLocal(
      nonce: nonce,
      secretBox: secretBox,
      mac: mac,
    );
  }

  static Future<Package> decrypt(
    Token token, {
    required SecretKey secretKey,
  }) async {
    final payload = token.payloadLocal;
    if (payload == null) throw UnsupportedError('Invalid payload type');
    final secretBox = payload.secretBox;
    final nonce = payload.nonce;
    final mac = payload.mac;
    if (nonce == null) {
      throw Exception('Missing nonce');
    }
    if (secretBox == null) {
      throw Exception('Missing secretBox');
    }
    final cipher = AesCtr.with256bits(
      macAlgorithm: Hmac.sha384(),
    );
    final subkeys = await secretKey.deriveSubkeysV1(
      nonce: Mac(nonce.bytes.sublist(0, halfNonceLength)),
    );
    final expectedMac = await calculateMac(
      token.standardPreAuthenticationEncoding,
      subkeys: subkeys,
    );
    if (expectedMac != mac) {
      throw ArgumentError('Invalid mac', 'message');
    }
    final content = await cipher.decrypt(
      SecretBox(
        secretBox.cipherText,
        nonce: nonce.bytes.sublist(halfNonceLength, nonceLength),
        mac: Mac.empty,
      ),
      secretKey: subkeys.encryptionKey,
    );
    return Package(
      content: content,
      footer: token.footer,
    );
  }

  static Future<Hash> calculateMac(
    Uint8List preAuthenticationEncoding, {
    required SymmetricSubkeys subkeys,
  }) async {
    final hashAlgorithm = Sha384();
    final key = List.filled(hashAlgorithm.blockLengthInBytes, 0);
    List.copyRange(
      key,
      0,
      subkeys.authenticationKey.bytes.sublist(0, nonceLength),
    );
    final opad =
        Uint8List.fromList(List.filled(hashAlgorithm.blockLengthInBytes, 0x5c));
    for (var i = 0; i < key.length; i++) {
      opad[i] = key[i] ^ opad[i];
    }
    final ipad =
        Uint8List.fromList(List.filled(hashAlgorithm.blockLengthInBytes, 0x36));
    for (var i = 0; i < key.length; i++) {
      ipad[i] = key[i] ^ ipad[i];
    }
    final hash = await hashAlgorithm
        .hash(Uint8List.fromList(ipad + preAuthenticationEncoding));
    final hash2 =
        await hashAlgorithm.hash(Uint8List.fromList(opad + hash.bytes));
    return hash2;
  }

  static Future<Signature> sign(
    List<int> preAuthenticationEncoding, {
    required KeyPair keyPair,
  }) {
    return Ed25519().sign(
      preAuthenticationEncoding,
      keyPair: keyPair,
    );
  }

  static Future<bool> verify(
    List<int> preAuthenticationEncoding, {
    required Signature signature,
  }) {
    return Ed25519().verify(
      preAuthenticationEncoding,
      signature: signature,
    );
  }
}

extension on SecretKey {
  static final encryptionKeyInfo = utf8.encode('paseto-encryption-key');
  static final authenticationKeyInfo = utf8.encode('paseto-auth-key-for-aead');

  Future<SymmetricSubkeys> deriveSubkeysV1({
    required Mac nonce,
  }) async {
    final subkeyNonce = nonce.bytes.sublist(0, LocalV1.halfNonceLength);
    final hkdf = Hkdf(
      hmac: Hmac.sha384(),
      outputLength: LocalV1.nonceLength,
    );
    final encryptionKey = await hkdf.deriveKey(
      secretKey: this,
      nonce: subkeyNonce,
      info: encryptionKeyInfo,
    );
    final authenticationKey = await hkdf.deriveKey(
      secretKey: this,
      nonce: subkeyNonce,
      info: authenticationKeyInfo,
    );
    return SymmetricSubkeys(
      encryptionKey: encryptionKey,
      authenticationKey: authenticationKey,
    );
  }
}

@immutable
class SymmetricSubkeys {
  const SymmetricSubkeys({
    required this.encryptionKey,
    required this.authenticationKey,
  });

  final SecretKeyData encryptionKey;
  final SecretKeyData authenticationKey;
}
