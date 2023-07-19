import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

@immutable
class LocalV2 {
  static const header = Header(
    version: Version.v2,
    purpose: Purpose.local,
  );
  static const nonceLength = 24;

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
    final cipher = Xchacha20.poly1305Aead();
    final content = await cipher.decrypt(
      SecretBox(
        secretBox.cipherText,
        nonce: nonce.bytes,
        mac: Mac.empty,
      ),
      aad: token.localAADPreAuthenticationEncoding,
      secretKey: secretKey,
    );
    return Package(
      content: content.sublist(0, secretBox.cipherText.length - 16),
      footer: token.footer,
    );
  }

  static Future<Payload> encrypt(
    Package package, {
    required SecretKey secretKey,
  }) async {
    final cipher = Xchacha20.poly1305Aead();
    final preNonce = await cipher.newSecretKey();
    final fullNonce = await package.calculateNonce(preNonce: preNonce);
    final nonce = Mac(fullNonce.bytes.sublist(0, 24));
    final secretBox = await cipher.encrypt(
      package.content,
      aad: Token.preAuthenticationEncoding(
        header: header,
        payload: PayloadLocal(
          secretBox: null,
          nonce: nonce,
        ),
        footer: package.footer,
      ),
      nonce: nonce.bytes,
      secretKey: secretKey,
    );
    return PayloadLocal(
      nonce: nonce,
      secretBox: SecretBox(
        secretBox.cipherText + secretBox.mac.bytes,
        nonce: secretBox.nonce,
        mac: secretBox.mac,
      ),
    );
  }
}
