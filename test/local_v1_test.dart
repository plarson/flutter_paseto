import 'package:cryptography/cryptography.dart';
import 'package:cryptography/helpers.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('decrypt', () async {
    final secretKey = SecretKey(
      HEX.decode(
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
      ),
    );
    const tokenString = 'v1.local.rElw-'
        'WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-'
        'CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_'
        'ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.stringContent, 'Love is stronger than hate or fear');
  });

  test('encrypt', () async {
    final secretKey = await AesGcm.with256bits().newSecretKey();
    const message = '''
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec
            pretium orci enim, tincidunt bibendum diam suscipit et.
            Pellentesque vel sagittis sem, vitae tempor elit. Sed non suscipit
            augue. In hac habitasse platea dictumst. Nunc consectetur et urna
            ac molestie. Nunc eleifend nisi nisl, non ornare nunc auctor sit
            amet. Sed eu sodales nibh. Etiam eros mi, molestie in nibh in,
            cursus ullamcorper augue. Duis id vestibulum nulla. Nulla in
            fermentum arcu. Nunc et nibh nec lacus pellentesque vulputate
            commodo vel sapien. Sed molestie, dui ac condimentum feugiat, magna
            risus tincidunt est, feugiat faucibus est magna at arcu. 👻
    ''';

    final encryptedMessage = await Message.encryptString(
      message,
      version: Version.v1,
      secretKey: secretKey,
    );
    final decryptedMessage = await encryptedMessage.toToken
        .decryptLocalMessage(secretKey: secretKey);
    expect(encryptedMessage, decryptedMessage);
  });

  test('encrypt large data', () async {
    final secretKey = await AesGcm.with256bits().newSecretKey();
    final message = HEX.encode(randomBytes(1 << 18));
    final encrypted = await Message.encryptString(
      message,
      version: Version.v1,
      secretKey: secretKey,
    );
    final decryptedMessage = await encrypted.toToken.decryptLocalMessage(
      secretKey: secretKey,
    );
    expect(encrypted, decryptedMessage);
  });
}
