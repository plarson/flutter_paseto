import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('encrypt', () async {
    final secretKey = await AesCtr.with256bits(
      macAlgorithm: Hmac.sha384(),
    ).newSecretKey();
    const content = '''
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
    final message = await Message.encryptString(
      content,
      version: Version.v3,
      secretKey: secretKey,
    );
    final decryptedMessage = await message.toToken.decryptLocalMessage(
      secretKey: secretKey,
    );
    expect(message.stringContent, decryptedMessage.stringContent);
  });
}
