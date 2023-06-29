import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('decrypt', () async {
    final secretKey = SecretKey(
      decodePasetoBase64('EOIf5G5PXsHrm45-QV-NxEHRvyg-uw38BOIajl7slZ4'),
    );
    const tokenString =
        'v2.local.iaODL67I7c1Fvg2BCsG6TWi58Y33d4fksk0Cut9hCpvk0T-'
        'IXh5SlJPkPrjJ7cU';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.stringContent, 'Foobar!');
  });

  test('encrypt', () async {
    final secretKey = await Xchacha20.poly1305Aead().newSecretKey();
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
      version: Version.v2,
      secretKey: secretKey,
    );
    final decryptedMessage = await message.toToken.decryptLocalMessage(
      secretKey: secretKey,
    );
    expect(message.stringContent, decryptedMessage.stringContent);
  });

  test('example1', () async {
    final secretKey = SecretKey(
      HEX.decode(
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
      ),
    );
    const content =
        'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqI'
        'IhOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhf'
        'wHpGF38L7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aX'
        'ZlIEVudGVycHJpc2Vz';
    final token = await Token.fromString(content);
    final decryptedMessage =
        await token.decryptLocalMessage(secretKey: secretKey);
    expect(decryptedMessage.jsonContent, {
      'data': 'this is a signed message',
      'expires': '2019-01-01T00:00:00+00:00',
    });
    expect(
      decryptedMessage.package.stringFooter,
      'Paragon Initiative Enterprises',
    );
  });

  test('largeData', () async {
    final secretKey = SecretKey(
      HEX.decode(
        '707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f',
      ),
    );
  });
}
