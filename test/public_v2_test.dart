import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('verify', () async {
    final publicKey = SimplePublicKey(
      decodePasetoBase64('Xq649QQaRMADs0XOWSuWj80ZHN4uqN7PfZuQ9NoqjBs'),
      type: KeyPairType.ed25519,
    );
    const tokenString =
        'v2.public.dGVzdDUInakrW3fJBz_DRfy_IrgUj2UORbb72EJ0Z-tufH0ZSUMCtij5-'
        'VsgbqoBzuNOpni5-J5CBHcVNTKVHzM79Ao';
    final token = await Token.fromString(tokenString);
    final message = await token.verifyPublicMessage(publicKey: publicKey);
    expect(message.stringContent, 'test');
  });

  test('sign', () async {
    final keyPair = await Ed25519().newKeyPair();
    const content = 'Hello World!';
    final message = await Message.signString(
      content,
      version: Version.v2,
      keyPair: keyPair,
    );
    final verifiedMessage = await message.toToken.verifyPublicMessage(
      publicKey: await keyPair.extractPublicKey(),
    );
    expect(message, verifiedMessage);
  });
}
