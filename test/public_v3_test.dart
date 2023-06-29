import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('sign', () async {
    final keyPair = await Ed25519().newKeyPair();
    const content = 'Hello World!';
    final message = await Message.signString(
      content,
      version: Version.v3,
      keyPair: keyPair,
    );
    final verifiedMessage = await message.toToken.verifyPublicMessage(
      publicKey: await keyPair.extractPublicKey(),
    );
    expect(message, verifiedMessage);
  });
}
