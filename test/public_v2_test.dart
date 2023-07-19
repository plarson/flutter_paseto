import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
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

  test('Test Vector v2-S-1', () async {
    final publicKey = SimplePublicKey(
      HEX.decode(
          '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'),
      type: KeyPairType.ed25519,
    );
    final token = await Token.fromString(
        'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjA'
        'xOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdG'
        'yJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw');
    final message = await token.verifyPublicMessage(publicKey: publicKey);
    expect(
        message.stringContent,
        '{"data":"this is a signed message",'
        '"exp":"2019-01-01T00:00:00+00:00"}');
  });

  test('Test Vector v2-S-2', () async {
    final publicKey = SimplePublicKey(
      HEX.decode(
          '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2'),
      type: KeyPairType.ed25519,
    );
    final token = await Token.fromString(
        'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi'
        'wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC'
        'R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601'
        'tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q'
        '3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');
    final message = await token.verifyPublicMessage(publicKey: publicKey);
    expect(
        message.stringContent,
        '{"data":"this is a signed message",'
        '"exp":"2019-01-01T00:00:00+00:00"}');
  });
}
