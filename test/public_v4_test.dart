import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('verify', () async {
    const encodedPublicKey =
        '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2';
    final publicKey = SimplePublicKey(
      HEX.decode(encodedPublicKey),
      type: KeyPairType.ed25519,
    );
    final token = await Token.fromString(
        'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAy'
        'Mi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0Dt'
        'wQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCU'
        'DlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9');
    final message = await token.verifyPublicMessage(publicKey: publicKey);
    expect(
        message.stringContent,
        // ignore: missing_whitespace_between_adjacent_strings
        '{"data":"this is a signed message",'
        '"exp":"2022-01-01T00:00:00+00:00"}');
  });

  test('Test Vector v4-S-2', () async {
    const encodedPublicKey =
        '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2';
    final publicKey = SimplePublicKey(
      HEX.decode(encodedPublicKey),
      type: KeyPairType.ed25519,
    );
    final token = await Token.fromString(
      'v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi'
      '0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxV'
      'rJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDl'
      'mUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9',
    );
    final message = await token.verifyPublicMessage(publicKey: publicKey);
    expect(
        message.stringContent,
        // ignore: missing_whitespace_between_adjacent_strings
        '{"data":"this is a signed message",'
        '"exp":"2022-01-01T00:00:00+00:00"}');
  });

  test('sign', () async {
    final keyPair = await Ed25519().newKeyPair();
    const content = 'Hello World!';
    final message = await Message.signString(
      content,
      version: Version.v4,
      keyPair: keyPair,
    );
    final verifiedMessage = await message.toToken.verifyPublicMessage(
      publicKey: await keyPair.extractPublicKey(),
    );
    expect(message, verifiedMessage);
  });
}
