# flutter_paseto

  
[![pub](https://img.shields.io/pub/v/paseto)](https://pub.dartlang.org/packages/paseto)
[![license](https://img.shields.io/badge/license-BSD-blue.svg)](https://opensource.org/license/BSD-3-clause/)

[Paseto](https://paseto.io) is everything you love about JOSE (JWT, JWE, JWS) without any of the many design deficits that plague the JOSE standards. 

## Support

| Version   | Implemented |
| -------   | --:         |
| v1.local  | ✅          |
| v1.public | ✅          |
| v2.local  | ✅          |
| v2.public | ✅          |
| v3.local  | ✅          |
| v3.public | ✅          |
| v4.local  | ❌          |
| v4.public | ✅          |


Requires a patched version of [Flutter cryptography](https://github.com/plarson/flutter_cryptography/tree/plarson/disable-mac-verification) that disables MAC verification.

## Decode a Token into a Message

Paseto converts Token strings into Message objects. Paseto tokens are either in local mode or public mode depending on your use case. 

### Decode Local Encrypted Tokens

Local mode tokens contain encrypted data, and must be decrypted.

```dart
main () async {
  // The same symmetric key the token was signed with.
  final secretKey = SecretKey();
  // The local encrypted paceto token.
  const tokenString = 'v4.local.payloadBase64.footerBase64';
  // Turns the string into a Token object.
  final token = await Token.fromString(tokenString);
  // Decrypts the local encrypted Token into a full Message.
  final message = await token.decryptLocalMessage(secretKey: secretKey);
}
```

### Decide Public Signed Tokens

Public mode tokens are unencrypted, and the module will verify the signature.

```dart
main () async {
  // An asymmetric ED25519 KeyPair to sign and verify the message.
  final publicKey = SimplePublicKey([], type: KeyPairType.ed25519);
  // The public key from the asymmetric KeyPair used to sign the token.
  const tokenString = 'v4.public.payloadBase64.footerBase64';
  // Turns the string into a Token object.
  final token = await Token.fromString(tokenString);
  // Verifies the signature of the Token, using the publicKey, and returns the full Message.
  final message = await token.verifyPublicMessage(publicKey: publicKey);
}
```

## Encode a Message into a Token

### Local Encrypted Tokens

Local mode tokens contain encrypted data, and must be encrypted.

```dart
main () async {
  // The  symmetric key to encrypt with.
  final secretKey = SecretKey();
  // Encrypt the content into a Paceto Message object.
  final message = await Message.encryptString(
    'Hello World!',
    version: Version.v2,
    secretKey: secretKey,
  );
  // Encode the Token
  final token = message.toToken.toTokenString;
}
```

### Public Signed Tokens

Public mode tokens are unencrypted, and the module will sign the Message.

```dart
main () async {
  // An asymmetric ED25519 KeyPair to sign and verify the message.
  final keyPair = await Ed25519().newKeyPair();
  // Sign the content with the Paceto version you are using.
  final message = await Message.signString(
    'Hello World!',
    version: Version.v4,
    keyPair: keyPair,
  );
  // Encode the Token
  final token = message.toToken.toTokenString;  
}
```