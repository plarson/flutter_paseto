import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

extension SecretBoxNonce on SecretBox {
  SecretBox withNonce(Uint8List nonce) {
    return SecretBox(
      cipherText,
      nonce: nonce,
      mac: mac,
    );
  }
}
