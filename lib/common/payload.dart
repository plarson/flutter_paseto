import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

abstract class Payload {
  String get toTokenString;
}

@immutable
class PayloadLocal implements Payload {
  const PayloadLocal({
    required this.secretBox,
    required this.nonce,
    this.mac,
  });

  final SecretBox? secretBox;
  final Mac? nonce;
  final Hash? mac;

  @override
  String get toTokenString {
    var result = List<int>.empty(growable: true);
    final nonce = this.nonce;
    if (nonce != null) {
      result += nonce.bytes;
    }
    final secretBox = this.secretBox;
    if (secretBox != null) {
      result += secretBox.cipherText;
    }
    final mac = this.mac;
    if (mac != null) {
      result += mac.bytes;
    }
    return encodePasetoBase64(result);
  }
}

@immutable
class PayloadPublic implements Payload {
  const PayloadPublic({
    required this.message,
    this.signature,
  });

  final List<int> message;
  final List<int>? signature;

  @override
  String get toTokenString {
    final signature = this.signature;
    if (signature != null) {
      return encodePasetoBase64(message + signature);
    } else {
      return encodePasetoBase64(message);
    }
  }
}
