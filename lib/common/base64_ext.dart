import 'dart:convert';
import 'dart:typed_data';

/// Encodes base64 and strips the padding.
String encodePasetoBase64(List<int> bytes) {
  final encoded = base64Url.encode(bytes);
  var padding = 0;
  for (var i = encoded.length; i > 4 && i > encoded.length / 4; i--) {
    if (encoded[i - 1] == '=') {
      padding += 1;
    } else {
      break;
    }
  }
  return encoded.substring(0, encoded.length - padding);
}

/// Decodes an unpadded base64 string.
Uint8List decodePasetoBase64(String rawBase64) {
  if (rawBase64.length % 4 > 0) {
    final decodedAndPadded = base64Url.decode(padPasetoBase64(rawBase64));
    return decodedAndPadded.sublist(
      0,
      decodedAndPadded.length - (4 - rawBase64.length % 4),
    );
  } else {
    return base64Url.decode(rawBase64);
  }
}

/// Pads a base64 encoding with underscores.
String padPasetoBase64(String rawBase64) {
  return (rawBase64.length % 4 > 0)
      ? rawBase64 + List.filled(4 - (rawBase64.length % 4), '_').join()
      : rawBase64;
}
