import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';

@immutable
class Package extends Equatable {
  const Package({
    required this.content,
    this.footer,
  });

  final List<int> content;
  final List<int>? footer;

  String? get stringContent {
    final content = this.content;
    try {
      return utf8.decode(content);
    } catch (e) {
      return null;
    }
  }

  Map<String, dynamic>? get jsonContent {
    final stringContent = this.stringContent;
    if (stringContent == null) return null;
    try {
      return jsonDecode(stringContent) as Map<String, dynamic>?;
    } catch (e) {
      return null;
    }
  }

  String? get stringFooter {
    final content = footer;
    if (content == null) return null;
    try {
      return utf8.decode(content);
    } catch (e) {
      return null;
    }
  }

  Map<String, dynamic>? get jsonFooter {
    final stringContent = stringFooter;
    if (stringContent == null) return null;
    try {
      return jsonDecode(stringContent) as Map<String, dynamic>?;
    } catch (e) {
      return null;
    }
  }

  Future<Mac> calculateNonce({
    required SecretKey preNonce,
  }) {
    return Hmac.sha384().calculateMac(
      content,
      secretKey: preNonce,
    );
  }

  @override
  List<Object?> get props => [
        content,
        footer,
      ];
}
