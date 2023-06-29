import 'dart:convert';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:paseto/paseto.dart';

@immutable
class Header extends Equatable {
  const Header({
    required this.version,
    required this.purpose,
  });

  final Version version;
  final Purpose purpose;

  String get toTokenString {
    return '${[version.name, purpose.name].join('.')}.';
  }

  List<int> get bytes {
    return utf8.encode(toTokenString);
  }

  @override
  List<Object?> get props => [
        version,
        purpose,
      ];
}
