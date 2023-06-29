import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:paseto/paseto.dart';

void main() {
  test('v2 strings', () async {
    const controlString =
        'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqII'
        'hOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L'
        '7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc'
        '2Vz';
    final token = await Token.fromString(controlString);
    final resultString = token.toTokenString;
    expect(controlString, resultString);
  });

  test('v1 decrypt', () async {
    final secretKey = SecretKey(
      decodePasetoBase64('cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8'),
    );
    const tokenString =
        'v1.local.RyoRvI1w3vHN80SRZrBmCugFk4bKaSzSFHM6lbCyTa7_b3wRN8ujJMIt'
        'IQ3bgXOYosKt8DJP98VBnKzKtA_W5eYGdPrp2SjbaMDz22M1Xd3Jhjgcl_Rl7Ktwv'
        'g7EWR7Lr00znpJFNSOsS0D60RyFFZUtGFt4XWN6lgX02MdjJua-quukaV1OcXDuIb'
        'U9ttZ0s-pQd0d5tuu9.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.jsonContent, {
      'data': 'this is a signed message',
      'expires': '2019-01-01T00:00:00+00:00',
    });
  });

  test('v2 decrypt', () async {
    final secretKey = SecretKey(
      decodePasetoBase64('cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8'),
    );
    const tokenString =
        'v2.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqII'
        'hOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L'
        '7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc'
        '2Vz';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.jsonContent, {
      'data': 'this is a signed message',
      'expires': '2019-01-01T00:00:00+00:00',
    });
  });

  test('v3 decrypt', () async {
    final secretKey = SecretKey(
      decodePasetoBase64('cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8'),
    );
    const tokenString =
        'v4.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqII'
        'hOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L'
        '7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc'
        '2Vz';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.jsonContent, {
      'data': 'this is a signed message',
      'expires': '2019-01-01T00:00:00+00:00',
    });
  });

  test('v4 decrypt', () async {
    final secretKey = SecretKey(
      decodePasetoBase64('cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8'),
    );
    const tokenString =
        'v4.local.lClhzVOuseCWYep44qbA8rmXry66lUupyENijX37_I_z34EiOlfyuwqII'
        'hOjF-e9m2J-Qs17Gs-BpjpLlh3zf-J37n7YGHqMBV6G5xD2aeIKpck6rhfwHpGF38L'
        '7ryYuzuUeqmPg8XozSfU4PuPp9o8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc'
        '2Vz';
    final token = await Token.fromString(tokenString);
    final message = await token.decryptLocalMessage(secretKey: secretKey);
    expect(message.jsonContent, {
      'data': 'this is a signed message',
      'expires': '2019-01-01T00:00:00+00:00',
    });
  });
}
