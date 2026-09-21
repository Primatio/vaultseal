import 'dart:typed_data';

Uint8List decodeHex(String hex) {
  final cleaned = hex.replaceAll(RegExp(r'\s'), '');
  if (cleaned.length.isOdd) {
    throw FormatException('Odd hex length');
  }
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String encodeHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
