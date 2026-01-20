import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'vcknots_wallet_dart_wrapper_bindings_generated.dart';

/// The dynamic library in which the symbols for [VcknotsWalletDartWrapperBindings] can be found.
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    // NOTE: 実際の .so 名はビルド設定に合わせて調整してください。
    return DynamicLibrary.open('libvcknots_wallet.so');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

/// The bindings to the native functions in [_dylib].
final VcknotsWalletDartWrapperBindings _bindings =
    VcknotsWalletDartWrapperBindings(_dylib);

class CredentialSummary {
  final String id;
  final String? issuer;
  final String? type;
  final DateTime receivedAt;

  CredentialSummary({
    required this.id,
    this.issuer,
    this.type,
    required this.receivedAt,
  });

  factory CredentialSummary.fromJson(Map<String, dynamic> json) {
    return CredentialSummary(
      id: json['id'] as String,
      issuer: json['issuer'] as String?,
      type: json['type'] as String?,
      receivedAt: DateTime.parse(json['receivedAt'] as String),
    );
  }
}

class CredentialDetail {
  final String id;
  final String issuer;
  final List<String> types;
  final DateTime receivedAt;
  final String rawJwt;

  CredentialDetail({
    required this.id,
    required this.issuer,
    required this.types,
    required this.receivedAt,
    required this.rawJwt,
  });

  factory CredentialDetail.fromJson(Map<String, dynamic> json) {
    return CredentialDetail(
      id: json['id'] as String,
      issuer: json['issuer'] as String,
      types: (json['types'] as List<dynamic>).map((e) => e as String).toList(),
      receivedAt: DateTime.parse(json['receivedAt'] as String),
      rawJwt: json['rawJwt'] as String,
    );
  }
}

/// 高レベルなウォレット API。Flutter UI からはこのクラスだけを使えばよい。
class WalletApi {
  bool _initialized = false;

  Future<void> init({String? dataDir}) async {
    final dir = dataDir ?? '/tmp/vcknots_wallet_demo';
    final dirPtr = dir.toNativeUtf8().cast<Char>();
    final code = _bindings.Wallet_Init(dirPtr);
    malloc.free(dirPtr);
    if (code != 0) {
      throw Exception('Wallet_Init failed with code $code');
    }
    _initialized = true;
  }

  void shutdown() {
    if (_initialized) {
      _bindings.Wallet_Shutdown();
      _initialized = false;
    }
  }

  Future<List<CredentialSummary>> listCredentials() async {
    _ensureInitialized();

    final jsonOutPtr = malloc<Pointer<Char>>();
    final errOutPtr = malloc<Pointer<Char>>();
    try {
      final code = _bindings.Wallet_ListCredentials(jsonOutPtr, errOutPtr);
      if (code != 0) {
        final err = _readAndFreeCString(errOutPtr.value);
        throw Exception(err);
      }
      final jsonStr = _readAndFreeCString(jsonOutPtr.value);

      // ネイティブ側が VC なしの場合に "null" や空文字を返すケースを考慮して防御的に扱う。
      final trimmed = jsonStr.trim();
      if (trimmed.isEmpty || trimmed == 'null') {
        return <CredentialSummary>[];
      }

      final decoded = json.decode(trimmed);
      if (decoded is! List) {
        throw StateError('Expected a JSON list but got ${decoded.runtimeType}');
      }

      return decoded
          .cast<Map<String, dynamic>>()
          .map(CredentialSummary.fromJson)
          .toList();
    } finally {
      malloc.free(jsonOutPtr);
      malloc.free(errOutPtr);
    }
  }

  Future<String> receiveFromOffer(String offerUrl) async {
    _ensureInitialized();

    final offerPtr = offerUrl.toNativeUtf8().cast<Char>();
    final idOutPtr = malloc<Pointer<Char>>();
    final errOutPtr = malloc<Pointer<Char>>();
    try {
      final code = _bindings.Wallet_ReceiveFromOffer(
        offerPtr,
        idOutPtr,
        errOutPtr,
      );
      if (code != 0) {
        final err = _readAndFreeCString(errOutPtr.value);
        throw Exception(err);
      }
      final id = _readAndFreeCString(idOutPtr.value);
      return id;
    } finally {
      malloc.free(offerPtr);
      malloc.free(idOutPtr);
      malloc.free(errOutPtr);
    }
  }

  Future<CredentialDetail?> getCredential(String id) async {
    _ensureInitialized();

    final idPtr = id.toNativeUtf8().cast<Char>();
    final jsonOutPtr = malloc<Pointer<Char>>();
    final errOutPtr = malloc<Pointer<Char>>();
    try {
      final code = _bindings.Wallet_GetCredential(idPtr, jsonOutPtr, errOutPtr);
      if (code != 0) {
        final err = _readAndFreeCString(errOutPtr.value);
        throw Exception(err);
      }
      final jsonStr = _readAndFreeCString(jsonOutPtr.value);
      if (jsonStr == 'null') {
        return null;
      }
      final decoded = json.decode(jsonStr) as Map<String, dynamic>;
      return CredentialDetail.fromJson(decoded);
    } finally {
      malloc.free(idPtr);
      malloc.free(jsonOutPtr);
      malloc.free(errOutPtr);
    }
  }

  Future<void> present({
    required String requestUri,
    String? credentialId,
  }) async {
    _ensureInitialized();

    final uriPtr = requestUri.toNativeUtf8().cast<Char>();
    final idPtr = (credentialId ?? '').toNativeUtf8().cast<Char>();
    final errOutPtr = malloc<Pointer<Char>>();
    try {
      final code = _bindings.Wallet_Present(uriPtr, idPtr, errOutPtr);
      if (code != 0) {
        final err = _readAndFreeCString(errOutPtr.value);
        throw Exception(err);
      }
    } finally {
      malloc.free(uriPtr);
      malloc.free(idPtr);
      malloc.free(errOutPtr);
    }
  }

  void _ensureInitialized() {
    if (!_initialized) {
      throw StateError('WalletApi is not initialized. Call init() first.');
    }
  }

  String _readAndFreeCString(Pointer<Char> ptr) {
    if (ptr == nullptr) {
      return '';
    }
    final str = ptr.cast<Utf8>().toDartString();
    malloc.free(ptr);
    return str;
  }
}
