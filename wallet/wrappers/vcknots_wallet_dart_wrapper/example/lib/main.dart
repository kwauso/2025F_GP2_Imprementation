import 'package:flutter/material.dart';
import 'package:vcknots_wallet_dart_wrapper/vcknots_wallet.dart';

void main() {
  runApp(const WalletDemoApp());
}

class WalletDemoApp extends StatelessWidget {
  const WalletDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(home: WalletHomePage());
  }
}

class WalletHomePage extends StatefulWidget {
  const WalletHomePage({super.key});

  @override
  State<WalletHomePage> createState() => _WalletHomePageState();
}

class _WalletHomePageState extends State<WalletHomePage> {
  final _wallet = WalletApi();
  final _offerController = TextEditingController();
  final _requestUriController = TextEditingController();

  List<CredentialSummary> _credentials = [];
  String? _selectedCredentialId;
  String _log = '';
  bool _initialized = false;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _initWallet();
  }

  Future<void> _initWallet() async {
    setState(() {
      _loading = true;
      _log = 'Initializing wallet...';
    });
    try {
      await _wallet.init();
      final creds = await _wallet.listCredentials();
      setState(() {
        _initialized = true;
        _credentials = creds;
        if (creds.isNotEmpty) {
          _selectedCredentialId = creds.first.id;
        }
        _log = 'Wallet initialized. Stored credentials: ${creds.length}';
      });
    } catch (e) {
      setState(() {
        _log = 'Failed to initialize wallet: $e';
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _reloadCredentials() async {
    try {
      final creds = await _wallet.listCredentials();
      setState(() {
        _credentials = creds;
        if (creds.isNotEmpty) {
          _selectedCredentialId ??= creds.first.id;
        }
      });
    } catch (e) {
      setState(() {
        _log = 'Failed to reload credentials: $e';
      });
    }
  }

  Future<void> _receiveCredential() async {
    final offerUrl = _offerController.text.trim();
    if (offerUrl.isEmpty) {
      setState(() {
        _log = 'Offer URL is empty.';
      });
      return;
    }
    setState(() {
      _loading = true;
      _log = 'Receiving credential...';
    });
    try {
      final id = await _wallet.receiveFromOffer(offerUrl);
      await _reloadCredentials();
      setState(() {
        _selectedCredentialId = id;
        _log = 'Credential received. ID: $id';
      });
    } catch (e) {
      setState(() {
        _log = 'Failed to receive credential: $e';
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _present() async {
    final requestUri = _requestUriController.text.trim();
    if (requestUri.isEmpty) {
      setState(() {
        _log = 'OID4VP request URI is empty.';
      });
      return;
    }
    setState(() {
      _loading = true;
      _log = 'Presenting credential...';
    });
    try {
      await _wallet.present(
        requestUri: requestUri,
        credentialId: _selectedCredentialId,
      );
      setState(() {
        _log = 'Presentation sent successfully.';
      });
    } catch (e) {
      setState(() {
        _log = 'Failed to present credential: $e';
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  @override
  void dispose() {
    _offerController.dispose();
    _requestUriController.dispose();
    _wallet.shutdown();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('VCKnots Wallet Demo')),
      body: _loading && !_initialized
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Issuer から VC を受け取り、VP を提示するデモウォレットです。',
                    style: TextStyle(fontSize: 16),
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton(
                    onPressed: _loading ? null : _initWallet,
                    child: const Text('Re-initialize Wallet'),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    '1. VC 受領 (OID4VCI offer URL)',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _offerController,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      hintText:
                          'openid-credential-offer://?credential_offer=...',
                    ),
                  ),
                  const SizedBox(height: 8),
                  ElevatedButton(
                    onPressed: _loading ? null : _receiveCredential,
                    child: const Text('Receive Credential'),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    '2. 保存済み VC 一覧',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  _credentials.isEmpty
                      ? const Text('No credentials stored.')
                      : Column(
                          children: _credentials
                              .map(
                                (c) => RadioListTile<String>(
                                  title: Text(
                                    '${c.type ?? 'Unknown'} from ${c.issuer ?? '-'}',
                                  ),
                                  subtitle: Text(
                                    'ID: ${c.id}\nReceived: ${c.receivedAt.toIso8601String()}',
                                  ),
                                  value: c.id,
                                  groupValue: _selectedCredentialId,
                                  onChanged: (v) {
                                    setState(() {
                                      _selectedCredentialId = v;
                                    });
                                  },
                                ),
                              )
                              .toList(),
                        ),
                  const SizedBox(height: 24),
                  const Text(
                    '3. VP 提示 (OID4VP request URI)',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  TextField(
                    controller: _requestUriController,
                    decoration: const InputDecoration(
                      border: OutlineInputBorder(),
                      hintText: 'openid4vp://authorize?...',
                    ),
                  ),
                  const SizedBox(height: 8),
                  ElevatedButton(
                    onPressed: _loading ? null : _present,
                    child: const Text('Present VP'),
                  ),
                  const SizedBox(height: 24),
                  const Text(
                    'Log',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      border: Border.all(color: Colors.grey),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(_log, style: const TextStyle(fontSize: 12)),
                  ),
                ],
              ),
            ),
    );
  }
}
