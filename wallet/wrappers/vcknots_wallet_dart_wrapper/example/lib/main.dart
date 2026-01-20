import 'package:flutter/material.dart';
import 'package:vcknots_wallet_dart_wrapper/vcknots_wallet.dart';

void main() {
  runApp(const WalletDemoApp());
}

class WalletDemoApp extends StatelessWidget {
  const WalletDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blueAccent),
        scaffoldBackgroundColor: const Color(0xFFF3F4F6),
        inputDecorationTheme: const InputDecorationTheme(
          filled: true,
          fillColor: Colors.white,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.all(Radius.circular(14)),
            borderSide: BorderSide.none,
          ),
          contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        ),
      ),
      home: const WalletHomePage(),
    );
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
      appBar: AppBar(
        elevation: 0,
        centerTitle: true,
        title: const Text('VCKnots Wallet'),
      ),
      body: _loading && !_initialized
          ? const Center(child: CircularProgressIndicator())
          : SafeArea(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    _HeaderStatus(
                      initialized: _initialized,
                      loading: _loading,
                      onRefresh: _loading ? null : _initWallet,
                    ),
                    const SizedBox(height: 16),
                    _SectionCard(
                      icon: Icons.download_outlined,
                      title: 'VCを受け取る',
                      subtitle: 'Issuer からの offer URL を貼り付けて、VC をウォレットに追加します。',
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          TextField(
                            controller: _offerController,
                            decoration: const InputDecoration(
                              hintText:
                                  'openid-credential-offer://?credential_offer=...',
                            ),
                            maxLines: 2,
                          ),
                          const SizedBox(height: 12),
                          FilledButton.icon(
                            onPressed: _loading ? null : _receiveCredential,
                            icon: const Icon(Icons.add_circle_outline),
                            label: const Text('VC を受領する'),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                    _SectionCard(
                      icon: Icons.credit_card_rounded,
                      title: '保存済みのカード',
                      subtitle: 'ウォレット内の VC を一覧で確認し、提示に使うものを選択します。',
                      child: _credentials.isEmpty
                          ? const Padding(
                              padding: EdgeInsets.symmetric(vertical: 12),
                              child: Text('まだカードはありません。まずは VC を受領してください。'),
                            )
                          : Column(
                              children: _credentials
                                  .map(
                                    (c) => Card(
                                      elevation: 0,
                                      margin: const EdgeInsets.symmetric(
                                        vertical: 4,
                                      ),
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(14),
                                      ),
                                      child: RadioListTile<String>(
                                        title: Text(
                                          c.type ?? 'Unknown credential',
                                          style: const TextStyle(
                                            fontWeight: FontWeight.w600,
                                          ),
                                        ),
                                        subtitle: Text(
                                          '${c.issuer ?? '-'}\nReceived: ${c.receivedAt.toIso8601String()}',
                                          maxLines: 2,
                                          overflow: TextOverflow.ellipsis,
                                        ),
                                        value: c.id,
                                        groupValue: _selectedCredentialId,
                                        onChanged: (v) {
                                          setState(() {
                                            _selectedCredentialId = v;
                                          });
                                        },
                                      ),
                                    ),
                                  )
                                  .toList(),
                            ),
                    ),
                    const SizedBox(height: 16),
                    _SectionCard(
                      icon: Icons.qr_code_scanner_rounded,
                      title: 'VPを提示する',
                      subtitle: 'Verifier からの OID4VP Request URI を貼り付けて提示します。',
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          TextField(
                            controller: _requestUriController,
                            decoration: const InputDecoration(
                              hintText: 'openid4vp://authorize?...',
                            ),
                            maxLines: 2,
                          ),
                          const SizedBox(height: 12),
                          FilledButton.icon(
                            onPressed: _loading ? null : _present,
                            icon: const Icon(Icons.send_rounded),
                            label: const Text('VP を提示する'),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                    _SectionCard(
                      icon: Icons.notes_rounded,
                      title: 'アクティビティログ',
                      subtitle: '最近の操作の結果やエラーを表示します。',
                      child: Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: Colors.grey.shade100,
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Text(
                          _log,
                          style: const TextStyle(fontSize: 12),
                          softWrap: true,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
    );
  }
}

class _HeaderStatus extends StatelessWidget {
  const _HeaderStatus({
    required this.initialized,
    required this.loading,
    required this.onRefresh,
  });

  final bool initialized;
  final bool loading;
  final VoidCallback? onRefresh;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: initialized
                ? colorScheme.primaryContainer
                : colorScheme.errorContainer,
            borderRadius: BorderRadius.circular(20),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                initialized ? Icons.check_circle : Icons.sync_problem,
                size: 18,
                color: initialized
                    ? colorScheme.onPrimaryContainer
                    : colorScheme.onErrorContainer,
              ),
              const SizedBox(width: 8),
              Text(
                initialized ? 'Connected' : 'Not initialized',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                  color: initialized
                      ? colorScheme.onPrimaryContainer
                      : colorScheme.onErrorContainer,
                ),
              ),
            ],
          ),
        ),
        const Spacer(),
        IconButton(
          onPressed: loading ? null : onRefresh,
          tooltip: '再接続',
          icon: const Icon(Icons.refresh_rounded),
        ),
      ],
    );
  }
}

class _SectionCard extends StatelessWidget {
  const _SectionCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.child,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 18,
                  backgroundColor: Theme.of(
                    context,
                  ).colorScheme.primaryContainer,
                  child: Icon(
                    icon,
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: const TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        subtitle,
                        style: TextStyle(
                          fontSize: 12,
                          color: Colors.grey.shade600,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}
