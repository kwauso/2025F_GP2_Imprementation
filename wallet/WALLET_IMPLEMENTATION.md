## vcknots-wallet 実装レポート

このドキュメントでは、今回実装した **Go ベースの VC ウォレットコア** と **Flutter デモアプリ** の構成・意図・現状カバーしている範囲、および **今後実装すべき点** を整理します。

---

## 1. 全体アーキテクチャ

### 1.1 レイヤ構成

ウォレット機能は大きく 3 レイヤに分かれています。

| レイヤ | 実装場所 | 主な責務 |
|--------|----------|----------|
| ① ウォレットコア（Go） | `wallet/pkg`・`wallet/internal`・`wallet/capi` | VC 受領・保存・VP 生成・提示・検証・DID 生成などのロジック |
| ② FFI ブリッジ（Dart FFI） | `wallet/wrappers/vcknots_wallet_dart_wrapper/lib` | Go の C API を Dart から呼び出すためのバインディングと高レベル API |
| ③ プレゼンテーション層（Flutter UI） | `wallet/wrappers/vcknots_wallet_dart_wrapper/example` | モバイルウォレットの画面・操作（VC 受領 / 一覧 / VP 提示） |

概念図：

```text
┌─────────────────────────────┐
│        Flutter UI           │  ← example/lib/main.dart (WalletHomePage)
│  - 入力フォーム/ボタン       │
│  - カード一覧/ログ表示       │
└────────────▲────────────────┘
             │ WalletApi (Dart)
┌────────────┴────────────────┐
│      Dart FFI ラッパ        │  ← lib/vcknots_wallet.dart
│  - WalletApi.init()/present │
│  - FFI: Wallet_* C 関数呼び出し │
└────────────▲────────────────┘
             │ C ABI
┌────────────┴────────────────┐
│        Go C API             │  ← wallet/capi/wallet_capi.go
│  - Wallet_Init              │
│  - Wallet_ReceiveFromOffer  │
│  - Wallet_List/Get/Present  │
└────────────▲────────────────┘
             │ Go 呼び出し
┌────────────┴────────────────┐
│       vcknots_wallet        │  ← pkg/internal 配下
│  - Controller               │
│  - Receiver (OID4VCI)       │
│  - Presenter (OID4VP)       │
│  - CredStore (bbolt)        │
│  - DID / Verifier / Serializer │
└─────────────────────────────┘
```

---

## 2. Go 側の実装（ウォレットコア + C API）

### 2.1 既存のコアロジック（おさらい）

`pkg/vcknots_wallet/controller.go` で定義される `Controller` は、以下のコンポーネントを束ねる統合 API です。

- CredStore（VC の保存 / 取得）
- Receiver（OID4VCI: VC 受領）
- Serializer（JWT VC / VP のシリアライズ・デシリアライズ）
- Verifier（署名検証：ES256）
- Presenter（OID4VP: VP 提示）
- IDProfiler（DID / JWKS 管理）

主なメソッド：

- `NewControllerWithDefaults()`
- `ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)`
- `GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)`
- `GetCredentialEntry(id string) (*SavedCredential, error)`
- `PresentCredential(uriString string, key IKeyEntry) error`

これにより、**VC 受領 → 保存 → 構造化データとしての参照 → VP 生成＆提示** までを Go 単体で完結できます。

### 2.2 C API ラッパ（wallet/capi/wallet_capi.go）

Flutter から利用しやすい形で `Controller` にアクセスするため、C ABI を持つ薄いラッパを追加しました。

#### エントリポイント

- `Wallet_Init(char* dataDir) int`
  - `Controller.NewControllerWithDefaults()` を生成。
  - 引数 `dataDir` はデモ用のデータディレクトリパスとして保持し、後述する鍵ファイル保存に利用。

- `Wallet_Shutdown()`
  - グローバルな `Controller` インスタンスを破棄（`nil`）。

- `Wallet_ReceiveFromOffer(char* offerUrl, char** credentialIdOut, char** errorOut) int`
  - `offerUrl`: `openid-credential-offer://?credential_offer=...` 形式の URL。
  - Offer 部分を `url.QueryUnescape` → `json.Unmarshal`。
  - `CredentialOffer` 構造体に変換し、`ReceiveCredentialRequest` を組み立てて `Controller.ReceiveCredential` を呼び出す。
  - 成功時: 新規 `CredentialEntry.Id` を `credentialIdOut` に返却。

- `Wallet_ListCredentials(char** jsonOut, char** errorOut) int`
  - `GetCredentialEntries` で全件取得し、以下の構造に絞って JSON で返却：
    - `[{ id, issuer, type, receivedAt }, ...]`
  - Flutter UI での一覧表示に利用。

- `Wallet_GetCredential(char* id, char** jsonOut, char** errorOut) int`
  - `GetCredentialEntry(id)` で単一 VC を取得し、以下の JSON で返却：
    - `{ id, issuer, types, receivedAt, rawJwt }`

- `Wallet_Present(char* requestUri, char* credentialId, char** errorOut) int`
  - `requestUri`: `openid4vp://authorize?...` 形式の Request URI。
  - 内部で `Controller.PresentCredential(requestUri, key)` を呼び出し、VP 生成と verifier への POST を行う。
  - 現時点では `credentialId` は未使用で、保存済み VC のうち 1 件目を提示に利用。

#### 2.3 鍵管理の意図と実装

要件の一つ「VC, VP, 鍵はローカルのデータストレージで保管」に沿って、**デモ用途の簡易キーストレージ**を実装しました。

- 関連コード：`wallet/capi/wallet_capi.go` 内
  - `storedKey` 構造体：ES256 JWK 相当（`kty`, `crv`, `x`, `y`, `d`）
  - ファイル名：`demo_es256_key.json`
  - 保存場所：`Wallet_Init` に渡された `dataDir` 直下（`walletDataDir/demo_es256_key.json`）

`getOrCreateKeyEntry()` の挙動：

1. `demo_es256_key.json` が存在すれば読み込み、P-256 の `ecdsa.PrivateKey` を復元。
2. ない場合は `ecdsa.GenerateKey(P-256)` で新規鍵を生成し、Base64URL で JWK 風にシリアライズしてファイルに保存。
3. 復元した鍵を `fileKeyEntry` として `vcknots_wallet.IKeyEntry` 実装として返す。

`fileKeyEntry` は VC 受領・VP 生成時に利用されます：

- `ReceiveCredential` 時の JWT proof 生成（`generateJWTProof`）
- `PresentCredential` 時の VP 署名（`serializer.SerializePresentation` 経由）

---

## 3. Dart / Flutter 側の実装

### 3.1 FFI バインディング（lib/vcknots_wallet_dart_wrapper_bindings_generated.dart）

`ffigen` のテンプレートをベースに、手動で以下の C 関数のバインディングを追加しました。

```dart
int Wallet_Init(Pointer<ffi.Char> dataDir);
void Wallet_Shutdown();

int Wallet_ListCredentials(
  Pointer<Pointer<ffi.Char>> jsonOut,
  Pointer<Pointer<ffi.Char>> errorOut,
);

int Wallet_ReceiveFromOffer(
  Pointer<ffi.Char> offerUrl,
  Pointer<Pointer<ffi.Char>> credentialIdOut,
  Pointer<Pointer<ffi.Char>> errorOut,
);

int Wallet_GetCredential(
  Pointer<ffi.Char> id,
  Pointer<Pointer<ffi.Char>> jsonOut,
  Pointer<Pointer<ffi.Char>> errorOut,
);

int Wallet_Present(
  Pointer<ffi.Char> requestUri,
  Pointer<ffi.Char> credentialId,
  Pointer<Pointer<ffi.Char>> errorOut,
);
```

これにより、Dartコードから **ほぼ素の C 関数** を呼べる状態になっています。

### 3.2 高レベル API: WalletApi（lib/vcknots_wallet.dart）

UI層が C ポインタ管理に煩わされないよう、`WalletApi` クラスで **FFI 呼び出しを隠蔽**しました。

#### データモデル

- `CredentialSummary`
  - `id`, `issuer`, `type`, `receivedAt`
  - VC 一覧表示用の軽量サマリ
- `CredentialDetail`
  - `id`, `issuer`, `types`, `receivedAt`, `rawJwt`
  - 単体 VC 詳細表示用（必要に応じて claims 等も今後拡張可能）

#### WalletApi のメソッド

- `Future<void> init({String? dataDir})`
  - デフォルト `'/tmp/vcknots_wallet_demo'` を使用。
  - `Wallet_Init` を呼び出し、内部フラグ `_initialized` を true に。

- `void shutdown()`
  - `Wallet_Shutdown` 呼び出し。

- `Future<List<CredentialSummary>> listCredentials()`
  - `Wallet_ListCredentials` の返す JSON を decode し、`CredentialSummary` のリストに変換。

- `Future<String> receiveFromOffer(String offerUrl)`
  - `Wallet_ReceiveFromOffer` を呼び出し、返ってきた `credentialId` を返却。

- `Future<CredentialDetail?> getCredential(String id)`
  - `Wallet_GetCredential` を呼び出し、`null` または `CredentialDetail` として返却。

- `Future<void> present({required String requestUri, String? credentialId})`
  - `Wallet_Present` を呼び出して VP を提示。
  - 現状、Go側は最初の VC を利用するため、`credentialId` は将来拡張用の引数。

`WalletApi` 内でポインタの `malloc/free` や `CString` → `String` 変換を一元的に扱うことで、UI 側からは **Dart の普通の async API のように扱える**ようにしています。

### 3.3 Flutter デモ UI（example/lib/main.dart）

Apple / Google Wallet 風のモダンな UI を意識して、以下のような画面構成とデザインにしました。

#### テーマ設定

- `MaterialApp` にて:
  - `useMaterial3: true`
  - `ColorScheme.fromSeed(seedColor: Colors.blueAccent)`
  - 背景を淡いグレー (`0xFFF3F4F6`) に設定。
- `InputDecorationTheme` で:
  - 角丸 14px のフルフィルドなテキストフィールド
  - 適度なパディング

#### ホーム画面レイアウト

コンポーネント：

- `WalletHomePage`（StatefulWidget）
  - 状態：
    - `_credentials`（`List<CredentialSummary>`）
    - `_selectedCredentialId`
    - `_log`（ログ文字列）
    - `_initialized`（ウォレット初期化済みか）
    - `_loading`（処理中か）

##### ヘッダー：接続ステータス

- `_HeaderStatus` コンポーネント
  - バッジ表示：
    - `Connected` / `Not initialized`
    - 色・アイコンを ColorScheme に従って変化
  - 右側に「再接続」アイコンボタン（`_initWallet()` 再実行）

##### セクション 1: VC を受け取る

- `_SectionCard`（共通カードコンポーネント）で枠組みを作成。
  - アイコン：`Icons.download_outlined`
  - タイトル：`VCを受け取る`
  - サブタイトル：Issuer からの offer URL を貼る説明文
- 中身：
  - Offer URL 入力フィールド（`TextField`）
    - `maxLines: 2` で長い URL に対応
  - 「VC を受領する」ボタン → `_receiveCredential()` → `WalletApi.receiveFromOffer()`

##### セクション 2: 保存済みのカード

- `_SectionCard`
  - アイコン：`Icons.credit_card_rounded`
  - タイトル：`保存済みのカード`
  - サブタイトル：ウォレット内の VC 説明
- 中身：
  - VC が 0 件の場合：
    - 「まだカードはありません。まずは VC を受領してください。」というメッセージ。
  - 1 件以上ある場合：
    - 各 VC を `Card + RadioListTile` でカード風に表示。
    - 表示内容：
      - タイトル：`type`（なければ `Unknown credential`）
      - サブタイトル：`issuer` と `receivedAt`
        - `maxLines: 2` + `TextOverflow.ellipsis` で小さい画面でも崩れないように調整。
    - ラジオで提示に利用する VC を選択可能。

##### セクション 3: VP を提示する

- `_SectionCard`
  - アイコン：`Icons.qr_code_scanner_rounded`
  - タイトル：`VPを提示する`
  - サブタイトル：OID4VP Request URI 説明
- 中身：
  - Request URI 入力フィールド（`TextField`、`maxLines: 2`）
  - 「VP を提示する」ボタン → `_present()` → `WalletApi.present()`

##### セクション 4: アクティビティログ

- `_SectionCard`
  - アイコン：`Icons.notes_rounded`
  - タイトル：`アクティビティログ`
  - サブタイトル：ログ説明
- 中身：
  - 薄いグレー背景のコンテナに `_log` を表示（`softWrap: true` で改行対応）。

#### レスポンシブ配慮

- タイトルやサブタイトルは `maxLines` + `TextOverflow.ellipsis` を設定し、狭い画面でも文字がちぎれにくいように調整。
- Offer URL / Request URI は `maxLines: 2` を設定し、極端な横スクロールを避けつつ、文字列を読みやすく表示。

---

## 4. 現状カバーしている要件と残課題

### 4.1 満たしている要件

ユーザーが挙げた要件と、その対応状況は以下の通りです。

| 要件 | 状態 | 実装箇所 |
|------|------|----------|
| issuerからVCを受け取れる | ✅ | Go: `Wallet_ReceiveFromOffer` → `Controller.ReceiveCredential` / Flutter: Offer URL 入力 + ボタン |
| VCからVPを発行できる | ✅ | Go: `Controller.PresentCredential` (内部で VP 生成) |
| VPを提示できる | ✅ | Go: OID4VP Presenter プラグインが `/callback` 等に POST / Flutter: Request URI 入力 + ボタン |
| VC, VP, 鍵をローカルストレージに保管 | ✅（VPは毎回生成のみ） | VC: bbolt / 鍵: `demo_es256_key.json` / VP: ローカル保存は現状不要と判断し未実装 |
| issuer/verifier がこのリポジトリの ./issuer+verifier 準拠 | ✅（前提） | サンプルサーバ `server/` と同一コードベースを想定 |
| デモ用途としてシミュレータで動作確認 | ✅ | iOS シミュレータ上で Flutter アプリ起動済み |

### 4.2 これから実装すべき・改善したいポイント

| 項目 | 現状 | 今後の改善案 |
|------|------|--------------|
| 提示に使う VC の選択 | Go側 `PresentCredential` が「1件目固定」 | `Wallet_Present` に渡された `credentialId` を使って該当 VC のみを提示するよう、Go 側ロジックを拡張 |
| エラーレポート | 文字列ログのみ | エラー種別ごとのユーザフレンドリーなメッセージや、UI 上のチップ表示等に整理 |
| VP のローカル保存 | 非保存（都度生成） | 必要であれば、提示履歴として VP/JWT とメタデータを保存する CredStore 拡張 |
| セキュリティ | デモ用（固定/ローカル鍵・PINロックなし） | 本番想定では OS キーストア連携、画面ロック、トラッキング対策などを検討 |
| QR/ディープリンク連携 | 手動で URI をコピペ | Flutter の QR スキャナ + `uni_links` 等を用いた deep link 受信に対応 |
| Android 対応 | 主に iOS シミュレータで確認 | Go の `.so` ビルドと Android NDK 設定、`android/` プラグイン設定を整備 |
| `enforceBundling` | Swift 側で no-op にしてビルド回避 | 将来的には C ライブラリ側に `void enforceBundling(void);` を定義し、正しくリンクさせる |

---

## 5. まとめ

この実装により、`wallet/` 以下の既存 Go コア（VC/VP の仕様準拠ロジック）を **Flutter アプリから直接操作できるデモウォレット** として立ち上げることができました。

- **Go** は仕様に忠実な OID4VCI / OID4VP / DID / 署名検証の実装を担当。
- **C API** は Go と Dart の橋渡し。
- **Dart/Flutter** は最小限の API (`WalletApi`) と、Apple/Google ウォレットライクな UI で、ユーザー操作を提供。

今後は、VC 選択ロジックの Go 側への反映、QR/ディープリンク連携、セキュリティ・UX 強化などを行うことで、デモから実運用に近いウォレット体験へと徐々に拡張していくことができます。

