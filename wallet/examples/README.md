# vcknots-wallet サーバー統合サンプル

このディレクトリには、vcknots-walletとverifierサーバーとの統合を実演するサンプルコードが含まれています。

## 前提条件

### 1. mise のインストール

Walletのパッケージは開発環境管理に[mise](https://mise.jdx.dev/)を使用しています．
miseがインストールされていない場合はまずインストールしてください．

例えば:
```bash
# macOS
brew install mise

# curl経由でのインストール
curl https://mise.jdx.dev/install.sh | sh
```

### 2. 環境のセットアップ

プロジェクトディレクトリに移動して環境をセットアップします：

```bash
cd /path/to/vcknots/wallet
mise install
```

これにより，`mise.toml`に基づいてGo 1.24.5が自動的にインストールされ，必要な環境変数が設定されます．
miseを利用しない場合は，Go 1.24.5を手動でインストールし，`GOPRIVATE`環境変数を設定してください：

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 3. 依存関係のインストール

Goモジュールの依存関係をインストールします：

```bash
go mod download
```

## サンプルの実行方法

### ステップ1: Verifierサーバーの起動

サンプルを実行するためには，verifierサーバーが動作している必要があります．サーバーディレクトリに移動してサーバーを起動します：

```bash
# walletディレクトリから、serverディレクトリへ移動
cd ../../packages/server

# サーバーの依存関係をインストール（まだの場合）
pnpm install

# サーバーを起動
pnpm start
```

サーバーはデフォルトで`http://localhost:8080`で起動します．
テスト用スクリプトも上記のURLを使用します．

### ステップ2: 統合テスト用のスクリプト実行

新しいターミナルで，walletディレクトリに戻ってサーバー統合テスト用のスクリプトを実行します：

```bash
cd /path/to/vcknots/wallet/examples
go run .
```

### ステップ3: 結果の確認

うまくいけば、以下のような出力が表示されます：

```
time=2025-09-10T15:23:40.851+09:00 level=INFO msg="Importing demo credential..."
time=2025-09-10T15:23:40.863+09:00 level=INFO msg="Successfully imported demo credential via controller.ReceiveCredential" entry_id=66a56284-9591-4b69-9dc9-29d0e493fe5c raw_length=1342
time=2025-09-10T15:23:40.865+09:00 level=INFO msg="Stored credentials" count=33 total=36
time=2025-09-10T15:23:40.865+09:00 level=INFO msg="Starting server integration check..."
time=2025-09-10T15:23:40.865+09:00 level=INFO msg="Verifier Details" URL=http://localhost:8080 ID=https://verifier.example.com
time=2025-09-10T15:23:40.871+09:00 level=INFO msg="Authorization RequestURI" status="200 OK" body="openid4vp://authorize?client_id=redirect_uri%3Ahttp%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttps%253A%252F%252Fverifier.example.com%2Fcallback&request_uri=http%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttps%253A%252F%252Fverifier.example.com%2Frequest.jwt%2F4e3a5afb84364b40b4840a3fc72411c2"
time=2025-09-10T15:23:40.871+09:00 level=INFO msg="Request URI is valid" scheme=openid4vp
time=2025-09-10T15:23:41.410+09:00 level=INFO msg="Credential presented successfully"
```

`Credential presented successfully`と表示されれば，成功です．

## ファイル構成

```
examples/
├── server_integration.go    # メインのソースコード
├── example_vc_jwt.txt      # サンプルVC
└── README.md               # このファイル
```
