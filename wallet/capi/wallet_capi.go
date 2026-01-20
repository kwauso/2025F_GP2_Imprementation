package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/receiver"
	"github.com/trustknots/vcknots/wallet/pkg/vcknots_wallet"
)

// グローバルな Controller インスタンスを保持する。
// デモ用途なのでシングルトンで十分とする。
var (
	ctrlMu sync.Mutex
	ctrl   *vcknots_wallet.Controller
	// walletDataDir は鍵ファイルなどを保存するディレクトリ
	walletDataDir string
)

// cString は Go の string から C の *char を生成するヘルパー。
// 呼び出し側（Dart/FFI 側）で free する必要がある。
func cString(s string) *C.char {
	return C.CString(s)
}

//export Wallet_Init
// Wallet_Init はウォレットのコアを初期化する。
// dataDir はローカルストレージ（鍵ファイルなど）の配置に利用する。
func Wallet_Init(dataDir *C.char) C.int {
	goDataDir := C.GoString(dataDir)

	ctrlMu.Lock()
	defer ctrlMu.Unlock()

	if ctrl != nil {
		return 0
	}

	c, err := vcknots_wallet.NewControllerWithDefaults()
	if err != nil {
		return 1
	}
	ctrl = c
	// データディレクトリには Go の string をそのまま保持する
	if goDataDir != "" {
		walletDataDir = goDataDir
	}
	return 0
}

//export Wallet_Shutdown
// Wallet_Shutdown はウォレットのコアを解放する。
func Wallet_Shutdown() {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()
	ctrl = nil
}

// ---------- 鍵管理（デモ用のシンプルなファイル保存） ----------

const keyFileName = "demo_es256_key.json"

type storedKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// fileKeyEntry は vcknots_wallet.IKeyEntry を実装する。
type fileKeyEntry struct {
	id         string
	privateKey *ecdsa.PrivateKey
}

func (f *fileKeyEntry) ID() string {
	return f.id
}

func (f *fileKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &f.privateKey.PublicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func (f *fileKeyEntry) Sign(data []byte) ([]byte, error) {
	// ES256 / P-256: 32byte R + 32byte S（IEEE P1363 形式）
	hash := data
	r, s, err := ecdsa.Sign(rand.Reader, f.privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// getOrCreateKeyEntry は dataDir 配下に ES256 鍵を保存/復元する。
func getOrCreateKeyEntry() (*fileKeyEntry, error) {
	if walletDataDir == "" {
		walletDataDir = "."
	}
	path := filepath.Join(walletDataDir, keyFileName)

	if _, err := os.Stat(path); err == nil {
		// 既存鍵を読み込み
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		var sk storedKey
		if err := json.Unmarshal(b, &sk); err != nil {
			return nil, fmt.Errorf("failed to unmarshal key file: %w", err)
		}
		if sk.Kty != "EC" || sk.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported key in key file")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(sk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(sk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode y: %w", err)
		}
		dBytes, err := base64.RawURLEncoding.DecodeString(sk.D)
		if err != nil {
			return nil, fmt.Errorf("failed to decode d: %w", err)
		}

		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			},
			D: new(big.Int).SetBytes(dBytes),
		}
		return &fileKeyEntry{
			id:         "demo-es256-key",
			privateKey: priv,
		}, nil
	}

	// 新規生成
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	sk := storedKey{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(privKey.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(privKey.PublicKey.Y.Bytes()),
		D:   base64.RawURLEncoding.EncodeToString(privKey.D.Bytes()),
	}

	if err := os.MkdirAll(walletDataDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}
	b, err := json.MarshalIndent(sk, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return &fileKeyEntry{
		id:         "demo-es256-key",
		privateKey: privKey,
	}, nil
}

// credentialSummary は Flutter 側で一覧表示するための最小限の情報。
type credentialSummary struct {
	ID         string `json:"id"`
	Issuer     string `json:"issuer,omitempty"`
	Type       string `json:"type,omitempty"`
	ReceivedAt string `json:"receivedAt"`
}

//export Wallet_ListCredentials
// Wallet_ListCredentials は保存済み VC の一覧を JSON 配列として返す。
// 返却値:
//   戻り値: 0 成功, 非 0 エラー
//   jsonOut: 成功時に JSON 文字列（[credentialSummary, ...]）
//   errorOut: エラー時にエラーメッセージ
func Wallet_ListCredentials(jsonOut **C.char, errorOut **C.char) C.int {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()

	if ctrl == nil {
		*errorOut = cString("wallet not initialized")
		return 1
	}

	entries, _, err := ctrl.GetCredentialEntries(vcknots_wallet.GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to get credential entries: %v", err))
		return 1
	}

	var list []credentialSummary
	for _, e := range entries {
		s := credentialSummary{
			ID:         e.Entry.Id,
			ReceivedAt: e.Entry.ReceivedAt.Format(time.RFC3339),
		}
		if len(e.Credential.Types) > 0 {
			s.Type = e.Credential.Types[0]
		}
		s.Issuer = e.Credential.Issuer.String()
		list = append(list, s)
	}

	b, err := json.Marshal(list)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to marshal credential list: %v", err))
		return 1
	}

	*jsonOut = cString(string(b))
	return 0
}

//export Wallet_ReceiveFromOffer
// issuer から取得した openid-credential-offer URL を受け取り VC を保存する。
// server_integration.go の receiveCredential 相当の処理を簡略化している。
func Wallet_ReceiveFromOffer(offerURL *C.char, credentialIDOut **C.char, errorOut **C.char) C.int {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()

	if ctrl == nil {
		*errorOut = cString("wallet not initialized")
		return 1
	}

	key, err := getOrCreateKeyEntry()
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to get key: %v", err))
		return 1
	}

	rawOfferURL := C.GoString(offerURL)
	const prefix = "openid-credential-offer://?credential_offer="
	if !strings.HasPrefix(rawOfferURL, prefix) {
		*errorOut = cString("invalid offer URL format")
		return 1
	}

	encodedOffer := strings.TrimPrefix(rawOfferURL, prefix)
	decodedOffer, err := url.QueryUnescape(encodedOffer)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to decode offer: %v", err))
		return 1
	}

	var offerData map[string]interface{}
	if err := json.Unmarshal([]byte(decodedOffer), &offerData); err != nil {
		*errorOut = cString(fmt.Sprintf("failed to parse offer JSON: %v", err))
		return 1
	}

	issuerStr, ok := offerData["credential_issuer"].(string)
	if !ok {
		*errorOut = cString("missing credential_issuer in offer")
		return 1
	}
	issuerURL, err := url.Parse(issuerStr)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("invalid credential_issuer URL: %v", err))
		return 1
	}

	var configIDs []string
	if ids, ok := offerData["credential_configuration_ids"].([]interface{}); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				configIDs = append(configIDs, s)
			}
		}
	}
	if len(configIDs) == 0 {
		*errorOut = cString("credential_configuration_ids is empty")
		return 1
	}

	grants := make(map[string]*vcknots_wallet.CredentialOfferGrant)
	if grantsData, ok := offerData["grants"].(map[string]interface{}); ok {
		for grantType, grantValue := range grantsData {
			if grantMap, ok := grantValue.(map[string]interface{}); ok {
				g := &vcknots_wallet.CredentialOfferGrant{}
				if preAuth, ok := grantMap["pre-authorized_code"].(string); ok {
					g.PreAuthorizedCode = preAuth
				}
				grants[grantType] = g
			}
		}
	}

	offer := &vcknots_wallet.CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: configIDs,
		Grants:                     grants,
	}

	req := vcknots_wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiver.Oid4vci,
		Key:             key,
	}

	saved, err := ctrl.ReceiveCredential(req)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to receive credential: %v", err))
		return 1
	}

	if saved == nil || saved.Entry == nil {
		*errorOut = cString("received credential is nil")
		return 1
	}

	*credentialIDOut = cString(saved.Entry.Id)
	return 0
}

//export Wallet_GetCredential
func Wallet_GetCredential(id *C.char, jsonOut **C.char, errorOut **C.char) C.int {
	ctrlMu.Lock()
	defer ctrlMu.Unlock()

	if ctrl == nil {
		*errorOut = cString("wallet not initialized")
		return 1
	}

	goID := C.GoString(id)
	res, err := ctrl.GetCredentialEntry(goID)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to get credential entry: %v", err))
		return 1
	}
	if res == nil {
		*jsonOut = cString("null")
		return 0
	}

	type detail struct {
		ID         string   `json:"id"`
		Issuer     string   `json:"issuer"`
		Types      []string `json:"types"`
		ReceivedAt string   `json:"receivedAt"`
		RawJWT     string   `json:"rawJwt"`
	}

	d := detail{
		ID:         res.Entry.Id,
		Issuer:     res.Credential.Issuer.String(),
		Types:      res.Credential.Types,
		ReceivedAt: res.Entry.ReceivedAt.Format(time.RFC3339),
		RawJWT:     string(res.Entry.Raw),
	}

	b, err := json.Marshal(d)
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to marshal credential detail: %v", err))
		return 1
	}
	*jsonOut = cString(string(b))
	return 0
}

//export Wallet_Present
// OID4VP Request URI と VC ID を受け取り、VP を生成して提示する。
// 現時点では VC ID は未使用で、保存済みの最初の VC を使う。
func Wallet_Present(requestURI *C.char, credentialID *C.char, errorOut **C.char) C.int {
	_ = C.GoString(credentialID)

	ctrlMu.Lock()
	defer ctrlMu.Unlock()

	if ctrl == nil {
		*errorOut = cString("wallet not initialized")
		return 1
	}

	key, err := getOrCreateKeyEntry()
	if err != nil {
		*errorOut = cString(fmt.Sprintf("failed to get key: %v", err))
		return 1
	}

	uri := C.GoString(requestURI)
	if uri == "" {
		*errorOut = cString("request URI is empty")
		return 1
	}

	if err := ctrl.PresentCredential(uri, key); err != nil {
		*errorOut = cString(fmt.Sprintf("failed to present credential: %v", err))
		return 1
	}

	return 0
}

func main() {}

