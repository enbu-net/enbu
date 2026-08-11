# enbu

enbuは、機密情報を扱うクロスプラットフォームの暗号化artifact workspaceです。

`.env`だけでなく、SSH鍵、CSV、JSON、個人情報を含むファイル、ファームウェア設定、複数ファイルのFileTree、独自schemaを、署名付きの不変グラフとしてOCI registryへ保存します。

設計とセキュリティ境界の正本は[artifact-platform-v1.md](docs/design/artifact-platform-v1.md)です。

## 基本操作

```bash
enbu auth login
enbu init --registry ghcr.io/OWNER/REPOSITORY-enbu

enbu import-file .env --format dotenv --name application
enbu import-file id_ed25519 --format opaque --name deployment-key
enbu import-file customers.csv --format csv --name customers

enbu import-tree \
  device/wifi.conf=./firmware/wifi.conf \
  keys/id_ed25519=./keys/id_ed25519 \
  --name embedded-device

enbu list
enbu history
enbu materialize RESOURCE_UUID output.bin --format Raw --payload content
enbu materialize FILE_TREE_UUID files.tar --format FileTreeTar
```

FileTreeは任意のnative pathへ直接展開せず、host所有のtransactional file capabilityを通して決定的tarとして出力します。

## 拡張

```bash
enbu plugin install transform.enbu-plugin.cbor trust-grant.cbor
```

WASM pluginは、署名・trust grant・出力namespaceを検証したうえで、明示的に選択されたimmutable inputだけをbounded streaming ABI経由で受け取ります。
filesystem、network、環境変数、keychain、registry、host actionへはアクセスできません。

## マルチデバイス

```bash
# 追加される端末
enbu enrollment request github:candidate request.cbor

# 既存owner
enbu enrollment approve request.cbor github:candidate assertion.cbor

# 追加される端末
enbu enrollment import assertion.cbor
```

新しい端末へaccessを付与すると、到達可能な過去CommitのGrant envelopeも公開され、fresh clientが完全な履歴を検証できます。

## 開発

```bash
task all/build
task all/test
task all/check
```
