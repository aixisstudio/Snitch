# Linux パッケージング

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | [Deutsch](PACKAGING.de.md) | [Русский](PACKAGING.ru.md) | **日本語** | [Português](PACKAGING.pt-BR.md) | [中文](PACKAGING.zh-CN.md)

## 提供フォーマット

| フォーマット | ファイル | 備考 |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | ポータブル、`libfuse2` が必要；更新情報は `latest-linux.yml` 経由 |
| deb | `snitch-linux-amd64.deb` | 標準的な Debian/Ubuntu インストール |
| snap | `Snitch-amd64.snap` | strict コンファインメント — 下記参照 |

## Snap — コンファインメント下でのパケットキャプチャ

Snap は electron-builder（`linux.target` に `"snap"` を含む）が strict
confinement でビルド。キャプチャは `AF_PACKET` ソケットを使い、
`network-observe` インターフェースがこれを許可（`tcpdump` snap と同じ
モデル）。ローカル `.snap` をインストール後:

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # AF_PACKET 読み取りを許可
```

この接続が無いと UI は動くがキャプチャは空のまま。Store 公開すれば
人間のレビュー後に自動接続される；それまでは手動接続が必要。

## Flatpak — あえて提供しない

Flatpak のサンドボックスは `AF_PACKET` アクセスを許可できない: 生の
パケットキャプチャを公開する portal も `finish-args` の組合せも存在
せず、`psutil` によるプロセス帰属にはサンドボックスが拒否するホスト
`/proc` の可視性が必要。Flatpak を出せばパケットを一切見られない綺麗な
UI になるだけ — 壊れたアプリを出すより公開しない方を選ぶ。flathub が
キャプチャ可能なパーミッションを追加すれば再検討する。

## rpm + Homebrew フォーミュラ + リリースパイプライン

`release.yml` ワークフロー（`v*` タグまたは `workflow_dispatch` ごと）は 4 つの公開ジョブを実行します：**nfpm** は `snitch-linux-amd64.rpm` をビルド（nfpm v2.48、`packaging/nfpm.yaml`）；**homebrew** は `Formula/snitch.rb` を tap `aixisstudio/homebrew-tap` にプッシュしヘッドレス `snitchd` デーモンをインストール（`brew install aixisstudio/tap/snitch`、`HOMEBREW_TAP_TOKEN` が必要）；**winget** はアセットがあれば `Snitch-Setup-*.exe` を winget-releaser で提出（`WINGET_TOKEN`）；**chocolatey** は `CHOCO_API_KEY` があれば `installer/Snitch.nuspec` をパック/公開。
