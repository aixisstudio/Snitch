# コード署名

[English](SIGNING.md) | [Français](SIGNING.md) | [Español](SIGNING.es.md) | [Deutsch](SIGNING.de.md) | [Русский](SIGNING.ru.md) | **日本語** | [Português](SIGNING.pt-BR.md) | [中文](SIGNING.zh-CN.md)

## 現状

Snitch のビルドは Windows/macOS とも**未署名**。これは正直かつ意図的:
署名の意味を損なう自己署名証明書は出さず、オープンソース向けの合法
かつ無料の道がある限り証明書も購入しない。

## Windows — SignPath Foundation（OSS 無料）

[SignPath](https://signpath.org) は条件を満たす OSS プロジェクトに
**無料の Authenticode 署名**を提供する。承認されたプロジェクトは
`release-signing` ポリシーを得て公的に信頼される署名が付く —
評判が育てば SmartScreen の警告も消える。

### セットアップ（一度のみ、メンテナ向け）

1. <https://signpath.org/apply> で申請 — 名前、メール、プロジェクト名、
   リポジトリ URL、説明を問うフォーム。承認は手動（数日）。Snitch は
   公開条件を全て満たす: AGPL-3.0（OSI 承認、デュアルライセンス無）、
   全ソース公開、活発に保守、GitHub Releases で公開済、文書化済。
   **申請送信済 — 審査待ち。**
2. SignPath 組織を作成し、**プロジェクト**（slug、例 `Snitch`）に
   trusted build system *GitHub.com* をリンク、SignPath GitHub App を
   このリポジトリにインストール（origin 検証に必須）。
3. **release-signing ポリシー**をタグビルド限定で作成、ZIP 内 `*.exe`
   に合う artifact 設定（標準テンプレートで可）。
4. GitHub → *Settings → Secrets and variables → Actions*:
   - Variables: `SIGNPATH_ORGANIZATION_ID`、`SIGNPATH_PROJECT_SLUG`、
     `SIGNPATH_POLICY_SLUG`
   - Secret: `SIGNPATH_API_TOKEN`
5. 完了 — CI ジョブ `SignPath — submit signing request` が次のタグで
   自動起動: 未署名インストーラをアップロードし、署名済コピーを待ち、
   リリース前にアーティファクトを差し替える。**ステップ 4 まで全て不活性。**

## macOS — 無料の道はない

Apple は Developer ID 証明書＋公証に有料の **Developer Program**
（$99/年）を要求。合法な無料代替は存在しない。それまでは:

- `.zip`/`.dmg` は未署名のまま — 初回起動は**右クリック → 開く**、
  または `xattr -d com.apple.quarantine Snitch.app`
- 各リリースの SHA256 チェックサムで完全性を検証可能
- 公開 CI ビルドログが出処を保証（再現可能パイプライン）

`APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_PASSWORD` / `MACOS_CERT_P12`
が設定されれば、CI の `ENABLE_CODESIGNING` プレースホルダがフックに
なる。

## 検討し却下した代替案

| 案 | 却下理由 |
|---|---|
| Azure Trusted Signing | ~$10/月 — 無料ではない; Free/Trial/スポンサー Azure サブスクは明示的に非対応 |
| Microsoft Store (MSIX) | Microsoft が認証後に無料再署名 — ただし Store 配布のみ; 将来のチャネル |
| 自己署名証明書 | SmartScreen/Gatekeeper の信頼を損なう — 未署名より悪い |
| コミュニティ/共有証明書 | CA 条項上違法 — 絶対に使わない |
