# 代码签名

[English](SIGNING.md) | [Français](SIGNING.md) | [Español](SIGNING.es.md) | [Deutsch](SIGNING.de.md) | [Русский](SIGNING.ru.md) | [日本語](SIGNING.ja.md) | [Português](SIGNING.pt-BR.md) | **中文**

## 现状

Snitch 的 Windows 和 macOS 构建**均未签名**。这是诚实且刻意的决定：
我们不会发布使签名失去意义的自签名证书，也不会在为开源项目存在
合法免费途径时购买证书。

## Windows —— SignPath Foundation（开源免费）

[SignPath](https://signpath.org) 为符合条件的开源项目提供**免费
Authenticode 签名**。获批项目获得 `release-signing` 策略，产生公开
可信签名——信誉积累后 SmartScreen 不再警告。

### 配置（一次性，仅维护者）

1. 在 <https://signpath.org/apply> 申请——表单需要姓名、邮箱、项目名、
   仓库 URL 和描述。人工审核（数天）。Snitch 满足全部公开条件：
   AGPL-3.0（OSI 批准，无双许可）、源码完全公开、活跃维护、已在
   GitHub Releases 发布、有文档。**申请已提交——等待审核。**
2. 创建 SignPath 组织、一个**项目**（slug，如 `Snitch`），关联可信
   构建系统 *GitHub.com*，并在本仓库安装 SignPath GitHub App（来源
   验证所必需）。
3. 创建仅限 tag 构建的 **release-signing 策略**，artifact 配置覆盖
   ZIP 中的 `*.exe`（标准模板即可）。
4. 在 GitHub → *Settings → Secrets and variables → Actions*：
   - 变量：`SIGNPATH_ORGANIZATION_ID`、`SIGNPATH_PROJECT_SLUG`、
     `SIGNPATH_POLICY_SLUG`
   - 密钥：`SIGNPATH_API_TOKEN`
5. 完成——CI 任务 `SignPath — submit signing request` 在下一个 tag
   自动激活：上传未签名安装包，等待签名副本，在 release 上传前替换
   构件。**第 4 步之前一切不生效。**

## macOS —— 没有免费途径

Apple 要求付费的 **Developer Program** 会员（$99/年）才能获得
Developer ID 证书 + 公证。没有合法的免费替代方案。在此之前：

- `.zip`/`.dmg` 保持未签名——首次启动需**右键 → 打开**，或
  `xattr -d com.apple.quarantine Snitch.app`
- 每个 release 的 SHA256 校验和可验证完整性
- 公开的 CI 构建日志提供来源证明（可复现流水线）

如果将来配置了 `APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_PASSWORD` /
`MACOS_CERT_P12`，CI 中的 `ENABLE_CODESIGNING` 占位步骤即为接入点。

## 已评估并否决的替代方案

| 方案 | 否决原因 |
|---|---|
| Azure Trusted Signing | ~$10/月——不免费；免费/试用/赞助 Azure 订阅被明确不支持 |
| Microsoft Store (MSIX) | Microsoft 认证后免费重签——但仅限 Store 分发；留作未来渠道 |
| 自签名证书 | 抵消 SmartScreen/Gatekeeper 信任——比不签更糟 |
| 社区/共享证书 | 违反 CA 条款属违法——绝不使用 |
