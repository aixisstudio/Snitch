# Linux 打包

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | [Deutsch](PACKAGING.de.md) | [Русский](PACKAGING.ru.md) | [日本語](PACKAGING.ja.md) | [Português](PACKAGING.pt-BR.md) | **中文**

## 发布的格式

| 格式 | 文件 | 说明 |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | 便携，需要 `libfuse2`；更新信息经 `latest-linux.yml` |
| deb | `snitch-linux-amd64.deb` | 标准 Debian/Ubuntu 安装 |
| snap | `Snitch-amd64.snap` | 严格限制（strict confinement）——见下文 |

## Snap —— 沙箱限制下的抓包

Snap 由 electron-builder（`linux.target` 含 `"snap"`）以 strict 模式
构建。抓包使用 `AF_PACKET` 套接字，`network-observe` 接口授予该权限
（与 `tcpdump` snap 相同的模式）。安装本地 `.snap` 后：

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # 授予 AF_PACKET 读取
```

不连接该接口时 UI 正常但抓包为空。发布到 Store 后，人工审核通过会
自动连接该接口；在此之前必须手动连接。

## Flatpak —— 有意不提供

Flatpak 沙箱无法授予 `AF_PACKET`：没有任何 portal 或 `finish-args`
组合能暴露原始抓包，而经 `psutil` 的进程归属需要沙箱拒绝提供的
宿主机 `/proc` 可见性。发布 Flatpak 只会得到一个永远看不到数据包的
漂亮 UI——与其造假，不如不发布。若 flathub 日后提供抓包权限，会重新
评估。

## rpm + Homebrew 配方 + 发布流水线

`release.yml` 工作流（每个 `v*` tag 或 `workflow_dispatch`）运行四个发布任务：**nfpm** 构建 `snitch-linux-amd64.rpm`（nfpm v2.48，`packaging/nfpm.yaml`）；**homebrew** 将 `Formula/snitch.rb` 推送到 `aixisstudio/homebrew-tap` 并安装无头 `snitchd` 守护进程（`brew install aixisstudio/tap/snitch`，需要 `HOMEBREW_TAP_TOKEN`）；**winget** 在存在 `Snitch-Setup-*.exe` 资产时通过 winget-releaser 提交（`WINGET_TOKEN`）；**chocolatey** 在配置 `CHOCO_API_KEY` 后打包/发布 `installer/Snitch.nuspec`。
