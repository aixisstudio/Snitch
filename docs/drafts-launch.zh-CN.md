# 发布日草稿 —— 全部可直接复制

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | [Deutsch](drafts-launch.de.md) | [Русский](drafts-launch.ru.md) | [日本語](drafts-launch.ja.md) | [Português](drafts-launch.pt-BR.md) | **中文**

> **说明：** 待粘贴的英文文本保持英文——HN 与 Reddit 是英语平台。完整权威 EN/FR 版本见 `drafts-launch.md`；此处为操作摘要。

## Show HN —— 「造势」包

**时机：周二巴黎时间 14:30-15:00**（= 纽约 8:30-9:00，工作日的周二是本周最佳窗口）。不要更早：美区首页必须活跃。

**URL：** `https://github.com/aixisstudio/Snitch`

### 标题 —— 方案 A（数据钩子，推荐）

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### 标题 —— 方案 B（故事钩子，若 A 已被使用）

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### 作者首评 —— 提交后 60 秒内发布

使用 `drafts-launch.md` 中的完整作者评论——技术栈细节：ctypes→libpcap、psutil 归属、.mmdb 离线、FastAPI 127.0.0.1 + token、`SNITCH_DEMO=1`、社区完成的 Windows 移植故事。

## Reddit —— 同日 r/privacy + r/selfhosted

**标题：** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**正文：** 见 `drafts-launch.md`——诚实优先（「 I'm the author 」）、功能要点、免管理员演示、仓库链接。版块允许的话附地图截图。

## r/netsec —— 每周 Show 帖

技术角度：无 Scapy 的 ctypes→libpcap 管线、手写 ~2K 行解析器、psutil 归属、信标/DNS 隧道检测、OS 防火墙编排。用 SOC/分析师口吻，不要营销腔。

## 预备回答（防御性 FAQ）

完整回答见 `drafts-launch.md`：「GlassWire/Portmaster/OpenSnitch 呢？」「为什么用 Python 不用 Rust？」「抓包需要 root？」「外发调用？」（全部 opt-in：GeoIP、更新、TI、webhook）、「代码签名？」（SignPath 审核中 + 已公开哈希）。
