# DSH Security Suite

> [English](README.md) · [中文](README.zh-CN.md)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）的原生安全评估套件，
架构改编自 [openai/codex-security](https://github.com/openai/codex-security)（Apache-2.0）。

它在 DSH 内运行仓库、diff 和深度安全扫描：**由 LLM 评审子代理负责发现**（baseline auditor、
定向调查员、文件评审与深度 worker），确定性引擎产出证据基线，每个可报告发现都必须绑定
claim-token 验证收据和攻击路径收据才能定稿。

## 快速开始

```sh
npm install
npm run build
dsh plugin --profile web add /absolute/path/to/dsh-security-suite
```

```sh
dsh run "Run a deep security scan, validate candidates, trace attack paths, and produce a report for this workspace."
```

## 能力一览

| 工作流 | 说明 |
| --- | --- |
| 标准扫描 | 一个独立 baseline auditor + 按 source-backed investigation packets 派发的定向调查员 DSH 子代理（`security_scan`，默认 `discovery: llm`） |
| Diff 扫描 | 每个变更文件一个受限 file-review 子代理，锚定变更代码（`security_review_diff`，默认 `discovery: llm`） |
| 深度扫描 | 每轮六个 worker，各持独立评审镜头，每轮一个语义归约器，stop-after-no-new 饱和 |
| 确定性回退 | 规则/AST/流分析引擎经 `discovery: engine` 保留，并始终产出收据基线 |
| 验证与攻击路径 | claim-token 绑定的验证与攻击路径收据；带快照校验的隔离运行时证据 |
| 跟踪 | GitHub / Jira / Linear issue 与私有 GitHub draft advisory，含预览、查重、readback |
| 分诊与积压 | 导入 GitHub REST 发现或 Jira/Linear 票据，对照本地源码证据分诊 |
| 修复 | 审阅 + 审批门控的原子多文件补丁，含回滚与验证扫描 |
| 导出 | Markdown、JSON、SARIF、CSV；规范 `scan-manifest.json` / `findings.json` / `coverage.json` |
| 其他 | 威胁模型、漏洞报告、加固组合、披露 campaign、批量扫描、pre-commit 钩子 |

完整工具面与证据模型见 [docs/evidence-contract.md](docs/evidence-contract.md)（英文）。

## 发现是如何工作的

- **标准扫描（`discovery: llm`，默认）**：插件从扫描收据冻结范围内 worklist，启动一个独立
  baseline auditor 子代理，构建源码支撑的威胁地图，把评审问题分组为 investigation packets，
  每个 packet 派发一个定向调查员子代理。每个候选必须引用收据内的范围内位置。
- **Diff 扫描（`discovery: llm`，默认）**：每个变更源码文件分配给一个受限 file-review
  子代理，完整通读该文件。
- **深度扫描**：每轮六个 worker，各持不同评审镜头（正向数据流、自 sink 反向、授权逻辑、
  开放式、解析器、机密与密码学），评审不可变 200 行区域；语义归约器子代理合并跨 worker
  等价候选；饱和需要连续 `stopAfterNoNew` 轮零新颖性。
- **引擎模式（`discovery: engine`）**：确定性规则/AST/流分析引擎，覆盖 JS/TS、Python、Go、
  Java、C#、PHP、Ruby、C、C++、Rust。

发现永不自动确认漏洞。一个发现只有在获得源码支撑的验证收据 + 单独认领的攻击路径收据之后
才可报告。

## 配置

```yaml
config:
  enabled: true
  maxFiles: 500
  maxFileBytes: 262144
  deepScan:                 # 深度扫描引擎（codex-security 语义）
    workers: auto           # 正整数，或 'auto'（上限 6）
    stopAfterNoNew: 6       # 连续零新颖性轮数达到后饱和
    maxDiscoveryRuns: 60
    maxTimeHours: 96
  knowledgeBase: []         # Markdown 或纯文本文件/目录，只读
  scanPrompt: ''            # 注入每个 LLM 发现 worker 的额外指令
```

状态存放在 `DSH_SECURITY_SUITE_STATE_DIR` 或 `stateDir`（默认 `~/.dsh-security-suite`）；
引擎把仓库与知识库路径限制在活动工作区内。

## 文档

- [docs/evidence-contract.md](docs/evidence-contract.md)（英文）— 证据模型、收据、覆盖语义与
  逐规则分析边界
- [MIGRATION.md](MIGRATION.md)（英文）— codex-security 能力矩阵与迁移状态

## 归属声明

Worker 提示词模板、规范扫描契约字段树、severity 策略与深度扫描配置语义改编自
[openai/codex-security](https://github.com/openai/codex-security)（Apache-2.0）。
不执行任何第三方安全运行时源码或依赖。

## 许可证

Apache-2.0。
