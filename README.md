# DSH Security Suite

`dsh-security-suite` brings the security-review methodology of [OpenAI Codex Security](https://github.com/openai/codex-security) to [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) as a native Cordis bundle.

> DeepSeek Harness is in developer preview; its plugin API may introduce breaking changes.

It is an independent implementation, not a wrapper around Codex Security's CLI. The plugin adds a security assessment section to the system prompt and exposes a read-only `security_assess` tool for quick candidate discovery. The agent validates candidate paths before presenting findings.

## Install

Build the package, then add it to every profile where it should be available:

```sh
npm install
npm run build
dsh plugin --profile web add /absolute/path/to/dsh-security-suite
dsh plugin --profile headless add /absolute/path/to/dsh-security-suite
```

Verify the profile composition and run a scan:

```sh
dsh --profile web --dump-config
dsh run "Assess this workspace for security vulnerabilities."
```

## Configuration

The bundle row accepts these settings:

```yaml
config:
  enabled: true
  maxFiles: 500
  maxFileBytes: 262144
```

The scan only reads source files inside the current workspace. It ignores dependency and build directories, limits the file count and file size, and rejects paths outside the workspace. Its output is candidate evidence, not a vulnerability verdict.

## Attribution

This project adapts the workflow concepts of [OpenAI Codex Security](https://github.com/openai/codex-security), which is licensed under Apache-2.0. No upstream source code is copied into this repository.

## License

Apache-2.0.
