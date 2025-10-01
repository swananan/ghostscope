# 贡献指南

感谢您对 GhostScope 的关注！我们欢迎各种形式的贡献。

## 如何贡献

### 报告问题
- 使用 [GitHub Issues](https://github.com/swananan/ghostscope/issues)
- 提供详细的重现步骤
- 包含系统信息和错误日志

### 提交代码
1. Fork 仓库
2. 创建功能分支：`git checkout -b feature/your-feature`
3. 提交更改：`git commit -m 'feat: add new feature'`
4. 推送分支：`git push origin feature/your-feature`
5. 创建 Pull Request

### 提交消息规范

使用 conventional commits 格式：

```bash
git commit -m "feat: add wildcard support for function tracing"
git commit -m "fix: resolve memory leak in DWARF parser"
git commit -m "docs: update installation instructions"
```

**提交前检查：**
- 必须运行 `cargo fmt` 格式化代码
- 检查 `git status` 确保不提交测试文件（*.c, *.rs 测试文件等）
- 消息最多 2-3 行，保持简洁清晰

**常用前缀：**
- `feat:` 新功能
- `fix:` Bug 修复
- `docs:` 文档更新
- `test:` 测试相关
- `refactor:` 代码重构
- `perf:` 性能优化

### 代码规范
- 遵循 Rust 标准格式（使用 `cargo fmt`）
- 运行 `cargo clippy` 检查代码
- 添加测试用例
- 更新相关文档

## 开发环境设置

请参考[开发指南](development.md)了解如何设置开发环境。
