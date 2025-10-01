# Contributing Guide

Thank you for your interest in contributing to GhostScope!

## How to Contribute

### Reporting Issues
- Use [GitHub Issues](https://github.com/swananan/ghostscope/issues)
- Provide detailed reproduction steps
- Include system information and error logs

### Submitting Code
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'feat: add new feature'`
4. Push the branch: `git push origin feature/your-feature`
5. Create a Pull Request

### Commit Message Conventions

Use conventional commits format:

```bash
git commit -m "feat: add wildcard support for function tracing"
git commit -m "fix: resolve memory leak in DWARF parser"
git commit -m "docs: update installation instructions"
```

**Before committing:**
- **Must run `cargo fmt`** to format code
- Check `git status` to avoid committing test files (*.c, *.rs test files, etc.)
- Keep messages concise (2-3 lines maximum)

**Common prefixes:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `perf:` Performance improvement

### Code Style
- Follow Rust standard format (use `cargo fmt`)
- Run `cargo clippy` for linting
- Add test cases
- Update relevant documentation

## Development Setup

Please refer to the [Development Guide](development.md) for setting up your development environment.

## Community

- [GitHub Discussions](https://github.com/swananan/ghostscope/discussions) - Questions and discussions
- Email: jt26wzz@gmail.com
