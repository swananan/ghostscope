# Roadmap

## Stack Unwinding

Support capturing complete function call stacks at trace points, implemented via `.eh_frame` parsing.

**Reference**: https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way#h5.1-parsing-eh_frame-and-eh_frame_hdr-with-gimli

## Stability and Accuracy Improvements

As a debugging tool, accuracy is paramount. Continuous efforts to fix bugs, improve error handling, and enhance trace data reliability.

## Performance Optimization with bpftime

Consider migrating from kernel-based uprobe to [**bpftime**](https://github.com/eunomia-bpf/bpftime) for userspace eBPF execution. This could significantly improve tracing performance by avoiding kernel context switches.

**Reference**: https://github.com/eunomia-bpf/bpftime

## Advanced Language Features

Two main directions:

1. **Compiled Language Features**: Priority support for Rust advanced features (async functions, trait objects, etc.)
2. **Interpreted Language Support**: Explore tracing support for specific interpreted languages (e.g., Lua)
