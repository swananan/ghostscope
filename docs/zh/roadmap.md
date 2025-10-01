# 未来规划

## 栈回溯（Stack Unwinding）

支持在追踪点处获取完整的函数调用栈，基于 `.eh_frame` 解析实现。

**参考**：https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way#h5.1-parsing-eh_frame-and-eh_frame_hdr-with-gimli

## 稳定性和准确性提升

作为辅助排查问题的工具，准确性是第一位的。将持续修复 bug，完善错误处理，提升追踪数据的可靠性。

## 高级语言特性支持

两个主要方向：

1. **编译型语言高级特性**：优先支持 Rust 的高级特性（如异步函数、trait 对象等）
2. **解释型语言支持**：探索对特定解释型语言的追踪支持（如 Lua）
