# GhostScope 脚本语言参考

GhostScope 使用专门的领域特定语言来定义追踪点和操作。脚本可以在 TUI 中使用 `trace` 命令时编写，或从脚本文件加载。

## 目录
1. [基础语法](#基础语法)
2. [追踪语句](#追踪语句)
3. [变量](#变量)
4. [打印语句](#打印语句)
5. [条件语句](#条件语句)
6. [表达式](#表达式)
7. [特殊变量](#特殊变量)
8. [示例](#示例)
9. [限制](#限制)

## 基础语法

### 注释

```ghostscope
// 单行注释

/*
   多行
   注释
*/
```

### 语句类型

GhostScope 支持以下语句类型：
- `trace` - 定义追踪点及其操作
- `print` - 输出格式化文本
- `backtrace` / `bt` - 打印调用栈（实现中）
- `if`/`else` - 条件执行
- `let` - 变量声明
- 表达式语句

## 追踪语句

`trace` 语句是定义追踪点的顶层结构。它只在脚本文件中使用，不在追踪块内部使用。

### 语法

```ghostscope
trace <模式> {
    // 命中追踪点时执行的语句
}
```

### 追踪模式

#### 函数名
```ghostscope
trace main {
    print "Main 函数被调用";
}

trace calculate_something {
    print "正在计算...";
}
```

#### 源代码行
```ghostscope
// 追踪特定文件和行号
trace sample.c:42 {
    print "到达第 42 行";
}

// 支持各种路径格式
trace /home/user/project/src/utils.c:100 {
    print "工具函数";
}
```

## 变量

### 脚本变量声明

使用 `let` 关键字声明脚本变量：

```ghostscope
let count = 0;
let threshold = 100;
let message = "hello";
let result = a + b;
```

脚本变量目前支持整数、浮点数和字符串类型。

### 局部变量、参数和全局变量

GhostScope 支持复杂的变量访问：

```ghostscope
// 简单变量
print x;

// 成员访问（结构体字段）
print person.name;
print config.settings.timeout;

// 数组访问
print arr[0];
print arr[i];

// 指针解引用
print *ptr;
print *(ptr);

// 取地址
print &variable;

// 复杂链式访问
print obj.field.subfield;
print arr[0].name;
```

### 特殊变量（实现中）

特殊变量以 `$` 开头，提供运行时信息访问：

```ghostscope
// 函数参数（x86_64 调用约定）
$arg0, $arg1, $arg2, $arg3, $arg4, $arg5

// 进程信息
$pid    // 进程 ID
$tid    // 线程 ID
$comm   // 进程名称

// 返回值（在返回探针中）
$retval

// CPU 寄存器（架构特定）
$pc     // 程序计数器
$sp     // 栈指针
```

### 变量查找顺序

当脚本中遇到变量时，GhostScope 按以下顺序查找：
1. 脚本定义的变量（使用 `let` 声明的）
2. 被追踪程序的局部变量和参数
3. 被追踪程序的全局变量

**注意**：脚本变量可能会遮蔽程序变量，命名时需要特别注意。

## 打印语句

`print` 语句在追踪期间输出信息。

### 基本形式

```ghostscope
// 打印字符串字面量
print "Hello, World";

// 打印变量
print count;

// 打印复杂表达式
print person.name;
print arr[0];
print *ptr;
```

### 格式化打印

使用 `{}` 作为格式字符串中的占位符：

```ghostscope
// 带参数的格式字符串
print "值: {}", value;
print "X: {}, Y: {}", x, y;
print "姓名: {}, 年龄: {}", person.name, person.age;
```

**注意**：格式字符串使用 `{}` 占位符（Rust 风格），而不是 `%d`/`%s`（C 风格）。

## 条件语句

GhostScope 使用 Rust 风格的条件语句语法：

```ghostscope
// 简单 if
if x > 100 {
    print "值很大";
}

// If-else
if result == 0 {
    print "成功";
} else {
    print "失败";
}

// 嵌套 if-else
if x > 100 {
    print "大";
} else if x > 50 {
    print "中";
} else {
    print "小";
}
```

### 比较运算符

- `==` - 等于
- `!=` - 不等于
- `<` - 小于
- `<=` - 小于等于
- `>` - 大于
- `>=` - 大于等于

## 表达式

### 算术运算

```ghostscope
let sum = a + b;       // 加法
let diff = a - b;      // 减法
let product = a * b;   // 乘法（不用于指针）
let quotient = a / b;  // 除法
```

### 表达式优先级

1. 括号 `()`
2. 成员访问 `.`，数组访问 `[]`
3. 指针解引用 `*`，取地址 `&`
4. 乘法 `*`，除法 `/`
5. 加法 `+`，减法 `-`
6. 比较 `==`, `!=`, `<`, `<=`, `>`, `>=`

### 表达式分组

```ghostscope
// 使用括号明确优先级
let result = (a + b) * c;
let complex = (x + y) / (a - b);
```

## 栈回溯语句（实现中）

打印当前调用栈：

```ghostscope
// 完整形式
backtrace;

// 简写形式
bt;
```

## 示例

### 基础函数追踪

```ghostscope
trace main {
    print "程序启动";
    print "PID: {}", $pid;
}
```

### 监控函数参数

```ghostscope
trace calculate {
    print "calculate({}, {})", $arg0, $arg1;

    if $arg0 > 1000 {
        print "检测到大输入";
        bt;
    }
}
```

### 条件追踪

```ghostscope
trace malloc {
    if $arg0 > 1048576 {  // 1 MB
        print "大内存分配: {} 字节", $arg0;
        backtrace;
    }
}
```

### 结构体字段访问

```ghostscope
trace process_user {
    print "用户: {}", user.name;
    print "ID: {}", user.id;

    if user.status == 1 {
        print "活跃用户";
    }
}
```

### 复杂变量访问

```ghostscope
trace handle_request {
    // 数组访问
    print "第一项: {}", items[0];

    // 嵌套结构体访问
    print "配置值: {}", config.network.timeout;

    // 指针操作
    print "解引用: {}", *ptr;
    print "地址: {}", &variable;
}
```

### 脚本文件中的多个追踪点

```ghostscope
// script.gs 文件
trace server_accept {
    print "新连接";
}

trace server_process {
    print "处理请求类型: {}", $arg0;
}

trace server_respond {
    print "发送响应代码: {}", $arg1;
}
```

## 限制

1. **无循环**：出于安全考虑，不支持循环（`for`、`while`）
2. **无函数定义**：不能定义自定义函数
3. **只读**：不能修改被追踪程序的状态
4. **无字符串操作**：不支持字符串连接或操作
5. **有限的算术运算**：仅支持基本运算，不支持位运算
6. **无动态内存**：不能分配内存

## 最佳实践

1. **保持简单**：追踪操作应该轻量以减少开销
2. **尽早过滤**：使用条件减少追踪频率
3. **有意义的输出**：在打印语句中包含上下文
4. **避免复杂逻辑**：保持追踪逻辑直观简单
5. **渐进测试**：从简单追踪开始，逐步增加复杂性

## 注意事项

- 变量声明（`let`）创建脚本局部变量，而非程序变量
- 所有变量都是动态类型
- 字符串字面量必须使用双引号
- 大多数语句需要分号
- 追踪模式匹配支持文件模糊匹配（参见[命令参考](command-reference.md)）
