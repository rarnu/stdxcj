# 仓颉编程语言 stdx

## 这个项目是对仓颉 stdx 库的另一种封装，旨在解决 stdx 库的编译和引用问题，并方便开发者使用。

### 特性

只需要简单的配置:

```toml
[package]
link-option = "-L . -lstdxcj -lz"

[dependencies]
stdx = { git = "https://github.com/rarnu/stdxcj" }
```

在上述配置中，配置了对 stdxcj 库的引用，必须先编译该库:

```shell
$ cd native
$ ./build.sh
```

此时即可在上一级目录找到编译好的库，其文件名为 ```libstdxcj.a```，将它拷贝到你的项目的根目录下，与 ```cjpm.toml``` 文件同级即可。

现在，在你的项目中自由的使用 stdx 库吧！


## 以下是官方简介

仓颉编程语言提供了 `stdx` 模块，该模块提供了网络、安全等领域的通用能力。`stdx` 的 API 详细说明请参见[资料](./doc/libs_stdx/summary_cjnative.md)。

## 目录结构

```text
/stdx
├─ build                        # 工程构建目录，编译构建工具、脚本等
├─ build_temp                   # 工程构建的临时目录
├─ doc                          # STDX 库资料目录
├─ src                          # STDX 各个包代码目录                        
│   └─ stdx                     
│       ├── aspectCJ            # 提供 AOP 功能
│       ├── compress            # 提供压缩和解压缩功能
│       ├── crypto              # 提供安全相关能力
│       ├── dynamicLoader       # Openssl 动态加载模块
│       ├── encoding            # 提供 JSON 和字符串编码相关能力。
│       ├── fuzz                # 提供基于覆盖率反馈的仓颉 fuzz 引擎及对应的接口
│       ├── log                 # 提供了日志记录相关的能力
│       ├── logger              # 提供文本格式和 JSON 格式日志打印功能
│       ├── net                 # 提供网络通信等能力
│       ├── serialization       # 提供序列化和反序列化能力
│       └─  unittest            # 提供单元测试扩展能力
│
├─ third_party                  # 第三方组件目录
└─ target                       # 编译构建产物目录
```

### 使用 stdx

在需要使用 `stdx` 的仓颉源代码文件中，通过 import 导入 `stdx` 提供的对应包，即可调用该包提供的 API。import 格式为：

**import stdx.fullPackageName.itemName**

其中 `fullPackageName` 为[包列表](./doc/libs_stdx/libs_overview.md#包列表)给出的包名，`itemName` 为可见声明或定义的名字,  `*` 表示导入所有可见的顶层声明或定义，例如：

- import stdx.net.http.ServerBuilder：导入 stdx 模块的 net.http 包中的【顶层声明】ServerBuilder。
- import stdx.net.http.\* ：导入 stdx 模块的 net.http 包。
- import stdx.log.\* ：导入 stdx 模块的 log 包。

### 使用示例

编写代码：使用 `net.http` 包创建 `HTTP` 服务。

```cangjie
package test

import stdx.net.http.ServerBuilder

main () {
    // 1. 构建 Server 实例
    let server = ServerBuilder()
                        .addr("127.0.0.1")
                        .port(8080)
                        .build()
    // 2. 注册 HttpRequestHandler
    server.distributor.register("/index", {httpContext =>
        httpContext.responseBuilder.body("Hello 仓颉!")
    })
    // 3. 启动服务
    server.serve()
}
```

## License 许可

本项目开源许可请参阅 [LICENSE](LICENSE)。
