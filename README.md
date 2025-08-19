# Cangjie stdx

## This project is another wrapper for the Cangjie stdx library, designed to solve compilation and reference issues with the stdx library and make it easier for developers to use.

### Feature

Just a few simple steps:

```toml
[package]
link-option = "-L . -lstdxcj -lz"

[dependencies]
stdx = { git = "https://github.com/rarnu/stdxcj" }
```

In the above configuration, a reference to the stdxcj library is configured, which must be compiled first:

```shell
$ cd native
$ ./build.sh
```

At this point, you can find the compiled library in the parent directory. Its filename is ```libstdxcj.a```. Copy it to the root directory of your project, placing it at the same level as the ```cjpm.toml``` file.

Now, It's free to use the stdx library in your projects!


## Here is the Official Introduction

Cangjie programming language provides `stdx` module, which provides common capabilities in the fields of network, security, etc. For detailed description of `stdx` API, please refer to the [document](./doc/libs_stdx/summary_cjnative.md).

## Project Directory

```text
/stdx
├─ build                        # Directory of Engineering Construction
├─ build_temp                   # Temporary directory for project construction
├─ doc                          # Directory of STDX library document
├─ src                          # Directory of STDX package codes                     
│   └─ stdx                     
│       ├── aspectCJ            # Provides AOP
│       ├── compress            # Provides compression and decompression 
│       ├── crypto              # Provide security related capabilities
│       ├── dynamicLoader       # Openssl dynamic loading module
│       ├── encoding            # Provide JSON and string encoding related capabilities
│       ├── fuzz                # Provides the Cangjie fuzz engine based on coverage feedback
│       ├── log                 # Provides logging related
│       ├── logger              # Provides log printing functions in text format and JSON format
│       ├── net                 # Provide network communication and other capabilities
│       ├── serialization       # Provides serialization and deserialization
│       └─  unittest            # Provides unit testing extension
│
├─ third_party                  # Directory of third-party components
└─ target                       # Directory of constructed products
```

### Using stdx

In the Cangjie source code file that needs to use `stdx`, import the corresponding package provided by `stdx` through import, and then call the API provided by the package. The import format is:

**import stdx.fullPackageName.itemName**

`fullPackageName` is the package name given in [package list](./doc/libs_stdx_en/libs_overview.md#package-list), `itemName` is the name of a visible declaration or definition,  `*` means importing all visible top-level declarations or definitions, for example:

- import stdx.net.http.ServerBuilder：Import the top-level declaration of ServerBuilder in the net.http package of the stdx module.
- import stdx.net.http.\* ：Import the net.http package of the stdx module.
- import stdx.log.\* ：Import the log package from the stdx module.

### Usage Examples

Write code: Create an `HTTP` service using the `net.http` package.

```cangjie
package test

import stdx.net.http.ServerBuilder

main () {
    // 1. Build a Server instance
    let server = ServerBuilder()
                        .addr("127.0.0.1")
                        .port(8080)
                        .build()
    // 2. Register HttpRequestHandler
    server.distributor.register("/index", {httpContext =>
        httpContext.responseBuilder.body("Hello 仓颉!")
    })
    // 3. Start the service
    server.serve()
}
```

## License

Please see [LICENSE](LICENSE) for more information.
