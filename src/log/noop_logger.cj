/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * This source file is part of the Cangjie project, licensed under Apache-2.0
 * with Runtime Library Exception.
 *
 * See https://cangjie-lang.cn/pages/LICENSE for license information.
 */

package stdx.log

public class NoopLogger <: Logger {
    public init() {}
    public mut prop level: LogLevel {
        get() {
            LogLevel.OFF
        }
        set(v) {
        }
    }
    public func log(record: LogRecord): Unit {}

    public func log(level: LogLevel, message: String, attrs: Array<Attr>): Unit {}

    public func log(level: LogLevel, message: () -> String, attrs: Array<Attr>): Unit {}

    public func withAttrs(attrs: Array<Attr>): Logger {
        return this
    }

    public func isClosed(): Bool {
        false
    }

    public func close(): Unit {
    }
}
