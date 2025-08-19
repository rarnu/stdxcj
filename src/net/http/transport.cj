/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * This source file is part of the Cangjie project, licensed under Apache-2.0
 * with Runtime Library Exception.
 *
 * See https://cangjie-lang.cn/pages/LICENSE for license information.
 */

package stdx.net.http

import std.net.*

type Connector = (SocketAddress) -> StreamingSocket

let TcpSocketConnector = {
    sa: SocketAddress =>
    let socket = TcpSocket(sa)
    socket.connect()
    return socket
}

public struct TransportConfig {
    private var _readTimeout: Duration = Duration.Max
    private var _writeTimeout: Duration = Duration.Max
    private var _readBufferSize: ?Int64 = None
    private var _writeBufferSize: ?Int64 = None
    private var _keepAliveConfig: SocketKeepAliveConfig = SocketKeepAliveConfig()

    public mut prop readTimeout: Duration {
        get() {
            _readTimeout
        }
        set(v) {
            _readTimeout = checkDuration(v)
        }
    }

    public mut prop writeTimeout: Duration {
        get() {
            _writeTimeout
        }
        set(v) {
            _writeTimeout = checkDuration(v)
        }
    }

    public mut prop readBufferSize: ?Int64 {
        get() {
            _readBufferSize
        }
        set(v) {
            _readBufferSize = v
        }
    }

    public mut prop writeBufferSize: ?Int64 {
        get() {
            _writeBufferSize
        }
        set(v) {
            _writeBufferSize = v
        }
    }

    public mut prop keepAliveConfig: SocketKeepAliveConfig {
        get() {
            _keepAliveConfig
        }
        set(v) {
            _keepAliveConfig = v
        }
    }
}
