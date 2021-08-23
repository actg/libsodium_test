## 说明
- 用于测试libsodim的chacha20加密解密实现，使用VS2015编译测试
- dll工程对加密解密API进行了封装，方便使用，依赖libsodium库，但属于平台无关代码实现，可以移植到任何POSIX平台
- libsodium_test_client作为TCP client客户端，可以修改连接的服务器地址，然后读取10个文本文件，并发送给server端
- libsodium_test_server作为TCP server服务端，在windows上运行，接收客户端的连接，然后进行TCP解密并拆包
- TCP封包机制，TLV模式，即type length value模式