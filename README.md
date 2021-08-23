## 说明
- 用于测试libsodium的chacha20加密解密实现，使用VS2015编译测试
- dll工程对加密解密API进行了封装，方便使用，属于平台无关代码实现，可以移植到任何POSIX平台，dll工程依赖libsodium库(下载最新[libsodium](https://download.libsodium.org/libsodium/releases/)官方库，进入libsodium\builds\msvc\vs2015，使用VS2015进行Release编译)
- libsodium_test_client作为TCP client客户端，可以修改连接的服务器地址，然后读取10个文本文件，并发送给server端
- libsodium_test_server作为TCP server服务端，在windows上运行，接收客户端的连接，然后进行TCP解密并拆包

## 关于加密算法的实现描述
- 加密/解密原理参考设计：https://github.com/shadowsocks/shadowsocks-libev.git 非常感谢。
- 加密解密需要依赖nonce和key，以及counter计数，nonce即随机数，由客户端生成并在第一次建立连接后发送给服务端，key即秘钥，32 BYTE长度，客户端/服务端每发送、接收完N BYTE密文数据，都要对加密/解密counter进行累加N BYTE，counter类型为uint64_t类型
- 每次客户端重新和服务端建立连接，都重新生成并发送8 BYTE的随机数nonce，确保即使同一个客户端同样的明文数据，不同的连接，产生的密文也是不一样的
- 加密/解密不影响数据字节长度，长度保持不变
- 加密/解密前数据包长度必须要64 BYTE padding对齐，即数据包长度对64进行模运算，如果结果大于零，则在数据包前填充相应长度数据，内容为0，加密/解密完成后去掉之前padding的数据长度，得到相应的密文/明文，举例：客户端需要加密60 BYTE的明文，不足64 BYTE，需要在数据前补4 BYTE然后进行加密，完成后去掉前面补的4 BYTE，得到60 BYTE密文，然后进行发送； 接收端收到60 BYTE密文以后，需要在前面补4 BYTE，再进行解密，然后去掉前面补的4 BYTE，得到明文。反之亦然。
- 由于是对称加密，key的安全非常重要，关乎到整个协议传输内容的安全性，所以key的管理分发必须谨慎处理，每个服务端都应该有自己的key，任何客户端需要和服务端收发消息，必须先拿到相应的key(可以通过其他方式实现key分发、比如绑定、SSL key交换算法等等)，即服务端必须有授权认证机制，key在这里扮演授权加密角色，任何没有被授权的客户端，是无法访问该服务的。

## TCP协议说明
- TCP的封包机制，TLV模式，即type length value模式，接收端接收固定长度的包头header，然后拆出后续的包体body长度，同时header进行CRC16计算，不符合则判定为非法数据包
