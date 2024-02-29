# Candy

另一个支持对等连接的虚拟专用网络工具.

## 什么是虚拟专用网络

互联网上存在大量自称 VPN (虚拟专用网络)的代理工具,严格意义上来说这些工具应该被称为 Proxy (代理).
两者的区别是: VPN 可以让虚拟网络中的设备相互访问; Proxy 则是把一台设备作为跳板访问另一台设备.

典型的 VPN 有 OpenVPN 和 IPSec, 以及进入 Linux 内核的 WireGuard.
典型的 Proxy 有 Socks5, Shadowsocks, V2Ray.

这个项目能且仅能帮你完成多台设备间组网.

## 为什么再实现一款虚拟专用网络工具

上面提到许多经典的 VPN, 它们已经能满足用户的绝大多数场景.
但是它们协议特征明显,在国内特殊的网络环境下,这成了缺陷,防火墙可以轻易的识别并阻断流量.
我曾是 WireGuard 用户,在防火墙的干扰下,我与网络里的其他设备失去了连接.
因此需要用设计代理的思路来设计 VPN, 让 VPN 有一定的抗防火墙的能力.

## 整体设计思路

设计的宗旨是简洁.在不牺牲性能和核心功能的情况下,用最少的代码量和最简单的概念完成设计.

### 降低配置复杂度

WireGuard 在 VPN 里配置已经相对较简单了,但对我来说依旧过于复杂.回忆一下你用多长时间完成的第一次 WireGuard 组网.
WireGuard 需要强制指定虚拟地址,不适用于想要灵活接入多个客户端并动态分配地址的场景.

用 WSS(Web Socket Secure) 处理通信,在保证链路数据安全的情况下,免去了配置公私钥的过程.
用口令校验客户端,可以轻松的让新客户端加入网络,这样就能由服务端实现地址动态分配.

### 高效的断线重连

在某些情况下 WireGuard 会断线,只有重启客户端才能解决.此时对于一个无人值守的设备,就意味着彻底失联.
曾经为了解决这个问题,给设备配置每天重启一次,这显然是一种很丑陋的解决方案.

使用 WSS 通信,就可以用 Ping/Pong 完成 TCP 保活,即使 TCP 连接异常断开,应用也可以及时发现,迅速处理.

### 支持内网穿透的对等连接

虽然 WireGuard 支持对等连接,但要求设备之间能够直接访问,对于双方都在 NAT 后面的情况无能为力.
增加内网穿透功能,可以节约服务端转发的流量,同时还能降低通信延迟.

内网穿透通过 STUN 服务器获取本地 UDP Socket 被映射后的公网地址和端口,通过服务端与其他客户端交换地址和端口信息,并尝试建立连接.

### 高速的中继路由

有时候两个客户端之间无法直连,但它们都能与另一个客户端直连.此时可以以这个客户端作为中继相互访问.

这实际上是[路由](https://zh.wikipedia.org/wiki/路由)的问题.本项目实现的是距离向量算法.

## 如何安装

这个项目编译出的命令行版本可执行文件根据参数区分以服务端模式运行还是客户端模式运行,因此安装不区分客户端与服务端.

### Linux

建议使用 Docker 镜像,已上传到 [Docker Hub](https://hub.docker.com/r/lanthora/candy) 和 [Github Packages](https://github.com/lanthora/candy/pkgs/container/candy).

Candy 会缓存上次从服务端分配到的地址,并在下次启动时优先申请使用这个地址,地址保存在 `/var/lib/candy` 目录下,启动容器服务前需要在 Host 创建一个目录用于映射,否则容器重启丢失数据将导致重新分配地址.创建与容器内相同的目录以方便理解.

```bash
mkdir -p /var/lib/candy
```

容器需要管理员权限读取设备创建虚拟网卡并设置路由,同时需要 Host 网络命名空间共享虚拟网卡.

```bash
docker run --rm --privileged=true --net=host --volume /var/lib/candy:/var/lib/candy docker.io/lanthora/candy:latest
```

Arch Linux 用户可以使用 [AUR](https://aur.archlinux.org/packages/candy).

### MacOS

请参考 [Homebrew](https://github.com/lanthora/homebrew-repo) 仓库中提供的方法安装.

Mac 默认的睡眠策略是: 1.在关闭屏幕一段时间后睡眠; 2.睡眠时收到网络包唤醒. Candy 运行过程中每 30 秒产生一个心跳,这会导致机器被频繁唤醒.对于作为服务器长期开机的 Mac 设备来说,可以关闭睡眠功能;对于作为普通设备的笔记本来说,可以关闭网络唤醒功能.参考苹果官网[睡眠与唤醒](https://support.apple.com/zh-cn/guide/mac-help/mchle41a6ccd/mac)完成设置.

### Windows

通过 Web 服务提供[安装包下载](https://dl.icandy.one/).

对于无人值守的设备: 1.请确认系统不会休眠; 2.进程启动需要管理员权限设置虚拟网卡,请确认进程不会因为用户账户控制无法正常开机启动.

### 从源码构建

可以参考 [Github Actions](.github/workflows/check.yaml) 和 [Dockerfile](dockerfile) 了解各系统构建时所需的环境.

## 如何使用

### 接入测试网络

上述客户端的[默认配置](candy.conf)会连到测试网络 172.16.0.0/16, 并被随机分配一个地址.

网络中部署了两个用于测试的客户端. 172.16.0.1 的 80 端口部署了 Web 服务. 172.16.0.2 的 1080 端口部署了的 socks5 服务.

接入网络后,除非你主动访问其他客户端,否则什么都不会发生.

### 部署私有网络

私有部署需要了解可配置的参数,下文有两个配置示例分别说明服务端和客户端的可用参数.

```bash
candy --help
```

参数可以由命令行指定.也可以通过配置文件指定.使用配置文件时需要指定路径.推荐使用配置文件,可以在不重建容器的情况下修改配置.

```bash
# 进程启动时指定配置文件路径
candy -c /path/to/candy.conf
```

#### 服务端

监听所有网卡的 80 端口,客户端连接后自动在 10.0.0.0/24 子网分配地址,并设置登录口令为 123456

```bash
candy -m "server" -w "ws://0.0.0.0:80" -d "10.0.0.0/24" -p "123456"
```

对应的配置文件内容为

```bash
mode = "server"
# 服务端不支持 wss, 需要由外部的服务加密,例如 nginx/caddy, 公网服务建议使用 wss
websocket = "ws://0.0.0.0:80"
# 不配置此项时,客户端需要指定静态地址
dhcp = "10.0.0.0/24"
# 不配置此项时,口令为空
password = "123456"
```

#### 客户端

```bash
candy -m "client" -w "ws://127.0.0.1:80" -p "123456"
# 启用对等连接
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -s "stun://stun.qq.com"
# 指定静态地址
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -t "10.0.0.1/24"
# 设置网卡名
candy -m "client" -w "ws://127.0.0.1:80" -p "123456" -n "test"
```

对应的配置文件内容为

```bash
mode = "client"
# 客户端支持 wss 协议
websocket = "ws://127.0.0.1:80"
# 服务端配置 dhcp 时,客户端可以不配置静态地址
tun = "10.0.0.1/24"
# 需要与服务端配置保持一致
password = "123456"
# 网卡名,区分单个机器上的多个客户端,仅一个客户端时可不配置
name = "test"
# 对等连接服务器,不配置此项标识不启用对等连接
stun = "stun://stun.qq.com"
```

关于路由的配置

```bash
# 路由功能在对等连接的基础上工作,对等连接是被动启动,
# 有些设备本可以作为中继,但由于此前没有与中继设备的流量导致无法使用路由.
# 此配置以秒为单位周期性的尝试让网络中的其他设备与本设备建立对等连接.
# 不添加此配置或者配置为 0 表示不启用主动发现.
discovery = 300

# 当消息通过本机作为中继转发时在本机内部消耗的代价.
# 此配置以毫秒为单位与直连设备间的真实时延求和作为以本机为路由的代价广播.
# 不配置或者配置配置为 0 表示不启用路由加速.
route = 5
```

## 未来的发展方向

除了正常的安全更新和问题修复,短期内不计划新增功能,希望这个软件可以像空气一样,让用户意识不到它的存在.

## 相似产品

- [WireGuard](https://www.wireguard.com/): fast, modern, secure VPN tunnel
- [n2n](https://github.com/ntop/n2n): Peer-to-peer VPN
- [ZeroTier](https://www.zerotier.com/): Global Area Networking
- [Tailscale](https://tailscale.com/): Best VPN Service for Secure Networks

## 联系我们

[Telegram Group](https://t.me/CandyUserGroup)
