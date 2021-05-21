# ipip-tunnel

重庆大学2018级信息安全基础课的实验。

编写一个支持单臂网卡使用的ipip tunnel，使用PF_PACKET的二层Socket手动实现。

由于程序进行了IP Fragment，因此不需要降低MTU即可使用（但实测发现不降低MTU效率较低），但本项目只是个课程项目用的玩具，由于作为用户进程运行效率较低，不建议实际部署，且内核也自带了该模块。

## 1. 编译程序

```bash
g++ main.cpp -o ipip-tunnel
```

## 2. 准备环境

首先，将4台电脑连接在一个局域网中，假设4台电脑的网卡均为ens192。四台电脑网卡的主IP分别为172.16.0.2、172.16.0.3、172.16.0.4、172.16.0.5。

按照以下操作给网卡添加第二IP地址，并设置路由表或开启ipip-tunnel转发程序。

- PC1

```bash
ip addr add 192.168.0.2/24 dev ens192
ip route add 192.168.1.0/24 via 192.168.0.1 src 192.168.0.2
```

- PC2

```bash
ip addr add 192.168.0.1/24 dev ens192
./ipip-tunnel -l ens192 -peer 172.16.0.3
```

- PC3

```bash
ip addr add 192.168.1.1/24 dev ens192
./ipip-tunnel -l ens192 -peer 172.16.0.2 -left 192.168.1.0 -right 192.168.0.0
```

- PC4

```bash
ip addr add 192.168.1.2/24 dev ens192
ip route add 192.168.0.0/24 via 192.168.1.1 src 192.168.1.2
```

## 3. 进行测试

- ping PC1->PC4:

```bash
cyy@PC-1:~$ ping 192.168.1.2
PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
64 bytes from 192.168.1.2: icmp_seq=1 ttl=62 time=0.507 ms
64 bytes from 192.168.1.2: icmp_seq=2 ttl=62 time=0.609 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=62 time=0.550 ms
^C
--- 192.168.1.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2053ms
rtt min/avg/max/mdev = 0.507/0.555/0.609/0.041 ms
```

- iperf3 PC1->PC4

```bash
cyy@PC-1:~$ iperf3 -c 192.168.1.2 
Connecting to host 192.168.1.2, port 5201
[  5] local 192.168.0.2 port 59622 connected to 192.168.1.2 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   765 KBytes  6.27 Mbits/sec  130   1.41 KBytes       
[  5]   1.00-2.00   sec   660 KBytes  5.41 Mbits/sec  219   2.83 KBytes       
[  5]   2.00-3.00   sec  1.22 MBytes  10.2 Mbits/sec  302   5.66 KBytes       
[  5]   3.00-4.00   sec   911 KBytes  7.46 Mbits/sec  304   5.66 KBytes       
[  5]   4.00-5.00   sec   912 KBytes  7.47 Mbits/sec  310   5.66 KBytes       
[  5]   5.00-6.00   sec  1.13 MBytes  9.50 Mbits/sec  368   5.66 KBytes       
[  5]   6.00-7.00   sec   904 KBytes  7.40 Mbits/sec  304   5.66 KBytes       
[  5]   7.00-8.00   sec   669 KBytes  5.48 Mbits/sec  242   5.66 KBytes       
[  5]   8.00-9.00   sec  1007 KBytes  8.25 Mbits/sec  336   5.66 KBytes       
[  5]   9.00-10.00  sec   908 KBytes  7.44 Mbits/sec  278   5.66 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  8.93 MBytes  7.49 Mbits/sec  2793             sender
[  5]   0.00-10.00  sec  8.83 MBytes  7.41 Mbits/sec                  receiver

iperf Done.
```

注：以上测试在AMD Ryzen 2700上的VMWare ESXi虚拟机中进行，测试主机内核为Linux 5.10，TCP拥塞控制算法采用Cubic。
