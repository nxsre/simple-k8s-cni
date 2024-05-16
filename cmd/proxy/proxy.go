package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docker/go-connections/proxy"
	jsoniter "github.com/json-iterator/go"
	goipam "github.com/metal-stack/go-ipam"
	"github.com/nxsre/cph-pilot-ng/pkg/container"
	"github.com/nxsre/simple-k8s-cni/nettools"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"net/netip"
	"time"
)

type PluginConf struct {
	// NetConf 里头指定了一个 plugin 的最基本的信息, 比如 CNIVersion, Name, Type 等, 当然还有在 containerd 中塞进来的 PrevResult
	types.NetConf

	// 这个 runtimeConfig 是可以在 /etc/cni/net.d/xxx.conf 中配置一个
	// 类似 "capabilities": {"xxx": true, "yyy": false} 这样的属性
	// 表示说要在运行时开启 xxx 的能力, 不开启 yyy 的能力
	// 然后等容器跑起来之后(或者被拉起来之前)可以直接通过设置环境变量 export CAP_ARGS='{ "xxx": "aaaa", "yyy": "bbbb" }'
	// 来开启或关闭某些能力
	// 然后通过 stdin 标准输入读进来的数据中就会多出一个 RuntimeConfig 属性, 里面就是 runtimeConfig: { "xxx": "aaaa" }
	// 因为 yyy 在 /etc/cni/net.d/xxx.conf 中被设置为了 false
	// 官方使用范例: https://kubernetes.feisky.xyz/extension/network/cni
	// cni 源码中实现: /cni/libcni/api.go:injectRuntimeConfig
	RuntimeConfig *struct {
		TestConfig map[string]interface{} `json:"testConfig"`
	} `json:"runtimeConfig"`

	// 这里可以自由定义自己的 plugin 中配置了的参数然后自由处理
	Bridge string `json:"bridge"`
	Subnet string `json:"subnet"`
}

func main() {
	// 测试代码执行后, 可通过执行 ./clear.sh testcni0 来清掉测试的操作,
	// 不过注意不同节点上要把对应的其他节点 ip 改咯

	type CNIArgs struct {
		ContainerID string
		Netns       string
		IfName      string
		Args        string
		Path        string
		StdinData   []byte
	}

	args := &CNIArgs{
		ContainerID: "8c4609110520c",
		IfName:      "eth99",
		StdinData:   []byte("{\"bridge\":\"testcni0\",\"capabilities\":{\"test1\":true,\"test2\":false},\"cniVersion\":\"0.3.0\",\"name\":\"testcni\",\"subnet\":\"10.244.0.0/16\",\"type\":\"testcni\"}"),
	}

	pluginConfig := &PluginConf{}
	if err := jsoniter.Unmarshal(args.StdinData, pluginConfig); err != nil {
		fmt.Println("args.StdinData 转 pluginConfig 失败: ", err.Error())
		return
	}
	log.Println("------------")
	data, err := container.InspectContainer(args.ContainerID)
	if err != nil {
		log.Fatalln(err)
	}
	var nsPath string
	for _, v := range data.Info.RuntimeSpec.Linux.Namespaces {
		if v.Type == "network" {
			nsPath = v.Path
		}
	}

	// 获取网桥名字
	bridgeName := pluginConfig.Bridge
	if bridgeName != "" {
		bridgeName = "testcni0"
	}
	// 这里如果不同节点间通信的方式使用 vxlan 的话, 这里需要变成 1460
	// 因为 vxlan 设备会给报头中加一个 40 字节的 vxlan 头部
	mtu := 1500
	// 获取 containerd 传过来的网卡名, 这个网卡名要被插到 net ns 中
	ifName := args.IfName
	// 根据 containerd 传过来的 netns 的地址获取 ns

	netns, err := ns.GetNS(nsPath)
	if err != nil {
		fmt.Println("获取 ns 失败: ", err.Error())
		return
	}

	log.Println(netns.Path())

	// create a ipamer with in memory storage
	ipam := goipam.NewWithStorage(goipam.NewLocalFile(context.Background(), "./ipam_data"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parentCidr := "192.168.1.0/24"
	_, ipnet, err := net.ParseCIDR(parentCidr)
	mask, _ := ipnet.Mask.Size()

	prefix, err := ipam.PrefixFrom(ctx, parentCidr)
	if err != nil {
		if errors.Is(err, goipam.ErrNotFound) {
			prefix, err = ipam.NewPrefix(ctx, parentCidr)
			if err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}

	// 为宿主机申请网桥地址
	//sip := "192.168.1.254"
	firstIP, _ := cidr.Host(ipnet, 1)
	log.Println("firstIP:::", firstIP)
	brIP, err := ipam.AcquireSpecificIP(ctx, prefix.Cidr, firstIP.String())
	if err != nil {
		addr, _ := netip.ParseAddr(firstIP.String())
		// 如果地址已经分配，则手动创建 brIP 对象，ParentPrefix 为当前子网
		if errors.Is(err, goipam.ErrAlreadyAllocated) {
			brIP = &goipam.IP{IP: addr, ParentPrefix: prefix.Cidr}
		} else {
			panic(err)
		}
	}

	log.Println(brIP.IP.StringExpanded(), brIP.IP.String(), brIP.IP.Next(), brIP.IP.Prev())
	aip, err := ipam.AcquireIP(ctx, prefix.Cidr)
	if err != nil {
		panic(err)
	}

	log.Println("--------")
	log.Println(prefix.String())
	log.Println(prefix.Network())
	mp := Prefix{}
	gb, err := prefix.GobEncode()
	mp.GobDecode(gb)
	log.Println(mp.ips)
	log.Println("--------")

	brIPStr := fmt.Sprintf("%s/%d", brIP.IP, mask)
	podIPStr := fmt.Sprintf("%s/%d", aip.IP, mask)
	// gw 为网关地址，参数 0.0.0.0/0 为不设置默认路由
	err = nettools.CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster(
		bridgeName, args.IfName, brIPStr, podIPStr, mtu, netns, "0.0.0.0/0")
	if err != nil {
		fmt.Println("执行创建网桥, 创建 veth 设备, 添加默认路由等操作失败, err: ", err.Error())
	}
	log.Println(bridgeName, ifName)

	// 配路由
	err = netns.Do(func(netNS ns.NetNS) error {
		ip, ipnet, _ := net.ParseCIDR(podIPStr)
		//rs, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: 254}, netlink.RT_FILTER_TABLE)
		//for _, r := range rs {
		//	log.Printf("RouteListFiltered----: %+v", r)
		//}
		l, err := netlink.LinkByName("eth99")
		if err != nil {
			log.Println("=====", err)
			return err
		}

		// local(id 为 255) 表添加一条静态路由
		r := netlink.Route{Table: 255, Dst: ipnet, LinkIndex: l.Attrs().Index, Scope: netlink.SCOPE_LINK, Src: ip, Protocol: unix.RTPROT_KERNEL}
		err = netlink.RouteReplace(&r)
		//return err
		//rs, err := netlink.RouteGet(net.ParseIP(sip))
		//
		if err != nil {
			log.Println("=====", err)
			return err
		}
		//for _, r := range rs {
		//	log.Printf("###### %+v", r)
		//	r.Table = 255
		//	var dr = &netlink.Route{}
		//	err := copier.Copy(dr, r)
		//	if err != nil {
		//		log.Println("=====", err)
		//		return err
		//	}
		//	err = netlink.RouteAdd(dr)
		//	if err != nil {
		//		log.Println("==****===", err)
		//		return err
		//	}
		//}
		return nil
	})
	if err != nil {
		log.Fatalln(err)
	}

	// 起代理
	faddr, _ := net.ResolveUDPAddr("", fmt.Sprintf("%s:%d", brIP.IP, 5555))
	baddr, _ := net.ResolveUDPAddr("", fmt.Sprintf("%s:%d", aip.IP, 6666))
	log.Println(faddr.String(), baddr.String())
	pp, err := proxy.NewUDPProxy(faddr, baddr)
	if err != nil {
		panic(err)
	}
	pp.Run()
	log.Println("2222222")
	time.Sleep(100 * time.Second)
	/**
	 * 到这儿为止, 同一台主机上的 pod 可以 ping 通了
	 * 并且也可以访问其他网段的 ip 了
	 * 不过此时只能 ping 通主机上的网卡的网段(如果数据包没往外走的话需要确定主机是否开启了 ip_forward)
	 * 暂时没法 ping 通外网
	 * 因为此时的流量包只能往外出而不能往里进
	 * 原因是流量包往外出的时候还需要做一次 snat
	 * 没做 nat 转换的话, 外网在往回送消息的时候不知道应该往哪儿发
	 * 不过 testcni 这里暂时没有做 snat 的操作, 因为暂时没这个需求~
	 *
	 *
	 * 接下来要让不同节点上的 pod 互相通信了
	 * 可以尝试先手动操作
	 * 	1. 主机上添加路由规则: ip route add 10.244.x.0/24 via 192.168.98.x dev ens33, 也就是把非本机的节点的网段和其他 node 的 ip 做个映射
	 *  2. 其他每台集群中的主机也添加
	 *  3. 把每台主机上的对外网卡都用 iptables 设置为可 ip forward
	 * 以上手动操作可成功
	 */

	// // 接下来获取网卡信息, 把本机网卡插入到网桥上
	// link, err := netlink.LinkByName(currentNetwork.Name)
	// if err != nil {
	// 	fmt.Println("获取本机网卡失败, err: ", err.Error())
	// 	return
	// }

	// bridge, err := netlink.LinkByName(pluginConfig.Bridge)
	// if err != nil {
	// 	fmt.Println("获取网桥设备失败, err: ", err.Error())
	// 	return
	// }

	// err = nettools.SetDeviceMaster(link.(*netlink.Device), bridge.(*netlink.Bridge))
	// if err != nil {
	// 	fmt.Println("把网卡塞入网桥 gg, err: ", err.Error())
	// 	return
	// }

	time.Sleep(100 * time.Second)

	return
}
