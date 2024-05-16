package nettools

import (
	"crypto/rand"
	"errors"
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-iptables/iptables"
	"github.com/nxsre/simple-k8s-cni/ipam"
	"github.com/nxsre/simple-k8s-cni/utils"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func delInterfaceByName(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	if err = netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete interface: %v", err)
	}

	return nil
}

// 对于 ipip 设备是删不掉的
// 当使用命令之类的创建 ipip 设备时
// 会先默认 “modprobe ipip” 把 ipip 模块加载到内核中
// 然后就会自动创建出一个叫做 tunl0 的 ipip 设备
// 相当于是内核默认创建的这个玩意儿, 用户态干不掉它
// 所以这里的删除就暂时先直接给它 down 掉
// 如果想真的删掉这个设备的话可以手动执行执行 “modprobe -r ipip”
func DelIPIP(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(link)
	// return delInterfaceByName(name)
}

func CreateIPIPDeviceAndUp(name string, mtus ...int) (*netlink.Iptun, error) {
	mtu := 1480
	if len(mtus) != 0 && mtus[0] != 0 {
		mtu = mtus[0]
	}

	link := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
	}

	err := netlink.LinkAdd(link)
	if err != syscall.EEXIST {
		return nil, err
	}

	// 已经存在
	existing, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	// fork from flannel
	// 如果已经存在但不是 ipip 设备的话, 告诉用户自己想辙
	if existing.Type() != "ipip" {
		return nil, fmt.Errorf("%v isn't an ipip mode device, please remove device and try again", name)
	}

	ipip, ok := existing.(*netlink.Iptun)
	if !ok {
		return nil, fmt.Errorf("%s isn't an iptun device (%#v), please remove device and try again", name, link)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to set %v UP: %v", name, err)
	}

	return ipip, nil
}

func SetIpForIPIPDeivce(name string, ip string) error {
	return setIpForDevice(name, ip, "ipip")
}

// TODO: trick now!
func CreateArpEntry(ip, mac, dev string) error {
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("arp -s %s %s -i %s", ip, mac, dev),
	)
	_, err := processInfo.Output()
	return err
}

func DeleteArpEntry(ip, dev string) error {
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("arp -d %s -i %s", ip, dev),
	)
	_, err := processInfo.Output()
	return err
}

func CreateVxlanAndUp(name string, mtu int) (*netlink.Vxlan, error) {
	l, _ := netlink.LinkByName(name)

	vxlan, ok := l.(*netlink.Vxlan)
	if ok && vxlan != nil {
		return vxlan, nil
	}
	if mtu == 0 {
		mtu = 1500
	}
	vxlan = &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
			// EncapType: "external",
			// OperState: netlink.OperDormant,
		},
	}
	err := netlink.LinkAdd(vxlan)
	if err != nil {
		utils.WriteLog("无法创建 vxlan 设备: ", name, "err: ", err.Error())
		return nil, err
	}

	l, err = netlink.LinkByName(name)
	if err != nil {
		utils.WriteLog("获取 vxlan 失败")
		return nil, err
	}

	vxlan, ok = l.(*netlink.Vxlan)
	if !ok {
		utils.WriteLog("找到了设备, 但是该设备不是 vxlan")
		return nil, fmt.Errorf("found the device %q but it's not a vxlan", name)
	}
	// 然后还要把这个 vxlan 给 up 起来
	if err = netlink.LinkSetUp(vxlan); err != nil {
		utils.WriteLog("启动 vxlan 失败, err: ", err.Error())
		return nil, fmt.Errorf("setup vxlan %q error, err: %v", name, err)
	}
	return vxlan, nil
}

func SetIpForVxlan(name string, ip string) error {
	return setIpForDevice(name, ip, "vxlan")
}

// TODO: golang 的 netlink 包在创建 vxlan 设备时不支持传入 external 模式
func CreateVxlanAndUp2(name string, mtu int) (*netlink.Vxlan, error) {
	l, _ := netlink.LinkByName(name)

	vxlan, ok := l.(*netlink.Vxlan)
	if ok && vxlan != nil {
		return vxlan, nil
	}
	// if mtu == 0 {
	// 	mtu = 1500
	// }

	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("ip link add name %s type vxlan external", name),
	)
	_, err := processInfo.Output()
	if err != nil {
		return nil, err
	}

	l, err = netlink.LinkByName(name)
	if err != nil {
		utils.WriteLog("获取 vxlan 失败")
		return nil, err
	}

	vxlan, ok = l.(*netlink.Vxlan)
	if !ok {
		utils.WriteLog("找到了设备, 但是该设备不是 vxlan")
		return nil, fmt.Errorf("found the device %q but it's not a vxlan", name)
	}
	// 然后还要把这个 vxlan 给 up 起来
	if err = netlink.LinkSetUp(vxlan); err != nil {
		utils.WriteLog("启动 vxlan 失败, err: ", err.Error())
		return nil, fmt.Errorf("set up vxlan %q error, err: %v", name, err)
	}
	return vxlan, nil
}

func DelVxlan(name string) error {
	return delInterfaceByName(name)
}

func CreateMacVlan(ifname, parentName string) (*netlink.Macvlan, error) {
	// macvlan 多一步, 要先把网卡给开启混杂模式
	link, err := netlink.LinkByName(parentName)
	if err != nil {
		return nil, err
	}

	// TODO: 这里应该先把 parent 网卡的当前状态记录下来
	// 然后等删除这个 macvlan 设备的时候再给恢复
	// 这里暂时先直接开启
	err = netlink.SetPromiscOn(link)
	if err != nil {
		return nil, err
	}

	for {
		rangeNum := utils.GetRandomNumber(9999)
		ifname = ifname + "." + strconv.Itoa(rangeNum)
		_, err := netlink.LinkByName(ifname)
		if err != nil {
			break
		}
	}

	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			ParentIndex: link.Attrs().Index,
			Name:        ifname,
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}

	err = netlink.LinkAdd(macvlan)
	if err != nil {
		return nil, err
	}

	return macvlan, nil
}

func SetIpForMacVlan(ifname, ip string) error {
	return setIpForDevice(ifname, ip, "macvlan")
}

func SetUpMacVlan(ifname string) error {
	macvlan, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = netlink.LinkSetUp(macvlan); err != nil {
		return fmt.Errorf("failed to set macvlan %q up, err: %v", ifname, err)
	}
	return nil
}

func CreateIPVlan(ifname, parentName string) (*netlink.IPVlan, error) {
	for {
		rangeNum := utils.GetRandomNumber(9999)
		ifname = ifname + "." + strconv.Itoa(rangeNum)
		_, err := netlink.LinkByName(ifname)
		if err != nil {
			break
		}
	}

	link, err := netlink.LinkByName(parentName)
	if err != nil {
		return nil, err
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			ParentIndex: link.Attrs().Index,
			Name:        ifname,
		},
		Mode: netlink.IPVLAN_MODE_L2,
		// Flag: netlink.IPVLAN_FLAG_BRIDGE,
	}

	err = netlink.LinkAdd(ipvlan)
	if err != nil {
		return nil, err
	}

	return ipvlan, nil
}

func SetIpForIPVlan(ifname, ip string) error {
	return setIpForDevice(ifname, ip, "ipvlan")
}

func SetUpIPVlan(ifname string) error {
	ipvlan, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	if err = netlink.LinkSetUp(ipvlan); err != nil {
		return fmt.Errorf("failed to set ipvlan %q up, err: %v", ifname, err)
	}
	return nil
}

func DelIPVlan(name string) error {
	return delInterfaceByName(name)
}

func CreateBridge(brName, brIP string, mtu int) (*netlink.Bridge, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}

	err := netlink.LinkAdd(br)
	if err != nil && (err != syscall.EEXIST) {
		utils.WriteLog("无法创建网桥: ", brName, "err: ", err.Error())
		return nil, err
	}

	// 这里需要通过 netlink 重新获取网桥
	// 否则光创建的话无法从上头拿到其他属性
	l, err := netlink.LinkByName(brName)
	if err != nil {
		return nil, err
	}

	br, ok := l.(*netlink.Bridge)
	if !ok {
		utils.WriteLog("找到了设备, 但是该设备不是网桥")
		return nil, fmt.Errorf("found the device %q but it's not a bridge device", brName)
	}

	// 给网桥绑定 ip 地址, 让网桥作为网关
	ipaddr, ipnet, err := net.ParseCIDR(brIP)
	if err != nil {
		utils.WriteLog("无法 parse gw 为 ipnet, err: ", err.Error())
		return nil, fmt.Errorf("transform the gatewayIP error %q: %v", brIP, err)
	}
	ipnet.IP = ipaddr
	addr := &netlink.Addr{IPNet: ipnet}
	if err = netlink.AddrReplace(br, addr); err != nil && err != syscall.EEXIST {
		utils.WriteLog("将 gw 添加到 bridge 失败, err: ", err.Error())
		return nil, fmt.Errorf("can not add the gw %q to bridge %q, err: %v", addr, brName, err)
	}

	// 然后还要把这个网桥给 up 起来
	if err = netlink.LinkSetUp(br); err != nil {
		utils.WriteLog("启动网桥失败, err: ", err.Error())
		return nil, fmt.Errorf("set up bridge %q error, err: %v", brName, err)
	}

	return br, nil
}

func SetUpVeth(veth ...*netlink.Veth) error {
	for _, v := range veth {
		// 启动 veth 设备
		err := netlink.LinkSetUp(v)
		if err != nil {
			utils.WriteLog("启动 veth1 失败, err: ", err.Error())
			return err
		}
	}
	return nil
}

func CreateVethPair(ifName string, mtu int, hostName ...string) (*netlink.Veth, *netlink.Veth, error) {
	vethPairName := ""
	if len(hostName) > 0 && hostName[0] != "" {
		vethPairName = hostName[0]
	} else {
		for {
			_vname, err := RandomVethName()
			vethPairName = _vname
			if err != nil {
				utils.WriteLog("生成随机 veth pair 名字失败, err: ", err.Error())
				return nil, nil, err
			}

			_, err = netlink.LinkByName(vethPairName)
			if err != nil && !os.IsExist(err) {
				// 上面生成随机名字可能会重名, 所以这里先尝试按照这个名字获取一下
				// 如果没有这个名字的设备, 那就可以 break 了
				break
			}
		}
	}

	log.Println("vethPairNamevethPairName:::", vethPairName)

	if vethPairName == "" {
		return nil, nil, errors.New("create veth pair's name error")
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
			// Flags:     net.FlagUp,
			MTU: mtu,
			// Namespace: netlink.NsFd(int(ns.Fd())), // 先不设置 ns, 要不一会儿下头 LinkByName 时候找不到
		},
		PeerName: vethPairName,
		// PeerNamespace: netlink.NsFd(int(ns.Fd())),
	}

	veth1, err := netlink.LinkByName(ifName)
	if err == nil {
		err := netlink.LinkDel(veth1)
		if err != nil {
			return nil, nil, err
		}
	}

	// 创建 veth pair
	err = netlink.LinkAdd(veth)
	if err != nil {
		utils.WriteLog("创建 veth 设备失败, err: ", err.Error())
		return nil, nil, err
	}

	// 尝试重新获取 veth 设备看是否能成功
	veth1, err = netlink.LinkByName(ifName) // veth1 一会儿要在 pod(net ns) 里
	if err != nil {
		log.Println("77777777777---", err)

		// 如果获取失败就尝试删掉
		netlink.LinkDel(veth1)
		utils.WriteLog("创建完 veth 但是获取失败, err: ", err.Error())
		return nil, nil, err
	}

	// 尝试重新获取 veth 设备看是否能成功
	veth2, err := netlink.LinkByName(vethPairName) // veth2 在主机上
	if err != nil {
		// 如果获取失败就尝试删掉
		netlink.LinkDel(veth2)
		utils.WriteLog("创建完 veth 但是获取失败, err: ", err.Error())
		return nil, nil, err
	}

	return veth1.(*netlink.Veth), veth2.(*netlink.Veth), nil
}

// TODO: 这里暂时先用命令去开启 proxy arp
// netlink 这个包从源码上看貌似只支持对 bridge 设备开启 proxy_arp
// 在 netlink.LinkAdd 的时候直接传 ProxyARP: true 也不好使
// 后面找到更好的方法之后再改
func SetUpDeviceProxyArpV4(link netlink.Link) error {
	name := link.Attrs().Name
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("echo 1 > /proc/sys/net/ipv4/conf/%s/proxy_arp", name),
	)
	_, err := processInfo.Output()
	return err
}

func SetDownDeviceProxyArpV4(link netlink.Link) error {
	name := link.Attrs().Name
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("echo 0 > /proc/sys/net/ipv4/conf/%s/proxy_arp", name),
	)
	_, err := processInfo.Output()
	return err
}

func SetUpDeviceForwarding(link netlink.Link) error {
	name := link.Attrs().Name
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("echo 1 > /proc/sys/net/ipv4/conf/%s/forwarding", name),
	)
	_, err := processInfo.Output()
	return err
}

func DelVethPair(ifName string) error {
	return delInterfaceByName(ifName)
}

func setIpForDevice(name string, ip string, mode ...string) error {
	deviceType := ""
	if len(mode) != 0 {
		deviceType = mode[0]
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get %s device by name %q, error: %v", deviceType, name, err)
	}

	ipaddr, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("failed to transform the ip %q, error : %v", ip, err)
	}
	ipnet.IP = ipaddr
	existingAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to get IP address for %q: %v", link.Attrs().Name, err)
	}

	if contains(existingAddrs, ipnet) {
		return nil
	}
	if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		return fmt.Errorf("failed to add IP address to %q: %v", link.Attrs().Name, err)
	}
	return nil
}

func contains(addrs []netlink.Addr, addr *net.IPNet) bool {
	for _, x := range addrs {
		if addr.IP.Equal(x.IPNet.IP) {
			return true
		}
	}
	return false
}

func DeviceExistIp(link netlink.Link) (string, error) {
	dev, err := net.InterfaceByIndex(link.Attrs().Index)
	if err == nil {
		addrs, err := dev.Addrs()
		if err == nil && len(addrs) > 0 {
			str := addrs[0].String()
			tmpIp := strings.Split(str, "/")
			if len(tmpIp) == 2 && net.ParseIP(tmpIp[0]).To4() != nil {
				return str, nil
			}
		}
	}
	return "", nil
}

func SetIpForVeth(name string, podIP string) error {
	return setIpForDevice(name, podIP, "veth")
}

func SetVethToBridge(veth *netlink.Veth, br *netlink.Bridge) error {
	// 把 veth2 干到 br 上, veth1 不用, 因为在创建的时候已经被干到 ns 里头了
	err := netlink.LinkSetMaster(veth, br)
	if err != nil {
		utils.WriteLog("把 veth 插到网桥上失败, err: ", err.Error())
		return fmt.Errorf("insert veth %q into bridge %v error, err: %v", veth.Attrs().Name, br.Attrs().Name, err)
	}
	return nil
}

func SetDeviceToNS(device netlink.Link, ns ns.NetNS) error {
	err := netlink.LinkSetNsFd(device, int(ns.Fd()))
	if err != nil {
		return fmt.Errorf("failed to add the device %q to ns: %v", device.Attrs().Name, err)
	}
	return nil
}

func SetVethNsFd(veth *netlink.Veth, ns ns.NetNS) error {
	return SetDeviceToNS(veth, ns)
}

func SetVethMaster(veth *netlink.Veth, br *netlink.Bridge) error {
	err := netlink.LinkSetMaster(veth, br)
	if err != nil {
		utils.WriteLog(fmt.Sprintf("把 veth %q 干到 master 上失败: %v", veth.Attrs().Name, err))
		return fmt.Errorf("add veth %q to master error: %v", veth.Attrs().Name, err)
	}
	return nil
}

func SetDeviceMaster(device *netlink.Device, br *netlink.Bridge) error {

	if device == nil {
		return nil
	}

	if br == nil {
		return nil
	}

	deviceMaster := device.Attrs().MasterIndex

	brIndex := br.Index

	if deviceMaster == brIndex {
		// fmt.Println("已经将网卡添加过网桥中, 无需添加")
		return nil
	}

	err := netlink.LinkSetMaster(device, br)
	if err != nil {
		utils.WriteLog(fmt.Sprintf("把 veth %q 干到网桥上失败: %v", device.Attrs().Name, err))
		return fmt.Errorf("add veth %q to bridge error: %v", device.Attrs().Name, err)
	}
	return nil
}

func SetDefaultRouteToVeth(gwIP net.IP, veth netlink.Link) error {
	return AddDefaultRoute(gwIP, veth)
}

func SetOtherHostRouteToCurrentHost(networks []*ipam.Network, currentNetwork *ipam.Network) error {

	link, err := netlink.LinkByName(currentNetwork.Name)

	list, _ := netlink.RouteList(link, netlink.FAMILY_V4)

	if err != nil {
		return err
	}

	for _, network := range networks {
		if !network.IsCurrentHost {
			// 对于其他主机, 需要获取到其他主机的对外网卡 ip, 以及它的 pods 们所占用的网段的 cidr
			// 然后用这个 cidr 和这个 ip 做一个路由表的映射
			if link == nil {
				return err
			}

			_, cidr, err := net.ParseCIDR(network.CIDR)
			if err != nil {
				return err
			}

			isSkip := false
			for _, l := range list {
				if l.Dst != nil && l.Dst.String() == network.CIDR {
					isSkip = true
					break
				}
			}

			if isSkip {
				// fmt.Println(network.CIDR, " 已存在路由表中, 直接跳过")
				continue
			}

			ip := net.ParseIP(network.IP)

			err = AddHostRoute(cidr, ip, link)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// forked from plugins/pkg/ip/route_linux.go
func AddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link, scope ...netlink.Scope) error {
	defaultScope := netlink.SCOPE_UNIVERSE
	if len(scope) > 0 {
		defaultScope = scope[0]
	}
	log.Println(dev.Attrs().Index, defaultScope, ipn, gw)
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     defaultScope,
		Dst:       ipn,
		Gw:        gw,
	})
}

// forked from plugins/pkg/ip/route_linux.go
func AddHostRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		// Scope:     netlink.SCOPE_HOST,
		Dst: ipn,
		Gw:  gw,
	})
}

func AddHostRouteWithVia(ipn *net.IPNet, via *netlink.Via, dev netlink.Link) error {
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     netlink.SCOPE_HOST,
		Dst:       ipn,
		Via:       via,
	})
}

// forked from plugins/pkg/ip/route_linux.go
func AddDefaultRoute(gw net.IP, dev netlink.Link) error {
	_, defNet, _ := net.ParseCIDR("0.0.0.0/0")
	return AddRoute(defNet, gw, dev)
}

// forked from /plugins/pkg/ip/link_linux.go
// RandomVethName returns string "veth" with random prefix (hashed from entropy)
func RandomVethName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (recent versions) will ignore veth devices that start with "veth"
	return fmt.Sprintf("veth%x", entropy), nil
}

func SetIptablesForToForwardAccept(link netlink.Link) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		utils.WriteLog("这里 NewWithProtocol 失败, err: ", err.Error())
		return err
	}
	err = ipt.AppendUnique("filter", "FORWARD", "-i", link.Attrs().Name, "-j", "ACCEPT")
	if err != nil {
		utils.WriteLog("这里 ipt.Append 失败, err: ", err.Error())
		return err
	}
	return nil
}

func SetIptablesForDeviceToFarwordAccept(device *netlink.Device) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		utils.WriteLog("这里 NewWithProtocol 失败, err: ", err.Error())
		return err
	}

	err = ipt.AppendUnique("filter", "FORWARD", "-i", device.Attrs().Name, "-j", "ACCEPT")
	if err != nil {
		utils.WriteLog("这里 ipt.Append 失败, err: ", err.Error())
		return err
	}

	return nil
}

func SetupVeth(netns ns.NetNS, br netlink.Link, mtu int, ifName string, podIP string, gateway net.IP) error {
	hostIface := &current.Interface{}
	err := netns.Do(func(hostNS ns.NetNS) error {
		if link, err := netlink.LinkByName(ifName); err == nil {
			ip.DelLinkByName(link.Attrs().Name)
		}

		// 在容器网络空间创建虚拟网卡
		hostVeth, containerVeth, err := ip.SetupVeth(ifName, mtu, "", hostNS)
		if err != nil {
			log.Println("111", err)
			return err
		}
		hostIface.Name = hostVeth.Name

		// set ip for container veth
		conLink, err := netlink.LinkByName(containerVeth.Name)
		if err != nil {
			log.Println("222", err)
			return err
		}

		// 绑定Pod IP
		if err := SetIpForVeth(conLink.Attrs().Name, podIP); err != nil {
			log.Println("333", err)
			return err
		}

		// 启动网卡
		if err := netlink.LinkSetUp(conLink); err != nil {
			log.Println("444", err)
			return err
		}

		if !gateway.Equal(net.ParseIP("0.0.0.0")) {
			// 添加默认路径，网关即网桥的地址
			if err := ip.AddDefaultRoute(gateway, conLink); err != nil {
				log.Println("555", err)
				return err
			}
		}

		hostNS.Do(func(netNS ns.NetNS) error {
			// need to lookup hostVeth again as its index has changed during ns move
			hostVeth, err := netlink.LinkByName(hostIface.Name)
			if err != nil {
				log.Println("666", err)
				return fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
			}

			// 将虚拟网卡另一端绑定到网桥上
			if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
				log.Println("777", err)
				return fmt.Errorf("failed to connect %q to bridge %v: %v", hostVeth.Attrs().Name, br.Attrs().Name, err)
			}

			// 都完事儿之后理论上同一台主机下的俩 netns(pod) 就能通信了
			// 如果无法通信, 有可能是 iptables 被设置了 forward drop
			// 需要用 iptables 允许网桥做转发
			err = SetIptablesForToForwardAccept(br)
			if err != nil {
				utils.WriteLog("xxxxxxxx", err.Error())
				return err
			}
			return nil
		})

		log.Println("================")

		return nil
	})

	return err
}

func CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster(
	brName, ifName string, brIP, podIP string, mtu int, netns ns.NetNS, gw string,
) error {
	// 先创建网桥
	br, err := CreateBridge(brName, brIP, mtu)
	if err != nil {
		utils.WriteLog("创建网卡失败, err: ", err.Error())
		return err
	}

	// 启动之后给这个 netns 设置默认路由 以便让其他网段的包也能从 veth 走到网桥
	gwNetIP, _, err := net.ParseCIDR(gw)
	if err != nil {
		utils.WriteLog("转换 gwip 失败, err:", err.Error())
		return err
	}

	err = SetupVeth(netns, br, mtu, ifName, podIP, gwNetIP)
	return err
}

func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", errors.New(fmt.Sprintf("interface %s don't have an ipv4 address\n", interfaceName))
	}
	return ipv4Addr.String(), nil
}
