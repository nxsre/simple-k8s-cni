package ipvlan

import (
	"fmt"
	"github.com/nxsre/simple-k8s-cni/cni"
	"github.com/nxsre/simple-k8s-cni/skel"
	"github.com/nxsre/simple-k8s-cni/utils"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TmpCreateNS(name string) error {
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("ip netns add %s", name),
	)
	_, err := processInfo.Output()
	return err
}

func TmpDeleteNS(name string) error {
	processInfo := exec.Command(
		"/bin/sh", "-c",
		fmt.Sprintf("ip netns del %s", name),
	)
	_, err := processInfo.Output()
	return err
}

func TestIPVlan(t *testing.T) {
	test := assert.New(t)
	err := TmpCreateNS("ns1")
	test.Nil(err)
	nsexist := utils.FileIsExisted("/var/run/netns/ns1")
	test.True(nsexist)

	args := &skel.CmdArgs{
		ContainerID: "308102901b7fe9538fcfc71669d505bc09f9def5eb05adeddb73a948bb4b2c8b",
		Netns:       "/var/run/netns/ns1",
		IfName:      "eth0",
		Args:        "K8S_POD_INFRA_CONTAINER_ID=308102901b7fe9538fcfc71669d505bc09f9def5eb05adeddb73a948bb4b2c8b;K8S_POD_UID=d392609d-6aa2-4757-9745-b85d35e3d326;IgnoreUnknown=1;K8S_POD_NAMESPACE=kube-system;K8S_POD_NAME=coredns-c676cc86f-4kz2t",
		Path:        "/opt/cni/bin",
		StdinData:   ([]byte)("{\"cniVersion\":\"0.3.0\",\"mode\":\"ipvlan\",\"name\":\"testcni\",\"subnet\":\"192.168.64.0/24\",\"type\":\"testcni\",\"ipam\":{\"rangeStart\":\"192.168.64.200\",\"rangeEnd\":\"192.168.64.210\"}}"),
	}

	pluginConfig := &cni.PluginConf{
		Subnet: "192.168.64.0/24",
		Mode:   "ipvlan",
		// 不同节点的 range 要不一样
		IPAM: &cni.IPAM{
			RangeStart: "192.168.64.200",
			RangeEnd:   "192.168.64.210",
		},
	}
	pluginConfig.CNIVersion = "0.3.0"
	pluginConfig.Name = "testcni"
	pluginConfig.Type = "testcni"

	ipvlan := IPVlanCNI{}
	res, err := ipvlan.Bootstrap(args, pluginConfig)
	test.Nil(err)
	fmt.Println(res)
	err = TmpDeleteNS("ns1")
	test.Nil(err)
	nsexist = utils.FileIsExisted("/var/run/netns/ns1")
	test.False(nsexist)
}
