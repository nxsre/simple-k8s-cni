package macvlan

import (
	"github.com/nxsre/simple-k8s-cni/cni"
	"github.com/nxsre/simple-k8s-cni/consts"
	base "github.com/nxsre/simple-k8s-cni/plugins/xvlan/base"
	"github.com/nxsre/simple-k8s-cni/skel"
	"github.com/nxsre/simple-k8s-cni/utils"
	"net"

	types "github.com/containernetworking/cni/pkg/types/100"
)

const MODE = consts.MODE_MACVLAN

type MacVlanCNI struct{}

func (macvlan *MacVlanCNI) Bootstrap(
	args *skel.CmdArgs,
	pluginConfig *cni.PluginConf,
) (*types.Result, error) {
	podIP, gw, err := base.SetXVlanDevice(base.MODE_MACVlan, args, pluginConfig)
	if err != nil {
		return nil, err
	}
	// 获取网关地址和 podIP 准备返回给外边
	_gw := net.ParseIP(gw)
	_, _podIP, _ := net.ParseCIDR(podIP)
	result := &types.Result{
		CNIVersion: pluginConfig.CNIVersion,
		IPs: []*types.IPConfig{
			{
				Address: *_podIP,
				Gateway: _gw,
			},
		},
	}
	return result, nil
}

func (macvlan *MacVlanCNI) Unmount(
	args *skel.CmdArgs,
	pluginConfig *cni.PluginConf,
) error {
	// TODO
	return nil
}

func (macvlan *MacVlanCNI) Check(
	args *skel.CmdArgs,
	pluginConfig *cni.PluginConf,
) error {
	// TODO
	return nil
}

func (macvlan *MacVlanCNI) GetMode() string {
	return MODE
}

func init() {
	MacVlanCNI := &MacVlanCNI{}
	manager := cni.GetCNIManager()
	err := manager.Register(MacVlanCNI)
	if err != nil {
		utils.WriteLog("注册 macvlan cni 失败: ", err.Error())
		panic(err.Error())
	}
}
