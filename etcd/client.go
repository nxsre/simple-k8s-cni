package etcd

import (
	// "context"
	// "crypto/tls"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	// "github.com/coreos/etcd/client"
	// "github.com/coreos/etcd/client"
	etcd "go.etcd.io/etcd/client/v3"
	// "go.etcd.io/etcd/pkg/transport"
	"go.etcd.io/etcd/client/pkg/v3/transport"
)

type EtcdConfig struct {
	EtcdScheme       string `json:"etcdScheme" envconfig:"APIV1_ETCD_SCHEME" default:""`
	EtcdAuthority    string `json:"etcdAuthority" envconfig:"APIV1_ETCD_AUTHORITY" default:""`
	EtcdEndpoints    string `json:"etcdEndpoints" envconfig:"APIV1_ETCD_ENDPOINTS"`
	EtcdDiscoverySrv string `json:"etcdDiscoverySrv" envconfig:"APIV1_ETCD_DISCOVERY_SRV"`
	EtcdUsername     string `json:"etcdUsername" envconfig:"APIV1_ETCD_USERNAME"`
	EtcdPassword     string `json:"etcdPassword" envconfig:"APIV1_ETCD_PASSWORD"`
	EtcdKeyFile      string `json:"etcdKeyFile" envconfig:"APIV1_ETCD_KEY_FILE"`
	EtcdCertFile     string `json:"etcdCertFile" envconfig:"APIV1_ETCD_CERT_FILE"`
	EtcdCACertFile   string `json:"etcdCACertFile" envconfig:"APIV1_ETCD_CA_CERT_FILE"`
}

type EtcdClient struct {
	client  *etcd.Client
	Version string
}

const (
	clientTimeout = 30 * time.Second
	etcdTimeout   = 2 * time.Second
)

func newEtcdClient(config *EtcdConfig) (*etcd.Client, error) {
	var etcdLocation []string
	if config.EtcdAuthority != "" {
		etcdLocation = []string{config.EtcdScheme + "://" + config.EtcdAuthority}
	}
	if config.EtcdEndpoints != "" {
		etcdLocation = strings.Split(config.EtcdEndpoints, ",")
	}

	if len(etcdLocation) == 0 {
		return nil, errors.New("找不到 etcd")
	}

	tlsInfo := transport.TLSInfo{
		CertFile:      config.EtcdCertFile,
		KeyFile:       config.EtcdKeyFile,
		TrustedCAFile: config.EtcdCACertFile,
	}

	tlsConfig, err := tlsInfo.ClientConfig()

	client, err := etcd.New(etcd.Config{
		Endpoints:   etcdLocation,
		TLS:         tlsConfig,
		DialTimeout: clientTimeout,
	})

	if err != nil {
		return nil, err
	}

	return client, nil
}

// func CreateClient() (*EtcdClient, error) {
// 	fmt.Println("创建 etcd 客户端......")
// 	client, err := newEtcdClient(&EtcdConfig{
// 		EtcdEndpoints:  "https://192.168.98.143:2379",
// 		EtcdCertFile:   "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
// 		EtcdKeyFile:    "/etc/kubernetes/pki/etcd/healthcheck-client.key",
// 		EtcdCACertFile: "/etc/kubernetes/pki/etcd/ca.crt",
// 	})

// 	if err != nil {
// 		fmt.Println("连接出错: ", err.Error())
// 		return nil, err
// 	}
// 	fmt.Println("连接 etcd 成功")
// 	// // version, err := client.etcdClient.
// 	// _, err = client.etcdClient.Put(context.TODO(), "/ding-test1", "bar")
// 	// if err != nil {
// 	// 	fmt.Println("存储失败: ", err.Error())
// 	// }

// 	// resp, err := client.etcdClient.Get(context.TODO(), "ding-test1")
// 	// if err != nil {
// 	// 	fmt.Println("获取失败: ", err.Error())
// 	// }
// 	// for _, ev := range resp.Kvs {
// 	// 	fmt.Printf("%s : %s\n", ev.Key, ev.Value)
// 	// }

// 	// if err != nil {
// 	// 	fmt.Println("获取 etcd 版本失败: ", err.Error())
// 	// 	return nil, err
// 	// }
// 	// fmt.Println("Etcd Cluster Version: ", version.Cluster)
// 	// fmt.Println("Etcd Server Version: ", version.Server)
// 	return client, nil
// }

var __GetEtcdClient func() (*EtcdClient, error)

func GetEtcdClient() (*EtcdClient, error) {

	if __GetEtcdClient == nil {
		return nil, nil
	}
	return __GetEtcdClient()

}

func _GetEtcdClient() func() (*EtcdClient, error) {
	var _client *EtcdClient

	return func() (*EtcdClient, error) {
		if _client != nil {
			return _client, nil
		} else {

			fmt.Println("正在创建 etcd 客户端......")
			client, err := newEtcdClient(&EtcdConfig{
				EtcdEndpoints:  "https://192.168.98.143:2379",
				EtcdCertFile:   "/etc/kubernetes/pki/etcd/healthcheck-client.crt",
				EtcdKeyFile:    "/etc/kubernetes/pki/etcd/healthcheck-client.key",
				EtcdCACertFile: "/etc/kubernetes/pki/etcd/ca.crt",
			})

			if err != nil {
				return nil, err
			}

			status, err := client.Status(context.TODO(), "https://192.168.98.143:2379")

			if err != nil {
				fmt.Println("无法获取到 etcd 版本: ", err.Error())
			}

			if client != nil {
				_client = &EtcdClient{
					client: client,
				}

				if status != nil && status.Version != "" {
					_client.Version = status.Version
				}

				return _client, nil
			}
		}
		return nil, errors.New("初始化 etcd client 失败")
	}
}

func Init() {
	if __GetEtcdClient == nil {
		__GetEtcdClient = _GetEtcdClient()
	}
}

func (c *EtcdClient) Set(key, value string) (bool, error) {
	_, err := c.client.Put(context.TODO(), key, value)
	if err != nil {
		return false, err
	}
	return true, err
}

func (c *EtcdClient) Get(key string) (string, error) {
	resp, err := c.client.Get(context.TODO(), key)
	if err != nil {
		return "", err
	}

	// for _, ev := range resp.Kvs {
	// 	fmt.Println("这里的 ev 是: ", ev)
	// 	fmt.Printf("%s : %s\n", ev.Key, ev.Value)
	// }

	return string(resp.Kvs[len(resp.Kvs)-1:][0].Value), nil
}