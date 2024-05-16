package main

import (
	"context"
	"crypto/tls"
	"github.com/allegro/bigcache/v3"
	"github.com/ipinfo/go/v2/ipinfo"
	jsoniter "github.com/json-iterator/go"
	"log"
	"net"
	"net/http"
	"time"
)

type dummyCacheEngine struct {
	cache *bigcache.BigCache
}

func newDummyCacheEngine() *dummyCacheEngine {
	config := bigcache.Config{
		// number of shards (must be a power of 2)
		Shards: 1024,

		// time after which entry can be evicted
		LifeWindow: 10 * time.Minute,

		// Interval between removing expired entries (clean up).
		// If set to <= 0 then no action is performed.
		// Setting to < 1 second is counterproductive — bigcache has a one second resolution.
		CleanWindow: 5 * time.Minute,

		// rps * lifeWindow, used only in initial memory allocation
		MaxEntriesInWindow: 1000 * 10 * 60,

		// max entry size in bytes, used only in initial memory allocation
		MaxEntrySize: 500,

		// prints information about additional memory allocation
		Verbose: true,

		// cache will not allocate more memory than this limit, value in MB
		// if value is reached then the oldest entries can be overridden for the new ones
		// 0 value means no size limit
		HardMaxCacheSize: 8192,

		// callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A bitmask representing the reason will be returned.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		OnRemove: nil,

		// OnRemoveWithReason is a callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A constant representing the reason will be passed through.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		// Ignored if OnRemove is specified.
		OnRemoveWithReason: nil,
	}

	bcache, initErr := bigcache.New(context.Background(), config)
	if initErr != nil {
		log.Fatal(initErr)
	}
	return &dummyCacheEngine{
		cache: bcache,
	}
}

func (c *dummyCacheEngine) Get(key string) (interface{}, error) {
	jb, err := c.cache.Get(key)
	if err != nil {
		return nil, err
	}
	var v = &ipinfo.Core{}
	err = jsoniter.Unmarshal(jb, v)
	return v, err
}

func (c *dummyCacheEngine) Set(key string, value interface{}) error {
	jb, err := jsoniter.Marshal(value)
	if err != nil {
		return err
	}
	c.cache.Set(key, jb)
	return nil
}

var dummyCache = ipinfo.NewCache(newDummyCacheEngine())

type DumpTransport struct {
	r http.RoundTripper
}

func (d *DumpTransport) RoundTrip(h *http.Request) (*http.Response, error) {
	//dump, _ := httputil.DumpRequestOut(h, true)
	//fmt.Printf("****REQUEST****\n%q\n", dump)
	resp, err := d.r.RoundTrip(h)
	//dump, _ = httputil.DumpResponse(resp, true)
	//fmt.Printf("****RESPONSE****\n%q\n****************\n\n", dump)
	return resp, err
}

func GetMyIP() (net.IP, error) {

	// 创建一个自定义的 TLS 配置
	tlsConfig := &tls.Config{
		// 在这里设置 TLS 选项，比如是否要求双向认证，证书校验等等
		InsecureSkipVerify: true,
	}

	// 创建一个自定义的 Transport，将 TLS 配置传递给它
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	transport.MaxIdleConns = 100
	transport.MaxConnsPerHost = 100
	transport.MaxIdleConnsPerHost = 100

	// 创建一个新的 HTTP client，将自定义 Transport 传递给它
	httpClient := &http.Client{
		Transport: &DumpTransport{
			r: transport,
		},
	}

	// 匿名用户每个月 50000 次调用限制
	client := ipinfo.NewClient(httpClient, dummyCache, "")

	// 入参为空即查询本机公网IP
	info, err := client.GetIPInfo(nil)
	if err != nil {
		return nil, err
	}
	return info.IP, nil
}
