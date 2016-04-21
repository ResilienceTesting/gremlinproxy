package config

import (
	"encoding/json"
	"io/ioutil"
)

// Config stores global routing configuration
type Config struct {
	Services     []ServiceConfig `json:"services"`
	Router       RouterConfig    `json:"router"`
	LogLevel     string          `json:"loglevel"`
	LogJSON      bool            `json:"logjson"`
	LogstashHost string          `json:"logstash"`
}

// ServiceConfig stores configuration for a single remote service
type ServiceConfig struct {
	Name          string             `json:"name"`
	Proxyconf     ProxyConfig        `json:"proxy"`
	LBConfig      LoadBalancerConfig `json:"loadbalancer"`
}

// ProxyConfig stores the proxy options. Protocol refers to proxying mode: tcp or http
type ProxyConfig struct {
	Port     uint16 `json:"port"`
	BindHost string `json:"bindhost"`
	Protocol string `json:"protocol"`
}

// LoadBalancerConfig configures each loadbalancer.
type LoadBalancerConfig struct {
	Hosts []string `json:"hosts"`
	BalanceMode  string   `json:"balancemode"`
}

// RouterConfig stores options specific to routers REST interface, and other
// global config options, such as which headers we track in HTTP requests
type RouterConfig struct {
	Port           uint16 `json:"port"`
	TrackingHeader string `json:"trackingheader"`
	Name           string `json:"name"`
}

// RuleConfig represents different rules
type RuleConfig struct {
	Source       string  `json:"source"`
	Dest  string  `json:"dest"`
	MType        string   `json:"messagetype"`

	BodyPattern   string   `json:"bodypattern"`
	HeaderPattern string   `json:"headerpattern"`
	// TestID       string   `json:"testid"`

	DelayProbability  float64 `json:"delayprobability"`
	DelayDistribution string `json:"delaydistribution"`
	MangleProbability  float64 `json:"mangleprobability"`
	MangleDistribution string `json:"mangledistribution"`
	AbortProbability  float64 `json:"abortprobability"`
	AbortDistribution string `json:"abortdistribution"`

	DelayTime    string  `json:"delaytime"`
//	Method       string  `json:"method"`
	ErrorCode int     `json:"errorcode"`
	SearchString string `json:"searchstring"`
	ReplaceString string `json:"replacestring"`
}

// ReadConfig reads a config from disk
func ReadConfig(path string) Config {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err.Error())
	}
	var c Config
	err = json.Unmarshal(bytes, &c)
	if err != nil {
		panic(err.Error())
	}
	return c
}
