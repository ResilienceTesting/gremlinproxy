package proxy

import (
	"github.com/gremlinproxy/config"
	"github.com/Sirupsen/logrus"
	"math/rand"
	str "strings"
	"sync"
)

//var globallog = config.GlobalLogger

// LoadBalancer is in charge of switching up which host the request goes to
type LoadBalancer struct {
	mode         string
	hosts        []string
	hostLock     *sync.RWMutex
	index        uint
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(c config.LoadBalancerConfig) *LoadBalancer {
	var lb LoadBalancer
	if c.Hosts != nil && len(c.Hosts) > 0 {
		lb.hosts = make([]string, len(c.Hosts))
		for i, server := range c.Hosts {
			lb.hosts[i] = server
			globallog.WithFields(logrus.Fields{
				"host":   server,
				"index":  i,
			}).Debug("adding lb host")
		}
	} else {
		lb.hosts = make([]string, 10)
	}
	lb.mode = c.BalanceMode
	lb.hostLock = new(sync.RWMutex)
	return &lb
}

// GetHost returns a single host that the client should connect based on the loadbalance mode
func (l *LoadBalancer) GetHost() string {
	l.hostLock.RLock()
	defer l.hostLock.RUnlock()
	var i uint
	switch str.ToLower(l.mode) {
	case "roundrobin":
	default:
		i = l.index % uint(len(l.hosts))
		l.index++
		break
	case "random":
		i = uint(rand.Int31n(int32(len(l.hosts))))
		break
	}
	return l.hosts[i]
}

// GetInstances retrieves the available instances for the service
func (l *LoadBalancer) GetInstances() []string {
	l.hostLock.Lock()
	defer l.hostLock.Unlock()
	retVal := make([]string, len(l.hosts))
	copy(retVal, l.hosts)
	return retVal
}

// SetInstances updates internally stored available instances for the service
func (l *LoadBalancer) SetInstances(hosts []string) {
	l.hostLock.Lock()
	defer l.hostLock.Unlock()
	l.hosts = hosts[:]
}
