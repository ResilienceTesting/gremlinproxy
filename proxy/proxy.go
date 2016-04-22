package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"github.com/ResilienceTesting/gremlinproxy/config"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	str "strings"
	"sync"
	"time"
	"fmt"
	"github.com/Sirupsen/logrus"
)

var proxylog = config.ProxyLogger
var globallog = config.GlobalLogger

// Proxy implements the proxying logic between a pair of services.
// A single router can have multiple proxies, one for each service that the local service needs to talk to
type Proxy struct {
	name       string
	testid     string
	port       uint16
	bindhost   string
	Protocol   string
	rules      map[MessageType][]Rule
	ruleLock   *sync.RWMutex
	/**
	expects    map[string]chan int
	expectLock *sync.RWMutex
	**/
	httpclient http.Client
	lb         *LoadBalancer
	httpregexp *regexp.Regexp
}

// NewProxy returns a new proxy instance.
func NewProxy(serviceName string, conf config.ProxyConfig,
	lbconf config.LoadBalancerConfig) *Proxy {
	var p Proxy
	p.name = serviceName
	if lbconf.Hosts == nil || len(lbconf.Hosts) < 1 {
		fmt.Println("Missing backend instances for service "+serviceName)
		os.Exit(1)
	}
	p.lb = NewLoadBalancer(lbconf)
	p.port = conf.Port
	p.httpclient = http.Client{}
	p.bindhost = conf.BindHost
	if (conf.BindHost == "") {
		p.bindhost = "localhost"
	}

	p.Protocol = conf.Protocol
	p.rules = map[MessageType][]Rule{Request: {}, Response: {}}
	p.ruleLock = new(sync.RWMutex)
	/**
	p.expects = map[string]chan int{}
	p.expectLock = new(sync.RWMutex)
	**/
	p.httpregexp = regexp.MustCompile("^https?://")
	return &p
}

// getRule returns first rule matched to the given request. If no stored rules match,
// a special NOPRule is returned.
func (p *Proxy) getRule(r MessageType, reqID string, data []byte) Rule {
	p.ruleLock.RLock()
	defer p.ruleLock.RUnlock()
	// globallog.Debug("In getRule")
	for counter, rule := range p.rules[r] {
		globallog.WithField("ruleCounter", counter).Debug("Rule counter")
		//  If request ID is empty, do not match unless wildcard rule
		if reqID == "" {
			if (rule.HeaderPattern == "*" || rule.BodyPattern == "*") {
				return rule
			}
			continue
		}

		// if requestID is a wildcard, pick up the first rule and return
		if reqID == "*" {
			return rule
		}

		if (rule.HeaderPattern == "*" && rule.BodyPattern == "*") {
			return rule
		}

		if rule.HeaderPattern != "*" {
			b, err := regexp.Match(rule.HeaderPattern, []byte(reqID))
			if err != nil {
				globallog.WithFields(logrus.Fields{
					"reqID":   reqID,
					"errmsg":  err.Error(),
					"headerpattern": rule.HeaderPattern,
				}).Error("Rule request ID matching error")
				continue
			}
			if !b {
				globallog.Debug("Id regex no match")
				continue
			}
			//globallog.WithField("ruleCounter", rule.ToConfig()).Debug("Id regex match")
		}

		if data == nil {
			// No match if body pattern is empty, but match if rule pattern is empty or this is a special pattern
			if rule.BodyPattern != "*" {
				continue
			}
		} else {
			if rule.BodyPattern != "*" {
				globallog.WithField("ruleCounter", counter).Debug("Body pattern !*")
				b, err := regexp.Match(rule.BodyPattern, data)
				if err != nil {
					globallog.WithFields(logrus.Fields{
						"reqID":   reqID,
						"errmsg":  err.Error(),
						"bodypattern": rule.BodyPattern,
					}).Error("Rule body matching error")
					continue
				}
				if !b {
					globallog.Debug("Body regex no match")
					continue
				}
			}
		}
		//globallog.WithField("returning rule ", rule.ToConfig()).Debug("Id regex match")
		return rule
	}
	return NopRule
}

/**
// expectCheck matches data against much any data the proxy should be seeing (i.e. expecting) on the wire
func (p *Proxy) expectCheck(data []byte) {
	p.expectLock.RLock()
	defer p.expectLock.RUnlock()
	if len(p.expects) == 0 {
		return
	}
	for k, v := range p.expects {
		go func(k string, v chan int, data []byte) {
			b, err := regexp.Match(k, data)
			if err != nil {
				globallog.Error("Rule matching error")
				return
			}
			if b {
				v <- 1
			}
		}(k, v, data)
	}
}
**/

func glueHostAndPort(host string, port uint16) string {
	return host + ":" + strconv.Itoa(int(port))
}

// Run starts up a proxy in the desired mode: tcp or http. This is a blocking call
func (p *Proxy) Run() {
	globallog.WithFields(logrus.Fields{
		"service": p.name,
		"bindhost" : p.bindhost,
		"port":    p.port,
		"protocol":    p.Protocol}).Info("Starting up proxy")
	switch str.ToLower(p.Protocol) {
	case "tcp":
		localhost, err := net.ResolveTCPAddr("tcp", glueHostAndPort(p.bindhost, p.port))
		if err != nil {
			globallog.Error(err.Error())
			break
		}
		listener, err := net.ListenTCP("tcp", localhost)
		if err != nil {
			globallog.Error(err.Error())
			break
		}
		// Standard accept connection loop
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				globallog.Error(err.Error())
				continue
			}
			// go and handle the connection in separate thread
			go p.proxyTCP(conn)
		}
		break
	case "http":
		err := http.ListenAndServe(glueHostAndPort(p.bindhost, p.port), p)
		if err != nil {
			globallog.Error(err.Error())
		}
		break
	default:
		panic(p.Protocol + " not supported")
	}
}

// tcpReadWrite handles low-level details of the proxying between two TCP connections
// FIXME: update this to the new RULE format
// func (p *Proxy) tcpReadWrite(src, dst *net.TCPConn, rtype MessageType, wg *sync.WaitGroup) {
// 	// Copy the data from one connection to the other
// 	data := make([]byte, 65536) //FIXME: This is bad.
// 	defer wg.Done()
// 	for {
// 		n, err := src.Read(data)
// 		if err != nil {
// 			dst.Close()
// 			return
// 		}

// 	   var i int = 0
// 	   var n2 int = 0
	   
// 	   for (n2 < n) {		
// 			i, err = dst.Write(data[n2:n])
// 			if err != nil {
// 				src.Close()
// 				return
// 			}
// 			//we have to write n-i more bytes
// 			n2 = n2 + i
// 	   }
// 	}
// }

func copyBytes(dest, src *net.TCPConn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dest, src)
	dest.CloseWrite()
	src.CloseRead()
}

//TODO: Need to add connection termination in the middle of a connection & bandwidth throttling.
// Delay implementation is half-baked (only adds initial delay).

// proxyTCP is responsible for handling a new TCP connection.
func (p *Proxy) proxyTCP(conn *net.TCPConn) {

	//We can abort the connection immediately, in case of an Abort action.
	//FIXME: Need to have a way to abort in the middle of a connection too.
	rule := p.getRule(Request, "", nil)
	t := time.Now()

	//FIXME: Add proper delay support for TCP channels.
	if ((rule.DelayProbability > 0.0) &&
		drawAndDecide(rule.DelayDistribution, rule.DelayProbability)) {
		proxylog.WithFields(logrus.Fields{
			"dest": p.name,
			"source": config.ProxyFor,
			"protocol" : "tcp",
			"action" : "delay",
			"rule": rule.ToConfig(),
			"testid": p.getmyID(),
			"ts" : t.Format("2006-01-02T15:04:05.999999"),
		}).Info("Stream")
		time.Sleep(rule.DelayTime)
	}

	if ((rule.AbortProbability > 0.0) &&
		drawAndDecide(rule.AbortDistribution, rule.AbortProbability)) {
		proxylog.WithFields(logrus.Fields{
			"dest": p.name,
			"source": config.ProxyFor,
			"protocol" : "tcp",
			"action" : "abort",
			"rule": rule.ToConfig(),
			"testid": p.getmyID(),
			"ts" : t.Format("2006-01-02T15:04:05.999999"),
		}).Info("Stream")
		conn.SetLinger(0)
		conn.Close()
		return
	}

	remotehost := p.lb.GetHost()
	rAddr, err := net.ResolveTCPAddr("tcp", remotehost)
	if err != nil {
		globallog.Error("Could not resolve remote address: " + err.Error())
		conn.Close()
		return
	}
	rConn, err := net.DialTCP("tcp", nil, rAddr)
	if err != nil {
		globallog.WithField("errmsg", err.Error()).Error("Could not connect to remote destination")
		conn.Close()
		return
	}
	// Make sure to copy data both directions, do it in separate threads
	var wg sync.WaitGroup
	wg.Add(2)
	//	go p.tcpReadWrite(conn, rConn, Request, &wg)
	//	go p.tcpReadWrite(rConn, conn, Response, &wg)
	//from proxier.go code in Kubernetes
	go copyBytes(conn, rConn, &wg)
	go copyBytes(rConn, conn, &wg)
	wg.Wait()
	conn.Close()
	rConn.Close()
}

//TODO: Need to add drip rule for HTTP (receiver taking in data byte by byte or sender sending data byte by byte, in low bandwidth situations).
//TODO: In the request path, a slow receiver will cause buffer bloat at sender and ultimately lead to memory pressure -- VALIDATE
//TODO: In the response path, emulating a slow response will keep caller connection alive but ultimately delay full req processing, sending HTTP header first, then byte by byte
//	-- VALIDATE if this is useful for common frameworks in languages like Java, Python, Node, Ruby, etc.
///If its not true, there is no need to emulate drip at all.
// ServeHTTP: code that handles proxying of all HTTP requests

/* FIXME: BUG This method reads requests/replies into memory.
* DO NOT use this on very large size requests.
*/
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	reqID := req.Header.Get(config.TrackingHeader)
	var rule Rule
	var decodedData []byte
	var cont bool
	data, err := readBody(req.Body)
	if (reqID != "") {
		// Process the request, see if any rules match it.
		decodedData, err := decodeBody(data, req.Header.Get("content-type"),
			req.Header.Get("content-encoding"))
		if err != nil {
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":   reqID,
				"errmsg":  err.Error()}).Error("Error reading HTTP request")
			rule = NopRule
		} else {
			// Check if we were expecting it on the wire:
			//p.expectCheck(decodedData)
			
			// Get the rule
			rule = p.getRule(Request, reqID, decodedData)
		}
		cont := p.executeRequestRule(reqID, rule, req, decodedData, w)
		if !cont {
			return
		}
	}

	var host = p.lb.GetHost()
	globallog.WithFields(logrus.Fields{
		"service": p.name,
		"reqID":   reqID,
		"host":    host}).Debug("Sending to")

	// If scheme (http/https is not explicitly specified, construct a http request to the requested service
	if (!p.httpregexp.MatchString(host)) {
		host = "http://"+host
	}
	newreq, err := http.NewRequest(req.Method, host+req.RequestURI, bytes.NewReader(data))
	if err != nil {
		status := http.StatusBadRequest
		http.Error(w, http.StatusText(status), status)
		globallog.WithFields(logrus.Fields{
			"service": p.name,
			"reqID":   reqID,
			"errmsg" : err.Error()}).Error("Could not construct proxy request")
		return
	}

	// Copy over the headers
	for k, v := range req.Header {
		if k != "Host" {
			for _, vv := range v {
				newreq.Header.Set(k, vv)
			}
		} else {
			newreq.Header.Set(k, host)
		}
	}

	// Make a connection
	starttime := time.Now()
	resp, err := p.httpclient.Do(newreq)
	respTime := time.Since(starttime)
	if err != nil {
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
		globallog.WithFields(
			logrus.Fields{
				"service":  p.name,
				"duration": respTime.String(),
				"status":   -1,
				"errmsg":   err.Error(),
			}).Info("Request proxying failed")
		return
	}

	// Read the response and see if it matches any rules
	rule = NopRule
	data, err = readBody(resp.Body)
	resp.Body.Close()
	if (reqID != "") {
		decodedData, err = decodeBody(data, resp.Header.Get("content-type"),
			resp.Header.Get("content-encoding"))

		if err != nil {
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":   reqID,
				"errmsg":  err.Error()}).Error("Error reading HTTP reply")
			rule = NopRule
		} else {
			// Check if we were expecting this
			//p.expectCheck(decodedData)

			// Execute rules, if any
			rule = p.getRule(Response, reqID, decodedData)
		}
	
		cont = p.executeResponseRule(reqID, rule, resp, decodedData, respTime, w)
		if !cont {
			return
		}
	}

	//return resp to caller
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Set(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = w.Write(data)
	if err != nil {
		globallog.WithFields(logrus.Fields{
			"service": p.name,
			"errmsg":  err.Error()}).Error("HTTP Proxy write error")
	}
}

// Executes the rule on the request path or response path. ResponseWriter corresponds to the caller's connection
// Returns a bool, indicating whether we should continue request processing further or not
func (p *Proxy) doHTTPAborts(reqID string, rule Rule, w http.ResponseWriter) bool {

	if (rule.ErrorCode < 0)	{
		hj, ok := w.(http.Hijacker)
		if !ok {
			// Revert to 500
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":  reqID,
				"abortmethod" : "reset",
				"errmsg" : "Hijacking not supported",
			}).Error("Hijacking not supported")
			return false
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			// Revert to 500
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			globallog.WithFields(logrus.Fields{
				"service": p.name,
				"reqID":  reqID,
				"abortmethod" : "reset",
				"errmsg" : err.Error(),
			}).Error("Hijacking Failed")
			return false
		}

		// Close the connection, discarding any unacked data
		tcpConn, ok := conn.(*net.TCPConn)
		if (ok) {
			tcpConn.SetLinger(0)
			tcpConn.Close()
		} else  {
			//we couldn't type cast net.Conn to net.TCPConn successfully.
			//This shouldn't occur unless the underlying transport is not TCP.
			conn.Close()
		}
	} else {
		status := rule.ErrorCode
		http.Error(w, http.StatusText(status), status)
	}

	return true
}


// Fault injection happens here.
// Log every request with valid reqID irrespective of fault injection
func (p *Proxy) executeRequestRule(reqID string, rule Rule, req *http.Request, body []byte, w http.ResponseWriter) bool {

	var actions []string
	delay, errorCode, retVal := time.Duration(0), -2, true
	t := time.Now()

	if rule.Enabled {
		globallog.WithField("rule", rule.ToConfig()).Debug("execRequestRule")

		if ((rule.DelayProbability > 0.0) &&
			drawAndDecide(rule.DelayDistribution, rule.DelayProbability)) {
			// In future, this could be dynamically computed -- variable delays
			delay = rule.DelayTime
			actions = append(actions, "delay")
			time.Sleep(rule.DelayTime)
		}

		if ((rule.AbortProbability > 0.0) &&
			drawAndDecide(rule.AbortDistribution, rule.AbortProbability) &&
			p.doHTTPAborts(reqID, rule, w)) {
			actions = append(actions, "abort")
			errorCode = rule.ErrorCode
			retVal = false
		}
	}

	proxylog.WithFields(logrus.Fields{
		"dest": p.name,
		"source": config.ProxyFor,
		"protocol" : "http",
		"trackingheader":  config.TrackingHeader,
		"reqID":  reqID,
		"testid": p.getmyID(),
		"actions" : "["+str.Join(actions, ",")+"]",
		"delaytime": delay.Nanoseconds()/(1000*1000), //actual time req was delayed in milliseconds
		"errorcode": errorCode, //actual error injected or -2
		"uri":  req.RequestURI,
		"ts" : t.Format("2006-01-02T15:04:05.999999"),
		"rule": rule.ToConfig(),
	}).Info("Request")

	return retVal
}

// Wrapper function around executeRule for the Response path
//TODO: decide if we want to log body and header
func (p *Proxy) executeResponseRule(reqID string, rule Rule, resp *http.Response, body []byte, after time.Duration, w http.ResponseWriter) bool {

	var actions []string
	delay, errorCode, retVal := time.Duration(0), -2, true
	t := time.Now()

	if rule.Enabled {
		if ((rule.DelayProbability > 0.0) &&
			drawAndDecide(rule.DelayDistribution, rule.DelayProbability)) {
			// In future, this could be dynamically computed -- variable delays
			delay = rule.DelayTime
			actions = append(actions, "delay")
			time.Sleep(rule.DelayTime)
		}

		if ((rule.AbortProbability > 0.0) &&
			drawAndDecide(rule.AbortDistribution, rule.AbortProbability) &&
			p.doHTTPAborts(reqID, rule, w)) {
			actions = append(actions, "abort")
			errorCode = rule.ErrorCode
			retVal = false
		}
	}

	proxylog.WithFields(logrus.Fields{
		"dest": p.name,
		"source": config.ProxyFor,
		"protocol" : "http",
		"trackingheader":  config.TrackingHeader,
		"reqID":  reqID,
		"testid": p.getmyID(),
		"actions" : "["+str.Join(actions, ",")+"]",
		"delaytime": delay.Nanoseconds()/(1000*1000), //actual time resp was delayed in milliseconds
		"errorcode": errorCode, //actual error injected or -2
		"status": resp.Header.Get("Status"),
		"duration": after.String(),
		"ts" : t.Format("2006-01-02T15:04:05.999999"),
		//log header/body?
		"rule": rule.ToConfig(),
	}).Info("Response")
	
	return retVal
}

// AddRule adds a new rule to the proxy. All requests/replies carrying the trackingheader will be checked
// against all rules, if something matches, the first matched rule will be executed
func (p *Proxy) AddRule(r Rule) {
	//TODO: check validity of regexes before installing a rule!
	p.ruleLock.Lock()
	p.rules[r.MType] = append(p.rules[r.MType], r)
	p.ruleLock.Unlock()
}

// RemoveRule removes a rule from this proxy
func (p *Proxy) RemoveRule(r Rule) bool {
	p.ruleLock.RLock()
	n := len(p.rules[r.MType])
	b := p.rules[r.MType][:0]
	for _, x := range p.rules[r.MType] {
		if x != r {
			b = append(b, x)
		}
	}
	p.ruleLock.RUnlock()
	p.ruleLock.Lock()
	p.rules[r.MType] = b
	p.ruleLock.Unlock()
	return len(p.rules[r.MType]) != n
}

// GetRules returns all rules currently active at this proxy
func (p *Proxy) GetRules() []Rule {
	globallog.Debug("REST get rules")
	p.ruleLock.RLock()
	defer p.ruleLock.RUnlock()
	return append(p.rules[Request], p.rules[Response]...)
}

// GetInstances returns the service instances available in the loadbalancer for a given service
func (p *Proxy) GetInstances() []string {
	return p.lb.GetInstances()
}

// SetInstances sets the service instances available in the loadbalancer for a given service
func (p *Proxy) SetInstances(hosts []string) {
	p.lb.SetInstances(hosts)
}

// Reset clears proxy state. Removes all stored rules and expects. However loadbalancer hosts remain.
func (p *Proxy) Reset() {
	// lock rules, clear, unlock
	p.ruleLock.Lock()
	p.rules = map[MessageType][]Rule{Request: {},
		Response: {}}
	p.ruleLock.Unlock()
	/**
	// lock expects, clear, unlock
	p.expectLock.Lock()
	p.expects = map[string]chan int{}
	p.expectLock.Unlock()
	**/
}

/**
// Expect waits for a pattern to be encountered on the wire, up until timeout, if timeout > 0
// Returns value < 0 if we timeout'd  OR >0 if we saw the expected pattern on the wire
func (p *Proxy) Expect(pattern string, timeout time.Duration) int {
	// Add a new expect to the list
	p.expectLock.Lock()
	c := make(chan int)
	p.expects[pattern] = c
	p.expectLock.Unlock()
	// If we have a timeout, set it up.
	if timeout > 0 {
		time.AfterFunc(timeout, func() {
			// after timeout write a value on the channel
			c <- -1
		})
	}
	// Wait for the value, which means we've seen something or timeout'd.
	val := <-c
	// Remove the expect
	p.expectLock.Lock()
	delete(p.expects, pattern)
	p.expectLock.Unlock()
	return val
}
**/

func (p *Proxy) SetTestID(testID string) {
//	p.expectLock.Lock()
//	defer p.expectLock.Unlock()
	p.testid = testID
	t := time.Now()
	proxylog.WithFields(logrus.Fields{
		"source":     config.ProxyFor,
		"dest": p.name,
		"testid":  testID,
		"ts" : t.Format("2006-01-02T15:04:05.999999"),
	}).Info("Test start")
}

func (p *Proxy) getmyID() string {
//	p.expectLock.RLock()
//	defer p.expectLock.RUnlock()
	return p.testid
}

func (p *Proxy) StopTest(testID string) bool {
	t := time.Now()
//	p.expectLock.Lock()
//	defer p.expectLock.Unlock()
	if testID == p.testid {
		p.testid = ""
		return true
	}
	proxylog.WithFields(logrus.Fields{
		"source":     config.ProxyFor,
		"dest": p.name,
		"ts" : t.Format("2006-01-02T15:04:05.999999"),
		"testid":  testID,
	}).Info("Test stop")
	return false
}

// readBody is shortcut method to get all bytes from a reader
func readBody(r io.Reader) ([]byte, error) {
	result, err := ioutil.ReadAll(r)
	return result, err
}

// Take the raw bytes from a request (or response) and run them through a decompression
// algorithm so we can run the regex on it or log it.
func decodeBody(raw []byte, ct string, ce string) ([]byte, error) {
	if str.Contains(ce, "gzip") {
		gr, err := gzip.NewReader(bytes.NewBuffer(raw))
		if err != nil {
			return []byte{}, err
		}
		result, err := ioutil.ReadAll(gr)
		return result, err
	} else if str.Contains(ce, "deflate") {
		zr, err := zlib.NewReader(bytes.NewBuffer(raw))
		if err != nil {
			return []byte{}, err
		}
		result, err := ioutil.ReadAll(zr)
		return result, err
	}
	return raw, nil
}

// Try to read in an arbitrary json object in the body of the request (or response)
// so we can log it.
func tryGetJSON(raw []byte) interface{} {
	var o interface{}
	err := json.Unmarshal(raw, &o)
	if err != nil {
		globallog.Warn("Could not get JSON from byte array")
		return raw
	}
	return o
}

// drawAndDecide draws from a given distribution and compares (<) the result to a threshold.
// This determines whether an action should be taken or not
func drawAndDecide(distribution ProbabilityDistribution, probability float64) bool {
//	fmt.Printf("In draw and decide with dis %s, thresh %f", DistributionString(distribution), probability);

	switch (distribution) {
	case ProbUniform:
		return rand.Float64() < probability
	case ProbExponential:
		return rand.ExpFloat64() < probability
	case ProbNormal:
		return rand.NormFloat64() < probability
	default:
//		globallog.Warn("Unknown probability distribution " + distribution + ", defaulting to coin flip")
		return rand.Float64() < .5
	}
}
