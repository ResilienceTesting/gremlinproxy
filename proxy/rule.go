package proxy

import (
	"errors"
	"github.com/ResilienceTesting/gremlinproxy/config"
	str "strings"
	"time"

)

// MessageType is just that a type: request or reply
type MessageType uint

// ActionType actions we can do to a request or reply: abort, delay,...
//type ActionType uint

// ActionMethod with respect to an action. In case of abort it's hang, reset,...
type ActionMethod uint

// ProbabilityDistribution is a type for probability distribution functions for rules
type ProbabilityDistribution uint

/*
const (
	// ActionAbort abort
	ActionAbort ActionType = 1 << iota
	// ActionDelay delay
	ActionDelay
	// ActionAbortOrDelay inject a abort or delay (for overload scenario)
	ActionAbortOrDelay
	// ActionNop do nothing
	ActionNop
)
*/

// //customizations within abort or delay
// const (
// 	// MethodStatus return some protocol specific error
// 	MethodError = iota
// 	// MethodReset TCP reset
// 	MethodReset
// 	//Emulates slow connections
// 	//MethodDrip
// )

const (
	ProbUniform = iota
	ProbExponential
	ProbNormal
)

/*
var actionMap = map[ActionType]string{
	ActionAbort:  "abort",
	ActionDelay:  "delay",
	ActionAbortOrDelay: "abort_or_delay",
	ActionNop:    "nop",
}
*/

// var methodMap = map[ActionMethod]string{
// 	MethodError: "errorcode",
// 	MethodReset: "connreset",
// 	//MethodDrip: "drip",
// }

var distributionMap = map[ProbabilityDistribution]string{
	ProbUniform: "uniform",
	ProbExponential: "exponential",
	ProbNormal: "normal",
}

//message channel type between client and server, via the proxy
const (
	Request MessageType = iota
	Response
	Publish
	Subscribe
)

var rMap = map[MessageType]string{
	Request: "request",
	Response: "response",
	Publish: "publish",
	Subscribe: "subscribe",
}

// Rule is a universal type for all rules.
type Rule struct {
	Source    string
	Dest      string
	MType           MessageType
	//Method       ActionMethod

	//Select only messages that match pattens specified in these fields
	BodyPattern      string
	HeaderPattern    string

	// Probability float64
	// Distribution string
	
	// First delay, then mangle and then abort
	// One could set the probabilities of these variables to 0/1 to toggle them on or off
	// We effectively get 8 combinations but only few make sense.
	DelayProbability  float64
	DelayDistribution ProbabilityDistribution
	MangleProbability  float64
	MangleDistribution ProbabilityDistribution
	AbortProbability  float64
	AbortDistribution ProbabilityDistribution

	//TestID       string
	DelayTime time.Duration
	ErrorCode int
	SearchString string
	ReplaceString string
	Enabled bool
}

// NopRule is a rule that does nothing. Useful default return value
var NopRule = Rule{Enabled: false}

func getDistribution(distribution string) (ProbabilityDistribution, error) {

	if distribution == "" {
		return ProbUniform, nil
	}

	switch str.ToLower(distribution) {
	case "uniform":
		return ProbUniform, nil
	case "exponential":
		return ProbExponential, nil
	case "normal":
		return ProbNormal, nil
	default:
		return ProbUniform, errors.New("Unknown probability distribution")
	}
}

// NewRule return a new rule based on the config.
func NewRule(c config.RuleConfig) (Rule, error) {
	var r Rule
	var err error
	/*
	// Convert actions into masks so we can check them quickly
	for _, a := range c.Actions {
		switch str.ToLower(a) {
		case "abort":
			r.Action = r.Action | ActionAbort
			break
		case "delay":
			r.Action = r.Action | ActionDelay
			break
		case "abort_or_delay":
			r.Action = r.Action | ActionAbortOrDelay
			break
		default:
			return NopRule, errors.New("Unsupported action")
		}
	}*/
	// Convert request/reply types
	switch str.ToLower(c.MType) {
	case "request":
		r.MType = Request
	case "response":
		r.MType = Response
	case "publish":
		r.MType = Publish
	case "subscribe":
		r.MType = Subscribe
	default:
		return NopRule, errors.New("Unsupported request type")
	}
	r.BodyPattern = c.BodyPattern
	r.HeaderPattern = c.HeaderPattern
	//sanity check
	//atleast header or body pattern must be non-empty
	if r.HeaderPattern == "" {
		return NopRule, errors.New("HeaderPattern cannot be empty (specify * instead)")
	}

	if r.BodyPattern == "" {
		r.BodyPattern = "*"
	}

	r.DelayDistribution, err = getDistribution(c.DelayDistribution)
	if (err != nil) {
		return NopRule, err
	}
	r.MangleDistribution, err = getDistribution(c.MangleDistribution)
	if (err != nil) {
		return NopRule, err
	}

	r.AbortDistribution, err = getDistribution(c.AbortDistribution)
	if (err != nil) {
		return NopRule, err
	}

	r.DelayProbability = c.DelayProbability
	r.MangleProbability = c.MangleProbability
	r.AbortProbability = c.AbortProbability
	valid := ((r.DelayProbability > 0.0) || (r.MangleProbability > 0.0) || (r.AbortProbability > 0.0))
	if (!valid) {
		return NopRule, errors.New("Atleast one of delayprobability, mangleprobability, abortprobability must be non-zero and <=1.0")
	}

	// valid = ((r.DelayProbability >1.0) || (r.MangleProbability > 1.0) || (r.AbortProbability > 1.0))
	// if (!valid) {
	// 	globallog.WithFields(logrus.Fields{"delay", r.DelayProbability, "abort": r.AbortProbability, "mangle": r.MangleProbability}).Warn("Probability cannot be >1.0")
	// 	return NopRule, errors.New("Probability cannot be >1.0")
	// }

	//r.TestID = c.TestID
	// r.DelayTime = time.Duration(c.DelayTime) * time.Millisecond
	if c.DelayTime != "" {
		var err error
		r.DelayTime, err = time.ParseDuration(c.DelayTime)
		if err != nil {
			globallog.WithField("errmsg", err.Error()).Warn("Could not parse rule delay time")
			return NopRule, err
		}
	} else {
		if (r.DelayProbability == 0.0) {
			return NopRule, errors.New("Invalid Delay (0s) when delayprobability >0.0")
		}
		r.DelayTime = time.Duration(0)
	}

//	switch str.ToLower(c.Method) {
//	case "hang":
//		r.Method = MethodHang
	// case "reset":
	// 	r.Method = MethodReset
	// case "error":
	// 	r.Method = MethodError
	// default:
	// 	return NopRule, errors.New("Unsupported method")
	// }
	r.ErrorCode = c.ErrorCode
	r.SearchString = c.SearchString
	r.ReplaceString = c.ReplaceString
	r.Source = c.Source
	r.Dest = c.Dest
	r.Enabled = true
	return r, nil
}

// ToConfig converts the rule into a human-readable string config.
func (r *Rule) ToConfig() config.RuleConfig {
	var c config.RuleConfig

	// Converting combo actions back into separate strings using some bit manipulations
	// c.Actions = []string{}
	// for a := range actionMap {
	// 	if a&r.Action > 0 {
	// 		c.Actions = append(c.Actions, actionMap[a])
	// 	}
	// }
	c.Source = r.Source
	c.Dest = r.Dest
	c.MType = rMap[r.MType]

	c.HeaderPattern = r.HeaderPattern
	// c.TestID = r.TestID
	c.BodyPattern = r.BodyPattern


	c.DelayDistribution = distributionMap[r.DelayDistribution]
	c.MangleDistribution = distributionMap[r.MangleDistribution]
	c.AbortDistribution = distributionMap[r.AbortDistribution]

	c.DelayProbability = r.DelayProbability
	c.MangleProbability = r.MangleProbability
	c.AbortProbability = r.AbortProbability

//	c.Method = methodMap[r.Method]

	c.DelayTime = r.DelayTime.String()
	c.ErrorCode = r.ErrorCode
	c.SearchString = r.SearchString
	c.ReplaceString = r.ReplaceString

	return c
}

// ActionString returns the string that represents this action.
// Warning: does not work on compound actions
// func ActionString(a ActionType) string {
// 	return actionMap[a]
// }

// ReqString returns the string represtation of MessageType: either "request" or "reply"
func ReqString(r MessageType) string {
	return rMap[r]
}

// MethodString returns the string version of a abort method: hang, reset, httpstatus...
// func MethodString(m ActionMethod) string {
// 	return methodMap[m]
// }

func DistributionString(p ProbabilityDistribution) string {
	return distributionMap[p]
}
