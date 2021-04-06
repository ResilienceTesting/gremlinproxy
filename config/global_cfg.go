// Some constants and globally accessible vars that remain constats once configured
package config

import (
	log "github.com/sirupsen/logrus"
	"os"
)

const OK = "OK"
const ERROR = "ERROR"
const NAME = "gremlinproxy"

var TrackingHeader string
var ProxyFor string

var GlobalLogger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.TextFormatter),
	Hooks:     make(log.LevelHooks),
	Level:     log.WarnLevel,
}
var ProxyLogger = &log.Logger{
	Out:       os.Stderr,
	Formatter: new(log.JSONFormatter),
	Hooks:     make(log.LevelHooks),
	Level:     log.InfoLevel,
}
