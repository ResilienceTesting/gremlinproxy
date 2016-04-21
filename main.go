package main

import (
	"flag"
	"fmt"
	"github.com/gremlinproxy/config"
	"github.com/gremlinproxy/router"
	"net"
	"os"

	"github.com/Sirupsen/logrus"
)

func main() {
	// Read config
	cpath := flag.String("c", "", "Path to the config file")
	flag.Parse()
	if *cpath == "" {
		fmt.Println("No config file specified.\nusage: gremlinproxy -c configfile")
		os.Exit(1)
	}
	conf := config.ReadConfig(*cpath)
	fmt.Println("Config read successful")

	var log = config.GlobalLogger
	// Log as JSON instead of the default ASCII formatter.
	if conf.LogJSON {
		log.Formatter = new(logrus.JSONFormatter)
	}

	if conf.LogstashHost != "" {
		conn, err := net.Dial("udp", conf.LogstashHost)
		if err == nil {
			config.ProxyLogger.Out = conn
		} else {
			config.ProxyLogger.Out = os.Stdout
			config.ProxyLogger.Warn("Could not establish connection to logstash, logging to stderr")
		}
	} else { //else console
		config.ProxyLogger.Out = os.Stdout
	}
	// parse and set our log level
	if conf.LogLevel != "" {
		lvl, err := logrus.ParseLevel(conf.LogLevel)
		if err != nil {
			// default is info, if something went wrong
			log.Level = logrus.InfoLevel
			log.Error("Error parsing log level, defaulting to info")
		} else {
			log.Level = lvl
		}
	} else {
		log.Level = logrus.InfoLevel
	}
	config.TrackingHeader = conf.Router.TrackingHeader
	log.WithField("trackingHeader", config.TrackingHeader).Debug("Config value")
	if config.TrackingHeader == "" {
		panic("No trackingheader provided")
	}

	// Start the router
	r := router.NewRouter(conf)
	r.Run() //this blocks
}
