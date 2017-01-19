package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
	"os"
	"path/filepath"
)

const (
	VERSION = "0.13"
)

var (
	defaultDir = filepath.Join(volume.DefaultDockerRootDirectory, "cinder")
)

func main() {
	showVersion := flag.Bool("version", false, "Display version number of plugin and exit")
	flag.Parse()
	if *showVersion == true {
		fmt.Println("Version: ", VERSION)
		os.Exit(0)
	}

	cfgFile := flag.String("config", "/var/lib/cinder/dockerdriver/config.json", "path to config file")
	debug := flag.Bool("debug", true, "enable debug logging")
	flag.Parse()
	if *debug == true {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.Info("Starting cinder-docker-driver version: ", VERSION)
	d := New(*cfgFile)
	h := volume.NewHandler(d)
	log.Info(h.ServeUnix("root", "cinder"))
}
