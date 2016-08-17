package main

import (
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
	"path/filepath"
)

var (
	defaultDir = filepath.Join(volume.DefaultDockerRootDirectory, "cinder")
)

func main() {
	cfgFile := flag.String("config", "/var/lib/cinder/dockerdriver/config.json", "path to config file")
	debug := flag.Bool("debug", true, "enable debug logging")
	flag.Parse()
	if *debug == true {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	d := New(*cfgFile)
	h := volume.NewHandler(d)
	log.Info(h.ServeUnix("root", "cinder"))
}
