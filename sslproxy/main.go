package main

import (
	"fmt"
	"os"
	"os/signal"
	"sslproxy/conf"
	"sslproxy/services"
	"syscall"
)

const APP_VERSION = "3.0"

func main() {

	//Clean()
	ret := conf.LoadConfig()
	if ret < 0 {
		fmt.Println("\nParse config failed")
		return
	}
	ret = services.Mirror_cfg_set(conf.Mirror_cfg.I_iface, conf.Mirror_cfg.In_mac,
		conf.Mirror_cfg.O_iface, conf.Mirror_cfg.O_mac)
	if ret < 0 {
		fmt.Println("\nMirror config failed\n")
		return
	}
	ret = services.Mirror_start()
	if ret < 0 {
		fmt.Println("\nMirror start failed\n")
		return
	}
	services.Https_start()
}
func Clean() {
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		for _ = range signalChan {
			fmt.Println("\nReceived an interrupt, stopping services...")

			cleanupDone <- true
		}
	}()
	<-cleanupDone
}
