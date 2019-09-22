package main

import (
	"io/ioutil"
	"os"
	"sync"
	"syscall"

	"github.com/cosiner/flag"
	"github.com/cosiner/golog"
	"github.com/cosiner/process"
	"github.com/ghodss/yaml"
)

type Flags struct {
	Server bool   `usage:"run as server"`
	Client bool   `usage:"run as client"`
	Debug  bool   `names:"-d,-debug" usage:"run in debug mode"`
	Conf   string `usage:"config file" default:"conf/tunnel.yaml"`
}

func main() {
	var flags Flags
	_ = flag.ParseStruct(&flags)

	if flags.Server == flags.Client {
		stdFatalf("invalid running mode: Server: %t, Client: %t\n", flags.Server, flags.Client)
		return
	}

	content, err := ioutil.ReadFile(flags.Conf)
	if err != nil {
		stdFatalf("read config file content failed: %s, %w\n", flags.Conf, err)
		return
	}

	var config Config
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		stdFatalf("decode config failed: %s, %w\n", flags.Conf, err)
		return
	}

	initGolog(flags.Debug)
	defer golog.DefaultLogger.Close()

	var handler interface {
		Close()
		Run()
	}
	if flags.Server {
		s, err := NewServer(config.Server)
		if err != nil {
			golog.WithFields("error", err.Error()).Fatal("create server failed")
			return
		}
		handler = s
	} else {
		c, err := NewClient(config.Client)
		if err != nil {
			golog.WithFields("error", err.Error()).Fatal("create client failed")
			return
		}
		handler = c
	}
	golog.Info("server started")

	var closeWg sync.WaitGroup
	defer closeWg.Wait()

	osSig := process.NewSignal().
		Ignore(syscall.SIGHUP).
		Exit(os.Kill, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)

	defer handler.Close()
	closeWg.Add(1)
	go func() {
		defer closeWg.Done()
		defer osSig.Close()

		handler.Run()
	}()
	sig := osSig.Loop()
	if sig != nil {
		golog.WithFields("signal", sig.String()).Error("existed by signal")
	}
}
