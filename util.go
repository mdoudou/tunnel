package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosiner/golog"
	"github.com/xtaci/smux"
)

type closeOnceConn struct {
	closed uint32
	net.Conn
}

func (c *closeOnceConn) Close() error {
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return c.Conn.Close()
	}
	return nil
}

func smuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.KeepAliveTimeout = time.Minute * 5
	return config
}

type buffedConn struct {
	net.Conn
	br *bufio.Reader
}

func (s buffedConn) Read(b []byte) (int, error) {
	var buffed int
	if s.br != nil {
		buffed = s.br.Buffered()
		if buffed > 0 {
			return io.LimitReader(s.br, int64(buffed)).Read(b)
		}
		s.br = nil
	}
	return s.Conn.Read(b)
}

func ignoreError(err error) bool {
	switch err {
	case nil, io.EOF, io.ErrClosedPipe:
		return true
	default:
		msg := err.Error()
		return strings.Contains(msg, "EOF") ||
			strings.Contains(msg, "closed pipe") ||
			strings.Contains(msg, "use of closed network connection")
	}
}

func pipeConns(clientConn, proxyConn net.Conn) {
	var wg sync.WaitGroup
	defer wg.Wait()

	defer clientConn.Close()
	defer proxyConn.Close()

	copyBuffer := func(dst, src net.Conn) {
		buf := make([]byte, 128*1024)
		_, err := io.CopyBuffer(dst, src, buf)
		if err != nil && !ignoreError(err) {
			golog.WithFields("error", err.Error()).Error("copy data failed")
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		copyBuffer(clientConn, proxyConn)
	}()
	copyBuffer(proxyConn, clientConn)
}

func stdFatalf(format string, v ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, v...)
	os.Exit(1)
}

func initGolog(debug bool) {
	var writer golog.Writer
	logLevel := golog.LevelInfo
	if debug {
		logLevel = golog.LevelDebug
		writer = golog.Console()
	} else {
		var err error
		writer, err = golog.SingleFile(golog.FileLogOptions{
			ExpireDays: 7,
			LogDir:     "logs",
		})
		if err != nil {
			stdFatalf("create log writer failed: %w\n", err)
			return
		}
	}

	golog.DefaultLogger = golog.New(logLevel, 0, 0, golog.NewJSONEncoder(""))
	golog.DefaultLogger.AddWriter(writer)
}

func geoIpDBFile() (string, error) {
	const (
		url      = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz"
		filename = "GeoLite2-Country.mmdb"
	)
	path := filepath.Join(os.TempDir(), "tunnel", filename)
	_, err := os.Stat(path)
	if err == nil {
		return path, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	//client := http.Client{Timeout: time.Second * 10}
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	gzR, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", err
	}
	tarR := tar.NewReader(gzR)

	var found bool
OUTER:
	for {
		header, err := tarR.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		switch header.Typeflag {
		case tar.TypeReg:
			if strings.HasSuffix(header.Name, filename) {
				found = true
				break OUTER
			}
		}
	}
	if !found {
		return "", fmt.Errorf("geoip db file not found")
	}

	err = os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return "", fmt.Errorf("create path dirs failed: %w", err)
	}
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("create destination file failed: %w", err)
	}
	_, err = io.Copy(fd, tarR)
	if err != nil {
		fd.Close()
		os.Remove(path)
		return "", fmt.Errorf("write destination file failed: %w", err)
	}
	fd.Close()
	return path, nil
}
