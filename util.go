package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosiner/golog"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zlib"
	"github.com/lucas-clemente/quic-go"
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

type closeOnceServerConn struct {
	closed uint32
	MultiplexingServerConn
}

func (c *closeOnceServerConn) Close() error {
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return c.MultiplexingServerConn.Close()
	}
	return nil
}

func smuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.KeepAliveTimeout = time.Minute * 3
	return config
}

func quicConfig() *quic.Config {
	return &quic.Config{
		//HandshakeTimeout: time.Second * 3,
		IdleTimeout: time.Minute * 3,
		KeepAlive:   true,
	}
}

type buffReadConn struct {
	net.Conn
	br *bufio.Reader
}

func (s buffReadConn) Read(b []byte) (int, error) {
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
			ExpireDays: 3,
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

type proxyConn struct {
	net.Conn
	rf func(io.Reader) (io.Reader, error)
	wf func(io.Writer) io.Writer
	mu sync.RWMutex

	r io.Reader
	w io.Writer
}

func (c *proxyConn) createReader() (io.Reader, error) {
	var (
		r   io.Reader
		err error
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.r == nil {
		c.r, err = c.rf(c.Conn)
	}
	r = c.r
	return r, err
}
func (c *proxyConn) createWriter() io.Writer {
	var (
		w io.Writer
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		c.w = c.wf(c.Conn)
	}
	w = c.w
	return w
}

func (c *proxyConn) Read(b []byte) (int, error) {
	c.mu.RLock()
	r := c.r
	c.mu.RUnlock()
	if r == nil {
		var err error
		r, err = c.createReader()
		if err != nil {
			return 0, err
		}
	}
	n, err := r.Read(b)
	return n, err
}

func (c *proxyConn) Write(b []byte) (int, error) {
	c.mu.RLock()
	w := c.w
	c.mu.RUnlock()
	if w == nil {
		w = c.createWriter()
	}

	n, err := w.Write(b)
	if err != nil {
		return 0, err
	}
	f, ok := w.(interface {
		Flush() error
	})
	if ok {
		err = f.Flush()
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func newCompressConn(conn net.Conn, algorithm string) (net.Conn, error) {
	switch algorithm {
	case "disable":
		return conn, nil
	default:
		fallthrough
	case "zlib":
		return &proxyConn{
			Conn: conn,
			rf:   func(r io.Reader) (io.Reader, error) { return zlib.NewReader(r) },
			wf:   func(w io.Writer) io.Writer { return zlib.NewWriter(w) },
		}, nil
	case "gzip":
		return &proxyConn{
			Conn: conn,
			rf:   func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) },
			wf:   func(w io.Writer) io.Writer { return gzip.NewWriter(w) },
		}, nil
	case "s2":
		return &proxyConn{
			Conn: conn,
			rf:   func(r io.Reader) (io.Reader, error) { return s2.NewReader(r), nil },
			wf:   func(w io.Writer) io.Writer { return s2.NewWriter(w) },
		}, nil
	case "snappy":
		return &proxyConn{
			Conn: conn,
			rf:   func(r io.Reader) (io.Reader, error) { return snappy.NewReader(r), nil },
			wf:   func(w io.Writer) io.Writer { return snappy.NewBufferedWriter(w) },
		}, nil
	}
}

func parseTransfer(t string) (string, map[string]string) {
	idx := strings.Index(t, ":")
	if idx < 0 {
		return t, nil
	}
	secs := strings.Split(t[idx+1:], ",")
	t = t[:idx]
	options := make(map[string]string)
	for _, s := range secs {
		kvs := strings.SplitN(s, "=", 2)
		var k string
		var v string
		if len(kvs) > 0 {
			k = kvs[0]
		}
		if len(kvs) > 1 {
			v = kvs[1]
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(k)
		if k != "" && v != "" {
			options[k] = v
		}
	}
	return t, options
}

type cycledKeyReader struct {
	s   []byte
	l   int
	idx int
}

func hashKeyForRandReader(k string) []byte {
	var buf bytes.Buffer
	data := []byte(k)
	for i := 0; i < 512; i++ {
		h := sha512.New()
		h.Write(data)
		data = h.Sum(nil)
		buf.Write(data)
	}
	return buf.Bytes()
}

func newCycledKeyReader(key []byte) *cycledKeyReader {
	return &cycledKeyReader{
		s: key,
		l: len(key),
	}
}

func (k *cycledKeyReader) Reset() {
	k.idx = 0
}

func (k *cycledKeyReader) Read(b []byte) (int, error) {
	if k.l <= 0 {
		return 0, io.EOF
	}
	l := len(b)
	var n int
	for {
		c := copy(b[n:], k.s[k.idx:])
		n += c
		k.idx += n
		if k.idx >= k.l {
			k.idx = 0
		}
		if n >= l {
			break
		}
	}
	return n, nil
}

func generateCAKey(keyStr string, bits int) (string, *rsa.PrivateKey, error) {
	r := newCycledKeyReader(hashKeyForRandReader(keyStr))
	keys := make(map[string]*rsa.PrivateKey)
	const NPrimes = 2

	var c int
	if NPrimes%2 == 0 {
		c = 2
	} else {
		c = 1
	}
	for len(keys) < c {
		r.Reset()
		priv, err := rsa.GenerateMultiPrimeKey(r, NPrimes, bits)
		if err != nil {
			return "", nil, err
		}
		data := x509.MarshalPKCS1PrivateKey(priv)
		{
			m := md5.New()
			m.Write(data)
			data = m.Sum(nil)
		}
		key := hex.EncodeToString(data)
		_, has := keys[key]
		if has {
			continue
		}
		keys[key] = priv
	}

	var (
		key  string
		priv *rsa.PrivateKey
	)
	for k, p := range keys {
		if key == "" || k < key {
			key = k
			priv = p
		}
	}
	return key, priv, nil
}

func listenUDPAndWrap(addr string, isServer bool, w *MaskConnWrapper) (net.PacketConn, net.Addr, error) {
	udpaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve udp addr failed: %w", err)
	}
	network := "udp4"
	if udpaddr.IP.To4() == nil {
		network = "udp"
	}
	listenAddr := udpaddr
	if !isServer {
		listenAddr = nil
	}
	c, err := net.ListenUDP(network, listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp failed: %w", err)
	}
	if w == nil {
		return c, nil, nil
	}
	return w.WrapPacketConn(c), udpaddr, nil
}

type MaskConnWrapper struct {
	Masker
}

func NewMaskConnWrapper(key string) *MaskConnWrapper {
	h := md5.New()
	h.Write([]byte(key))
	d := h.Sum(nil)

	r := newCycledKeyReader(d)
	xor := NewXorMasker(d)
	maskers := Maskers{
		xor,
		ReverseMasker{},
		NewDictMasker(r),
	}

	rand.New(rand.NewSource(int64(xor)<<8|int64(xor))).Shuffle(len(maskers), func(i, j int) {
		maskers[i], maskers[j] = maskers[j], maskers[i]
	})
	return &MaskConnWrapper{
		Masker: maskers,
	}
}

func (m *MaskConnWrapper) WrapConn(conn net.Conn) net.Conn {
	return &MaskConn{
		m:    m.Masker,
		Conn: conn,
	}
}

func (m *MaskConnWrapper) WrapPacketConn(conn net.PacketConn) net.PacketConn {
	return &MaskPacketConn{
		m:          m.Masker,
		PacketConn: conn,
	}
}

type Masker interface {
	Mask(b []byte)
	Unmask(b []byte)
}

type Maskers []Masker

func (m Maskers) Mask(b []byte) {
	for i := range m {
		m[i].Mask(b)
	}
}

func (m Maskers) Unmask(b []byte) {
	for i := len(m) - 1; i >= 0; i-- {
		m[i].Unmask(b)
	}
}

func NewXorMasker(key []byte) XorMasker {
	var m byte
	for _, b := range key {
		m ^= b
	}
	return XorMasker(m)
}

type XorMasker byte

func (m XorMasker) Mask(b []byte) {
	for i := range b {
		b[i] ^= byte(m)
	}
}

func (m XorMasker) Unmask(b []byte) {
	m.Mask(b)
}

type ReverseMasker struct{}

func (m ReverseMasker) Mask(b []byte) {
	for i := range b {
		b[i] = 255 - b[i]
	}
}

func (m ReverseMasker) Unmask(b []byte) {
	m.Mask(b)
}

type DictMasker struct {
	dict        [256]byte
	dictRestore [256]byte
}

func NewDictMasker(r *cycledKeyReader) *DictMasker {
	var m DictMasker
	for i := range m.dict {
		m.dict[i] = byte(i)
	}

	var buf [1]byte
	for i := range m.dict {
		_, _ = r.Read(buf[:])
		j := byte(i) ^ buf[0]

		m.dict[i], m.dict[j] = m.dict[j], m.dict[i]
	}
	for i := range m.dict {
		m.dictRestore[m.dict[i]] = byte(i)
	}
	return &m
}

func (m *DictMasker) Mask(b []byte) {
	for i := range b {
		b[i] = m.dict[b[i]]
	}
}

func (m *DictMasker) Unmask(b []byte) {
	for i := range b {
		b[i] = m.dictRestore[b[i]]
	}
}

type MaskConn struct {
	net.Conn

	m Masker
}

func (m *MaskConn) Read(b []byte) (int, error) {
	n, err := m.Conn.Read(b)
	m.m.Unmask(b[:n])
	return n, err
}

func (m *MaskConn) Write(b []byte) (int, error) {
	m.m.Mask(b)
	n, err := m.Conn.Write(b)
	m.m.Unmask(b[n:])
	return n, err
}

type MaskPacketConn struct {
	net.PacketConn

	m Masker
}

func (m *MaskPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := m.PacketConn.ReadFrom(b)
	m.m.Unmask(b[:n])
	return n, addr, err
}

func (m *MaskPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	m.m.Mask(b)
	n, err := m.PacketConn.WriteTo(b, addr)
	m.m.Unmask(b[n:])
	return n, err
}

type connListener struct {
	conn net.Conn
}

func (c *connListener) Close() error {
	return nil
}

func (c *connListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *connListener) Accept() (net.Conn, error) {
	conn := c.conn
	if conn != nil {
		c.conn = nil
		return conn, nil
	}
	return nil, fmt.Errorf("closed")
}

func protocolHttpMatcher(r io.Reader) bool {
	br := bufio.NewReader(r)
	var i int
	for {
		b, err := br.ReadByte()
		if err == io.EOF || b == ' ' {
			break
		}
		if err != nil {
			return false
		}
		var (
			hasMatched bool
			hasNext    bool
		)
		for _, m := range httpMethods {
			if i < len(m) {
				hasNext = hasNext || i < len(m)-1
				if m[i] == b {
					hasMatched = true
				}
			}
		}
		if !hasMatched {
			return false
		}
		if !hasNext {
			break
		}
		i++
	}
	return i >= 3
}

var localIpnets []*net.IPNet

func init() {
	cidrs := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
	for _, n := range cidrs {
		_, ipnet, err := net.ParseCIDR(n)
		if err != nil {
			panic(fmt.Errorf("parse lan ip nets failed: %s, %w", n, err))
		}
		localIpnets = append(localIpnets, ipnet)
	}
}

func isLocalIpNet(ip net.IP) bool {
	for _, n := range localIpnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
