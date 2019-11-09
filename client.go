package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosiner/golog"
	"github.com/ginuerzh/gosocks5"
	"github.com/oschwald/geoip2-golang"
	"github.com/soheilhy/cmux"
)

type proxyRule struct {
	Matcher *regexp.Regexp
	Proxy   bool
}

type Client struct {
	config ClientConfig

	regexpRules []proxyRule
	geoip       *geoip2.Reader

	closed         uint32
	clientListener *groupListener

	serverTransfer Transfer
	serverConnMu   sync.RWMutex
	serverConns    map[MultiplexingClientConn]int

	clientConnWg sync.WaitGroup
	clientConnMu sync.RWMutex
	clientConns  map[net.Conn]struct{}
}

func NewClient(config ClientConfig) (*Client, error) {
	c := Client{
		config:       config,
		clientConnWg: sync.WaitGroup{},
		clientConns:  make(map[net.Conn]struct{}),
		serverConns:  make(map[MultiplexingClientConn]int),
	}
	var err error
	l, err := net.Listen("tcp", c.config.Listen)
	if err != nil {
		return nil, fmt.Errorf("create listener failed: %w", err)
	}
	c.clientListener = newGroupListener(l)
	transfer, options := parseTransfer(config.Server.Transfer)
	tc, ok := transfers[transfer]
	if !ok {
		return nil, fmt.Errorf("unsupported transfer protcol: %s", config.Server.Transfer)
	}
	c.serverTransfer, err = tc(c.config.Server.Key, options, NewMaskConnWrapper(c.config.Server.Key))
	if err != nil {
		return nil, fmt.Errorf("create transfer failed: %w", err)
	}
	if c.config.Geoip.File == "" && c.config.Geoip.AutoDownload {
		c.config.Geoip.File, err = geoIpDBFile()
		if err != nil {
			return nil, fmt.Errorf("download geoip file failed: %w", err)
		}
	}
	if c.config.Geoip.File != "" {
		c.geoip, err = geoip2.Open(c.config.Geoip.File)
		if err != nil {
			return nil, fmt.Errorf("read geoip db file failed: %w", err)
		}
		if c.config.Geoip.NameLang == "" {
			c.config.Geoip.NameLang = "zh-CN"

			if len(c.config.Geoip.DirectCountries) == 0 {
				c.config.Geoip.DirectCountries = []string{"中国"}
			}
		}
	}
	c.regexpRules = make([]proxyRule, 0, len(c.config.Rules.Proxy)+len(c.config.Rules.Direct))
	for i, rs := range [][]string{c.config.Rules.Proxy, c.config.Rules.Direct} {
		proxy := i == 0
		for _, r := range rs {
			reg, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy rule regexp: %s, %w", r, err)
			}
			c.regexpRules = append(c.regexpRules, proxyRule{
				Matcher: reg,
				Proxy:   proxy,
			})
		}
	}
	return &c, nil
}

func (c *Client) closeAllClientConns() {
	c.clientConnMu.Lock()
	defer c.clientConnMu.Unlock()

	for c := range c.clientConns {
		c.Close()
	}
}
func (c *Client) closeServerConns() {
	c.serverConnMu.Lock()
	defer c.serverConnMu.Unlock()

	for c := range c.serverConns {
		c.Close()
	}
}

func (c *Client) Close() {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return
	}

	c.clientListener.Close()
	c.closeAllClientConns()
	c.closeServerConns()

	c.clientConnWg.Wait()
}

type acceptResult struct {
	Type string
	Conn net.Conn

	Err error
}

type groupListener struct {
	l net.Listener

	c      chan acceptResult
	close  chan struct{}
	closed bool
}

func newGroupListener(l net.Listener) *groupListener {
	g := groupListener{
		l:     l,
		c:     make(chan acceptResult, 2),
		close: make(chan struct{}),
	}
	g.run()
	return &g
}

func (t groupListener) Close() {
	t.closed = true
	close(t.close)
	t.l.Close()
}

var httpMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodOptions,
	http.MethodTrace,
}

func (t groupListener) run() {
	l := cmux.New(t.l)
	for typ, l := range map[string]net.Listener{
		"http":   l.Match(protocolHttpMatcher),
		"socks5": l.Match(cmux.Any()),
	} {
		typ := typ
		l := l
		go func() {
			for {
				conn, err := l.Accept()
				if t.closed {
					break
				}
				t.c <- acceptResult{
					Conn: conn,
					Err:  err,
					Type: typ,
				}
			}
		}()
	}
	go l.Serve()
}

func (t groupListener) Accept() (acceptResult, error) {
	if t.closed {
		return acceptResult{}, fmt.Errorf("listener closed")
	}
	select {
	case res := <-t.c:
		return res, res.Err
	case <-t.close:
		return acceptResult{}, fmt.Errorf("listener closed")
	}
}

func (c *Client) Run() {
	for {
		res, err := c.clientListener.Accept()
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Temporary() {
					continue
				}
			}

			if !ignoreError(err) {
				golog.WithFields("error", err.Error()).Fatal("listener accept conn failed")
			}
			return
		}

		c.clientConnMu.Lock()
		conn := net.Conn(&closeOnceConn{Conn: res.Conn})
		c.clientConns[conn] = struct{}{}
		c.clientConnMu.Unlock()
		c.clientConnWg.Add(1)
		go func() {
			defer func() {
				c.clientConnWg.Done()
				c.clientConnMu.Lock()
				delete(c.clientConns, conn)
				c.clientConnMu.Unlock()
			}()

			c.handleConn(conn, res.Type)
		}()
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (c *Client) getServerConn() (MultiplexingClientConn, error) {
	c.serverConnMu.Lock()
	defer c.serverConnMu.Unlock()

	var curr []MultiplexingClientConn
	for c := range c.serverConns {
		if len(curr) == 0 || c.NumStreams() < curr[0].NumStreams() {
			curr = []MultiplexingClientConn{c}
		} else if c.NumStreams() == curr[0].NumStreams() {
			curr = append(curr, c)
		}
	}
	const KEEP_SERVER_CONN = 4
	if len(c.serverConns) < KEEP_SERVER_CONN {
		conn, err := c.serverTransfer.Dial(c.config.Server.Listen)
		if err != nil {
			if len(curr) == 0 {
				return nil, fmt.Errorf("dial server failed: %w", err)
			}
			golog.WithFields("erorr", err.Error()).Error("create new server connection failed")
		} else {
			c.serverConns[conn] = 0
			curr = []MultiplexingClientConn{conn}
		}
	}
	if len(curr) > 0 {
		return curr[rand.Intn(len(curr))], nil
	}
	return nil, fmt.Errorf("no conn available")
}

func (c *Client) incrServerConnFailTimes(conn MultiplexingClientConn) {
	c.serverConnMu.Lock()
	defer c.serverConnMu.Unlock()

	const MAX_FAIL = 4
	times, has := c.serverConns[conn]
	if has {
		times++
		if times >= MAX_FAIL {
			delete(c.serverConns, conn)
			return
		}

		c.serverConns[conn] = times
	}
}

func (c *Client) clearServerConnFailTimes(conn MultiplexingClientConn) {
	c.serverConnMu.Lock()
	defer c.serverConnMu.Unlock()
	_, has := c.serverConns[conn]
	if has {
		c.serverConns[conn] = 0
	}
}

type clientProxyConn struct {
	net.Conn

	sconn MultiplexingClientConn
	c     *Client
}

func (c *clientProxyConn) Close() error {
	err := c.Conn.Close()
	if !c.c.isServerConnAlive(c.sconn) && c.sconn.NumStreams() <= 0 {
		c.sconn.Close()
	}
	return err
}

func (c *Client) isServerConnAlive(conn MultiplexingClientConn) bool {
	c.serverConnMu.RLock()
	_, has := c.serverConns[conn]
	c.serverConnMu.RUnlock()
	return has
}

func (c *Client) openServerStream() (net.Conn, error) {
	for i := 0; i < 3; i++ {
		conn, err := c.getServerConn()
		if err != nil {
			return nil, err
		}
		stream, err := conn.OpenStream()
		if err != nil {
			c.incrServerConnFailTimes(conn)
			golog.WithFields("error", err.Error()).Error("open server stream failed")
			continue
		}
		c.clearServerConnFailTimes(conn)
		return &clientProxyConn{
			Conn:  stream,
			sconn: conn,
			c:     c,
		}, nil
	}
	return nil, fmt.Errorf("no conn available")
}

func (c *Client) createServerProxyStream(addr string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	conn, err = c.openServerStream()
	if err != nil {
		return nil, err
	}
	{
		cConn, err := newCompressConn(conn, c.config.Server.Compress)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("create compress conn failed: %w", err)
		}
		conn = cConn
	}

	br := bufio.NewReader(conn)
	conn = buffReadConn{Conn: conn, br: br}

	err = ProtocolWrite(conn, HandshakeRequest{Addr: addr})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write handshake request failed: %w", err)
	}
	var handshakeResp HandshakeResponse
	err = ProtocolRead(br, &handshakeResp)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read handshake response failed: %w", err)
	}
	switch handshakeResp.Status {
	case HandshakeStatusOK:
	default:
		return nil, fmt.Errorf("server proxy addr failed: %s", handshakeResp.Msg)
	}

	return conn, nil
}

func (c *Client) shouldProxyByGeoIP(ips []net.IP) bool {
	var (
		hasProxy  bool
		hasDirect bool
	)
	for _, ip := range ips {
		ips = append(ips, ip)
		country, err := c.geoip.Country(ip)
		if err != nil {
			golog.WithFields("error", err.Error(), "ip", ip).Error("geoip lookup failed")
			continue
		}
		countryName := country.Country.Names[c.config.Geoip.NameLang]

		var direct bool
		for _, c := range c.config.Geoip.DirectCountries {
			if c == countryName {
				direct = true
				break
			}
		}
		hasProxy = hasProxy || !direct
		hasDirect = hasDirect || direct
	}
	if hasProxy {
		return true
	}
	if hasDirect {
		return false
	}
	return true
}

func (c *Client) resolveAddrIps(addr *gosocks5.Addr) ([]net.IP, error) {
	var ips []net.IP
	switch addr.Type {
	case gosocks5.AddrDomain:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()

		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, addr.Host)
		if err != nil {
			return nil, fmt.Errorf("resolve domain ip failed: %s, %w", addr.Host, err)
		}
		for _, ip := range resolved {
			ips = append(ips, ip.IP)
		}
	case gosocks5.AddrIPv4, gosocks5.AddrIPv6:
		ip := net.ParseIP(addr.Host)
		if len(ip) > 0 {
			ips = append(ips, ip)
		} else {
			return nil, fmt.Errorf("invalid ip address: %s", addr.Host)
		}
	default:
		return nil, fmt.Errorf("unsupported addr type: %d", addr.Type)
	}
	return ips, nil
}

func (c *Client) shouldProxy(addr *gosocks5.Addr) (bool, error) {
	for _, r := range c.regexpRules {
		if r.Matcher.MatchString(addr.Host) {
			return r.Proxy, nil
		}
	}
	if c.geoip == nil {
		return true, nil
	}
	ips, err := c.resolveAddrIps(addr)
	if err != nil {
		return false, nil
	}
	for _, ip := range ips {
		if isLocalIpNet(ip) {
			return false, nil
		}
	}
	return c.shouldProxyByGeoIP(ips), nil
}

func (c *Client) connectToRemote(addr *gosocks5.Addr) (net.Conn, bool) {
	proxy, err := c.shouldProxy(addr)
	if err != nil {
		golog.WithFields("error", err.Error(), "addr", addr.String()).Error("check addr should proxy failed")
		proxy = true
	}

	var proxyConn net.Conn
	if proxy {
		golog.WithFields("addr", addr.String()).Debug("start proxy")
		proxyConn, err = c.createServerProxyStream(addr.String())
		if err != nil {
			golog.WithFields("error", err).Error("create server proxy conn failed")
			return nil, false
		}
		golog.WithFields("addr", addr.String()).Debug("server proxy created")
	} else {
		golog.WithFields("addr", addr.String()).Debug("start direct")
		proxyConn, err = net.DialTimeout("tcp", addr.String(), time.Second*6)
		if err != nil {
			golog.WithFields("error", err, "addr", addr.String()).Error("dial addr failed")
			return nil, false
		}
	}
	return proxyConn, true
}

func (c *Client) handleSocks5(clientConn net.Conn) {
	var proxyStarted bool
	defer func() {
		if !proxyStarted {
			clientConn.Close()
		}
	}()
	{
		sconn := gosocks5.ServerConn(clientConn, nil)
		err := sconn.Handleshake()
		if err != nil {
			golog.WithFields("addr", clientConn.RemoteAddr().String(), "error", err.Error()).Error("handshake conn failed")
			return
		}
		clientConn = sconn
	}

	req, err := gosocks5.ReadRequest(clientConn)
	if err != nil {
		golog.WithFields("addr", clientConn.RemoteAddr().String(), "error", err.Error()).Error("read client request failed")
		return
	}
	writeReply := func(res uint8) bool {
		reply := gosocks5.NewReply(res, nil)
		err = reply.Write(clientConn)
		if err != nil {
			golog.WithFields("error", err.Error()).Error("write reply failed")
			return false
		}
		return true
	}
	switch req.Cmd {
	case gosocks5.CmdConnect:
	default:
		golog.WithFields("addr", clientConn.RemoteAddr().String(), "cmd", req.Cmd).Error("unsupported cmd from client")
		writeReply(gosocks5.CmdUnsupported)
		return
	}
	proxyConn, ok := c.connectToRemote(req.Addr)
	if !ok {
		return
	}

	var replyWrited bool
	defer func() {
		if !replyWrited {
			writeReply(gosocks5.Failure)
		}
	}()

	replyWrited = true
	if !writeReply(gosocks5.Succeeded) {
		proxyConn.Close()
		return
	}

	proxyStarted = true
	pipeConns(clientConn, proxyConn)
}

func (c *Client) handleHttp(clientConn net.Conn) {
	var proxyStarted bool
	defer func() {
		if !proxyStarted {
			clientConn.Close()
		}
	}()

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		golog.WithFields("error", err.Error()).Errorf("read request failed")
		return
	}
	writeResp := func(statusCode int, statusText string) {
		resp := http.Response{
			StatusCode: statusCode,
			Status:     statusText,
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Header:     make(http.Header),
			Close:      true,
		}
		resp.Write(clientConn)
	}

	host := req.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "http" {
			host += ":80"
		} else if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			writeResp(http.StatusBadRequest, "Bad Request")
			return
		}
	}
	addr, err := gosocks5.NewAddr(host)
	if err != nil {
		golog.WithFields("error", err.Error()).Error("parse request host failed")
		return
	}

	proxyConn, ok := c.connectToRemote(addr)
	if !ok {
		writeResp(http.StatusServiceUnavailable, "Service unavailable")
		return
	}
	defer func() {
		if !proxyStarted {
			proxyConn.Close()
		}
	}()
	if req.Method == http.MethodConnect {
		writeResp(http.StatusOK, "Connection established")
	} else {
		err = req.Write(proxyConn)
		if err != nil {
			golog.WithFields("error", err.Error()).Error("write request to proxy conn failed")
			writeResp(http.StatusBadGateway, "Bad Gateway")
			return
		}
	}

	proxyStarted = true
	pipeConns(buffReadConn{Conn: clientConn, br: br}, proxyConn)
}

func (c *Client) handleConn(clientConn net.Conn, typ string) {
	switch typ {
	case "socks5":
		c.handleSocks5(clientConn)
	case "http":
		c.handleHttp(clientConn)
	default:
		clientConn.Close()
	}
}
