package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosiner/golog"
	"github.com/ginuerzh/gosocks5"
	"github.com/oschwald/geoip2-golang"
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
	clientListener net.Listener

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
	c.clientListener, err = net.Listen("tcp", c.config.Listen)
	if err != nil {
		return nil, fmt.Errorf("create listener failed: %w", err)
	}
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
	c.regexpRules = make([]proxyRule, len(c.config.Rules.Direct)+len(c.config.Rules.Proxy))
	for i, rs := range [][]string{c.config.Rules.Direct, c.config.Rules.Proxy} {
		proxy := i > 0
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

func (c *Client) Run() {
	for {
		conn, err := c.clientListener.Accept()
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
		conn = &closeOnceConn{Conn: conn}
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

			c.handleConn(conn)
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
	br := bufio.NewReader(conn)
	conn = buffedConn{Conn: conn, br: br}

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
	{
		cConn, err := newCompressConn(conn, c.config.Server.Compress)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("create compress conn failed: %w", err)
		}
		conn = cConn
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
	return c.shouldProxyByGeoIP(ips), nil
}

func (c *Client) handleConn(clientConn net.Conn) {
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
	defer func() {
		if !proxyStarted {
			writeReply(gosocks5.Failure)
		}
	}()
	proxy, err := c.shouldProxy(req.Addr)
	if err != nil {
		golog.WithFields("error", err.Error(), "addr", req.Addr.String()).Error("check addr should proxy failed")
		proxy = true
	}

	var proxyConn net.Conn
	if proxy {
		golog.WithFields("addr", req.Addr.String()).Debug("start proxy")
		proxyConn, err = c.createServerProxyStream(req.Addr.String())
		if err != nil {
			golog.WithFields("error", err).Error("create server proxy conn failed")
			return
		}
		golog.WithFields("addr", req.Addr.String()).Debug("server proxy created")
	} else {
		golog.WithFields("addr", req.Addr.String()).Debug("start direct")
		proxyConn, err = net.DialTimeout("tcp", req.Addr.String(), time.Second*6)
		if err != nil {
			golog.WithFields("error", err).Error("dial addr failed")
			return
		}
	}

	proxyStarted = true
	if !writeReply(gosocks5.Succeeded) {
		proxyConn.Close()
		clientConn.Close()
		return
	}
	pipeConns(clientConn, proxyConn)
}
