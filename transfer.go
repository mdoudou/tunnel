package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	"github.com/ghodss/yaml"
	"github.com/lucas-clemente/quic-go"
	"github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
)

func parseOptions(options map[string]string, ptr interface{}) error {
	var buf bytes.Buffer
	for k, v := range options {
		buf.WriteString(k)
		buf.WriteString(": ")
		buf.WriteString(v)
		buf.WriteString("\n")
	}
	if buf.Len() > 0 {
		return yaml.Unmarshal(buf.Bytes(), ptr)
	}
	return nil
}

type TransferCreator func(key string, options map[string]string, w *MaskConnWrapper) (Transfer, error)

var transfers = map[string]TransferCreator{
	"kcp":  NewKcp,
	"quic": NewQUIC,
	"tcp":  NewTcp,
}

type MultiplexingConn interface {
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	NumStreams() int
}

type MultiplexingServerConn interface {
	MultiplexingConn
	AcceptStream() (net.Conn, error)
}

type MultiplexingClientConn interface {
	MultiplexingConn
	OpenStream() (net.Conn, error)
}

type MultiplexingListener interface {
	Close() error
	Accept() (MultiplexingServerConn, error)
}

type Transfer interface {
	Dial(addr string) (MultiplexingClientConn, error)
	Listen(addr string) (MultiplexingListener, error)
}

type Kcp struct {
	w          *MaskConnWrapper
	crypt      kcp.BlockCrypt
	smuxConfig *smux.Config

	configs struct {
		Crypt        string
		Mode         string
		DataShards   int
		ParityShards int
	}
}

func newKcpCrypt(crypt, key string) (kcp.BlockCrypt, error) {
	h := sha256.New()
	h.Write([]byte(key))
	k := h.Sum(nil)
	switch crypt {
	case "aes-128":
		k = k[:16]
	case "aes-192":
		k = k[:24]
	default:
		fallthrough
	case "aes-256":
		k = k[:32]
	}
	return kcp.NewAESBlockCrypt(k)
}

func NewKcp(key string, options map[string]string, w *MaskConnWrapper) (Transfer, error) {
	var err error
	k := Kcp{
		w:          w,
		smuxConfig: smuxConfig(),
	}
	err = parseOptions(options, &k.configs)
	if err != nil {
		return nil, fmt.Errorf("parse kcp options failed: %s", err.Error())
	}
	{
		if k.configs.DataShards <= 0 {
			k.configs.DataShards = 3
		}
		if k.configs.ParityShards <= 0 {
			k.configs.DataShards = 3
		}
	}

	k.crypt, err = newKcpCrypt(k.configs.Crypt, key)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (k *Kcp) initConn(u *kcp.UDPSession) {
	u.SetStreamMode(true)
	u.SetWriteDelay(false)
	u.SetACKNoDelay(true)
	switch k.configs.Mode {
	case "normal":
		u.SetNoDelay(0, 40, 2, 1)
	case "fast":
		u.SetNoDelay(0, 30, 2, 1)
	case "fast2":
		u.SetNoDelay(1, 20, 2, 1)
	case "fast3":
		fallthrough
	default:
		u.SetNoDelay(1, 10, 2, 1)
	}
}

func (k *Kcp) Dial(addr string) (MultiplexingClientConn, error) {
	uc, _, err := listenUDPAndWrap(addr, false, k.w)
	if err != nil {
		return nil, err
	}
	u, err := kcp.NewConn(addr, k.crypt, k.configs.DataShards, k.configs.ParityShards, uc)
	if err != nil {
		return nil, err
	}
	k.initConn(u)
	conn, err := newSmuxClientConn(u, k.smuxConfig)
	if err != nil {
		u.Close()
		return nil, err
	}
	return conn, nil
}

type kcpListener struct {
	k *Kcp
	*kcp.Listener
}

func (l kcpListener) Accept() (net.Conn, error) {
	u, err := l.Listener.AcceptKCP()
	if err != nil {
		return nil, err
	}
	l.k.initConn(u)
	return u, nil
}

func (k *Kcp) Listen(addr string) (MultiplexingListener, error) {
	uc, _, err := listenUDPAndWrap(addr, true, k.w)
	if err != nil {
		return nil, err
	}
	l, err := kcp.ServeConn(k.crypt, k.configs.DataShards, k.configs.ParityShards, uc)
	if err != nil {
		return nil, err
	}
	return smuxListener{
		Listener: kcpListener{k: k, Listener: l},
		config:   k.smuxConfig,
	}, nil
}

type Quic struct {
	w         *MaskConnWrapper
	serverTLS *tls.Config
	clientTLS *tls.Config

	config *quic.Config
}

func NewQUIC(key string, options map[string]string, w *MaskConnWrapper) (Transfer, error) {
	q := Quic{
		w: w,
	}
	var err error
	q.serverTLS, err = generateTLSFromKey(key, true)
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %w", err)
	}
	q.clientTLS, err = generateTLSFromKey(key, false)
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %w", err)
	}
	q.config = quicConfig()
	return &q, nil
}

func (q *Quic) Dial(addr string) (MultiplexingClientConn, error) {
	uc, uaddr, err := listenUDPAndWrap(addr, false, q.w)
	if err != nil {
		return nil, err
	}
	sess, err := quic.Dial(uc, uaddr, addr, q.clientTLS, q.config)
	if err != nil {
		return nil, err
	}
	conn, err := newQuicClientConn(sess)
	if err != nil {
		sess.Close()
		return nil, err
	}
	return conn, nil
}

func (q *Quic) Listen(addr string) (MultiplexingListener, error) {
	uc, _, err := listenUDPAndWrap(addr, true, q.w)
	if err != nil {
		return nil, err
	}
	l, err := quic.Listen(uc, q.serverTLS, q.config)
	if err != nil {
		return nil, err
	}
	return quicListener{
		Listener: l,
	}, nil
}

type Tcp struct {
	w         *MaskConnWrapper
	serverTLS *tls.Config
	clientTLS *tls.Config

	smuxConfig *smux.Config
}

func NewTcp(key string, options map[string]string, w *MaskConnWrapper) (Transfer, error) {
	t := Tcp{
		w: w,
	}
	var err error
	t.serverTLS, err = generateTLSFromKey(key, true)
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %w", err)
	}
	t.clientTLS, err = generateTLSFromKey(key, false)
	if err != nil {
		return nil, fmt.Errorf("generate tls config failed: %w", err)
	}
	t.smuxConfig = smuxConfig()
	return &t, nil
}

func (t *Tcp) Dial(addr string) (MultiplexingClientConn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if t.w != nil {
		conn = t.w.WrapConn(conn)
	}
	conn = tls.Client(conn, t.clientTLS)
	c, err := newSmuxClientConn(conn, t.smuxConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (t *Tcp) Listen(addr string) (MultiplexingListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	w := listenerWrapper{Listener: l}
	if t.w != nil {
		w.Wrappers = append(w.Wrappers, t.w.WrapConn)
	}
	l = tls.NewListener(w, t.serverTLS)
	return smuxListener{config: t.smuxConfig, Listener: l}, nil
}

type quicConn struct {
	quic.Session

	streamCount int32
}

type quicStream struct {
	c *quicConn
	quic.Stream
}

func (q quicStream) LocalAddr() net.Addr {
	return q.c.LocalAddr()
}

func (q quicStream) RemoteAddr() net.Addr {
	return q.c.RemoteAddr()
}

func (q quicStream) Close() error {
	atomic.AddInt32(&q.c.streamCount, -1)
	err := q.Stream.Close()
	return err
}

func newQuicStream(c *quicConn, s quic.Stream) quicStream {
	return quicStream{
		c:      c,
		Stream: s,
	}
}

func newQuicServerConn(sess quic.Session) (MultiplexingServerConn, error) {
	return &quicConn{
		Session: sess,
	}, nil
}

func newQuicClientConn(sess quic.Session) (MultiplexingClientConn, error) {
	return &quicConn{
		Session: sess,
	}, nil
}

func (c *quicConn) NumStreams() int {
	return int(atomic.LoadInt32(&c.streamCount))
}

func (c *quicConn) OpenStream() (net.Conn, error) {
	s, err := c.Session.OpenStream()
	if err != nil {
		if s == nil {
			return nil, err
		}
	}
	return newQuicStream(c, s), nil
}

func (c *quicConn) AcceptStream() (net.Conn, error) {
	s, err := c.Session.AcceptStream(context.Background())
	if err != nil {
		if s == nil {
			return nil, err
		}
	}
	return newQuicStream(c, s), nil
}

type quicListener struct {
	quic.Listener
}

func (s quicListener) Accept() (MultiplexingServerConn, error) {
	conn, err := s.Listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	sconn, err := newQuicServerConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sconn, nil
}

type smuxConn struct {
	*smux.Session
}

func newSmuxServerConn(conn net.Conn, config *smux.Config) (MultiplexingServerConn, error) {
	sess, err := smux.Server(conn, config)
	if err != nil {
		return nil, err
	}
	return smuxConn{
		sess,
	}, nil
}

func newSmuxClientConn(conn net.Conn, config *smux.Config) (MultiplexingClientConn, error) {
	sess, err := smux.Client(conn, config)
	if err != nil {
		return nil, err
	}
	return smuxConn{
		sess,
	}, nil
}

func (c smuxConn) OpenStream() (net.Conn, error) {
	return c.Session.OpenStream()
}

func (c smuxConn) AcceptStream() (net.Conn, error) {
	return c.Session.AcceptStream()
}

type smuxListener struct {
	net.Listener

	config *smux.Config
}

func (s smuxListener) Accept() (MultiplexingServerConn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sconn, err := newSmuxServerConn(conn, s.config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sconn, nil
}

type connWrappers []func(conn net.Conn) net.Conn

type listenerWrapper struct {
	net.Listener

	Wrappers connWrappers
}

func (s connWrappers) Wrap(conn net.Conn) net.Conn {
	for _, w := range s {
		conn = w(conn)
	}
	return conn
}

func (s listenerWrapper) Accept() (net.Conn, error) {
	conn, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return s.Wrappers.Wrap(conn), nil
}

func generateTLSFromKey(keyStr string, isServer bool) (*tls.Config, error) {
	var err error
	var (
		caKey  *rsa.PrivateKey
		caCert *x509.Certificate
	)
	{
		_, caKey, err = generateCAKey(keyStr, 2048)
		if err != nil {
			return nil, err
		}

		template := x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		caCert, err = x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
	}
	var (
		selfKey     *rsa.PrivateKey
		selfCertDER []byte
		serverName  = "quic-tunnel"
	)
	{
		selfKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		}
		if isServer {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.DNSNames = []string{"quic-tunnel"}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		selfCertDER, err = x509.CreateCertificate(rand.Reader, &template, caCert, &selfKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(selfKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfCertDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	if isServer {
		return &tls.Config{
			NextProtos:   []string{"quic-tunnel"},
			Certificates: []tls.Certificate{tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
		}, nil
	}
	return &tls.Config{
		ServerName:   serverName,
		NextProtos:   []string{"quic-tunnel"},
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
	}, nil
}
