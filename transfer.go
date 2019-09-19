package main

import (
	"crypto/sha256"
	"net"

	"github.com/xtaci/kcp-go"
)

type TransferCreator func(key string) (Transfer, error)

var transfers = map[string]TransferCreator{
	"kcp": NewKcp,
	"raw": NewRaw,
}

type Transfer interface {
	Dial(addr string) (net.Conn, error)
	Listen(addr string) (net.Listener, error)
}

type Kcp struct {
	crypt kcp.BlockCrypt
}

const (
	kcpDataShards   = 3
	kcpParityShards = 3
)

func newKcpCrypt(key string) (kcp.BlockCrypt, error) {
	h := sha256.New()
	h.Write([]byte(key))
	k := h.Sum(nil)
	return kcp.NewAESBlockCrypt(k)
}

func NewKcp(key string) (Transfer, error) {
	crypt, err := newKcpCrypt(key)
	if err != nil {
		return nil, err
	}
	return &Kcp{
		crypt: crypt,
	}, nil
}

func (k *Kcp) initConn(u *kcp.UDPSession) {
	u.SetNoDelay(1, 10, 2, 1)
	u.SetACKNoDelay(true)
}

func (k *Kcp) Dial(addr string) (net.Conn, error) {
	u, err := kcp.DialWithOptions(addr, k.crypt, kcpDataShards, kcpParityShards)
	if err != nil {
		return nil, err
	}
	k.initConn(u)
	return u, nil
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

func (k *Kcp) Listen(addr string) (net.Listener, error) {
	l, err := kcp.ListenWithOptions(addr, k.crypt, kcpDataShards, kcpParityShards)
	if err != nil {
		return nil, err
	}
	return kcpListener{k: k, Listener: l}, nil
}

type Raw struct{}

func NewRaw(key string) (Transfer, error) {
	return Raw{}, nil
}

func (Raw) Dial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (Raw) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
