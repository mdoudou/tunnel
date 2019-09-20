package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cosiner/golog"
)

type Server struct {
	config ServerConfig
	l      MultiplexingListener

	closed uint32
	connWg sync.WaitGroup
	connMu sync.RWMutex
	conns  map[MultiplexingServerConn]struct{}
}

func NewServer(config ServerConfig) (*Server, error) {
	s := Server{
		config: config,
		conns:  make(map[MultiplexingServerConn]struct{}),
	}
	var err error

	transferType, options := parseTransfer(s.config.Transfer)
	tc, ok := transfers[transferType]
	if !ok {
		return nil, fmt.Errorf("unsupported transfer protcol: %s", s.config.Transfer)
	}
	transfer, err := tc(s.config.Key, options, NewMaskConnWrapper(s.config.Key))
	if err != nil {
		return nil, fmt.Errorf("create transfer failed: %w", err)
	}
	s.l, err = transfer.Listen(s.config.Listen)
	if err != nil {
		return nil, fmt.Errorf("create kcp server listener failed: %s, %w", s.config.Listen, err)
	}
	return &s, nil
}

func (s *Server) closeAllConns() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	for conn := range s.conns {
		conn.Close()
	}
}

func (s *Server) Close() {
	if !atomic.CompareAndSwapUint32(&s.closed, 0, 1) {
		return
	}
	s.l.Close()
	s.closeAllConns()
	s.connWg.Wait()
}

func (s *Server) Run() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Temporary() {
					continue
				}
			}

			if !ignoreError(err) {
				golog.WithFields("error", err.Error()).Error("server accept conn failed")
			}
			return
		}

		conn = &closeOnceServerConn{MultiplexingServerConn: conn}
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()
		s.connWg.Add(1)
		go func() {
			defer func() {
				s.connMu.Lock()
				delete(s.conns, conn)
				s.connMu.Unlock()
				s.connWg.Done()
			}()

			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(conn MultiplexingServerConn) {
	defer conn.Close()
	golog.WithFields("addr", conn.RemoteAddr()).Info("new connection")

	var wg sync.WaitGroup
	for {
		stream, err := conn.AcceptStream()
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Temporary() {
					continue
				}
			}

			if !ignoreError(err) {
				golog.WithFields("error", err.Error()).Error("accept stream failed")
			}
			break
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			s.handleStream(stream)
		}()
	}
	wg.Wait()
}

func (s *Server) handleStream(clientConn net.Conn) {
	var proxyStarted bool
	defer func() {
		if !proxyStarted {
			clientConn.Close()
		}
	}()

	br := bufio.NewReader(clientConn)
	clientConn = buffReadConn{clientConn, br}

	var handshakeReq HandshakeRequest
	err := ProtocolRead(br, &handshakeReq)
	if err != nil {
		golog.WithFields("error", err.Error()).Error("read handhsake request failed")
		return
	}
	golog.WithFields("addr", handshakeReq.Addr).Debug("proxy")
	proxyConn, err := net.DialTimeout("tcp", handshakeReq.Addr, time.Second*3)
	if err != nil {
		golog.WithFields("error", err.Error(), "addr", handshakeReq.Addr).Error("dial addr failed")

		err = ProtocolWrite(clientConn, HandshakeResponse{
			Status: HandshakeStatusFailed,
			Msg:    "dial destination failed",
		})
		if err != nil {
			golog.WithFields("error", err.Error()).Error("write handshake response failed")
		}
		return
	}
	err = ProtocolWrite(clientConn, HandshakeResponse{
		Status: HandshakeStatusOK,
	})
	if err != nil {
		golog.WithFields("error", err.Error()).Error("write handshake response failed")
		proxyConn.Close()
		return
	}

	{
		cConn, err := newCompressConn(clientConn, s.config.Compress)
		if err != nil {
			clientConn.Close()
			golog.WithFields("error", err.Error()).Errorf("create compress conn failed")
			return
		}
		clientConn = cConn
	}
	proxyStarted = true
	pipeConns(clientConn, proxyConn)
}
