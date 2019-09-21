package main

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompress(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	m := NewMaskConnWrapper("test")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn = m.WrapConn(conn)
		conn, err = newCompressConn(conn, "zlib")
		if err != nil {
			t.Fatal(err)
		}

		err = ProtocolWrite(conn, HandshakeRequest{Addr: l.Addr().String()})
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(conn)
		var resp HandshakeResponse
		err = ProtocolRead(br, &resp)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Msg != l.Addr().String() {
			t.Fatal("mismatched")
		}
		conn.Close()
	}()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn = m.WrapConn(conn)
	conn, err = newCompressConn(conn, "zlib")
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)

	var h HandshakeRequest
	err = ProtocolRead(br, &h)
	if err != nil {
		t.Fatal(err)
	}

	err = ProtocolWrite(conn, HandshakeResponse{Msg: h.Addr})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	wg.Wait()
}

func TestKeyReader(t *testing.T) {
	r := newCycledKeyReader(hashKeyForRandReader("test"))
	_, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCAKey(t *testing.T) {
	var prev string
	for i := 0; i < 10; i++ {
		key, _, err := generateCAKey("test", 2048)
		if err != nil {
			t.Fatal()
		}
		if prev != "" && prev != key {
			t.Fatal("different key generated")
		}
		prev = key
	}
}

func TestTLS(t *testing.T) {
	serverTLS, err := generateTLSFromKey("test", true)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := generateTLSFromKey("test", false)
	if err != nil {
		t.Fatal(err)
	}
	{
		verifyOpts := x509.VerifyOptions{
			Roots:       clientTLS.RootCAs,
			DNSName:     clientTLS.ServerName,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		cert, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		_, err = cert.Verify(verifyOpts)
		if err != nil {
			t.Fatal(err)
		}
	}
	{
		verifyOpts := x509.VerifyOptions{
			Roots:       serverTLS.ClientCAs,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		cert, err := x509.ParseCertificate(clientTLS.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		_, err = cert.Verify(verifyOpts)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMask(t *testing.T) {
	w := NewMaskConnWrapper("Test")
	buf := []byte("test")
	w.Mask(buf)
	w.Unmask(buf)

	if !bytes.Equal(buf, []byte("test")) {
		t.Fatal("unmask failed")
	}
}

func TestHttpMatcher(t *testing.T) {
	for _, m := range httpMethods {
		t.Log(protocolHttpMatcher(strings.NewReader(m)))
	}
}
