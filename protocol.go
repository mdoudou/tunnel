package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type HandshakeRequest struct {
	Addr string
}

const (
	HandshakeStatusOK     = 0
	HandshakeStatusFailed = 1
)

type HandshakeResponse struct {
	Status uint
	Msg    string
}

func varintSize(u uint64) int {
	var c int
	for {
		c++
		u >>= 7
		if u == 0 {
			break
		}
	}
	return c
}

func ProtocolWrite(conn io.ReadWriteCloser, v interface{}) error {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(v)
	if err != nil {
		return err
	}

	length := uint64(buf.Len())
	lengthBuf := make([]byte, varintSize(length))

	binary.PutUvarint(lengthBuf, length)
	_, err = conn.Write(lengthBuf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf.Bytes())
	return err
}

func ProtocolRead(br *bufio.Reader, ptr interface{}) error {
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return err
	}
	lr := io.LimitedReader{R: br, N: int64(length)}
	err = json.NewDecoder(&lr).Decode(ptr)
	if err != nil {
		return err
	}
	if lr.N > 0 {
		return fmt.Errorf("invalid handshake json data")
	}
	return nil
}
