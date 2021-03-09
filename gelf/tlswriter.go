package gelf

import (
	"crypto/tls"
	"fmt"
	"os"
)

type TLSWriter struct {
	TCPWriter
	TlsConfig *tls.Config
}

func NewTLSWriter(addr string, tlsConfig *tls.Config) (*TLSWriter, error) {
	w := new(TLSWriter)
	w.MaxReconnect = DefaultMaxReconnect
	w.ReconnectDelay = DefaultReconnectDelay
	w.proto = "tls"
	w.addr = addr
	w.TlsConfig = tlsConfig
	var err error
	if w.hostname, err = os.Hostname(); err != nil {
		return nil, err
	}

	go func() {
		var err error
		if w.conn, err = tls.Dial("tcp", addr, w.TlsConfig); err != nil {
			fmt.Printf("failed to conenct gelf: %s", err.Error())
		}
	}()

	return w, nil
}
