package gelf

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

type TLSWriter struct {
	GelfWriter
	mu             sync.Mutex
	MaxReconnect   int
	ReconnectDelay time.Duration
	TlsConfig      *tls.Config
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

	return w, nil
}

// WriteMessage sends the specified message to the GELF server
// specified in the call to New().  It assumes all the fields are
// filled out appropriately.  In general, clients will want to use
// Write, rather than WriteMessage.
func (w *TLSWriter) WriteMessage(m *Message) (err error) {
	buf := newBuffer()
	defer bufPool.Put(buf)
	messageBytes, err := m.toBytes(buf)
	if err != nil {
		return err
	}

	messageBytes = append(messageBytes, 0)

	n, err := w.writeToSocketWithReconnectAttempts(messageBytes)
	if err != nil {
		return err
	}
	if n != len(messageBytes) {
		return fmt.Errorf("bad write (%d/%d)", n, len(messageBytes))
	}

	return nil
}

func (w *TLSWriter) Write(p []byte) (n int, err error) {
	file, line := getCallerIgnoringLogMulti(1)

	m := constructMessage(p, w.hostname, w.Facility, file, line)
	if err = w.WriteMessage(m); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (w *TLSWriter) writeToSocketWithReconnectAttempts(zBytes []byte) (n int, err error) {
	var i int
	w.mu.Lock()
	for i = 0; i <= w.MaxReconnect; i++ {
		if i > 0 {
			time.Sleep(w.ReconnectDelay)
		}
		if w.conn == nil {
			w.conn, err = tls.Dial("tcp", w.addr, w.TlsConfig)
			if err != nil {
				err = fmt.Errorf("failed to connect: %v", err)
			}
		}
		if w.conn != nil {
			n, err = w.conn.Write(zBytes)
			if err != nil {
				err = fmt.Errorf("failed to write: %v", err)
				continue
			} else {
				break
			}
		}
	}

	w.mu.Unlock()
	if err != nil {
		return 0, err
	}

	return n, nil
}
