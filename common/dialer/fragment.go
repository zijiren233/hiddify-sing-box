package dialer

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

type TLSFragment struct {
	Enabled  bool
	SizeMin  int
	SizeMax  int
	SleepMin int
	SleepMax int
}

type fragmentConn struct {
	dialer      net.Dialer
	fragment    TLSFragment
	network     string
	destination M.Socksaddr
	conn        net.Conn
	err         error
}

func (c *fragmentConn) Read(b []byte) (n int, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}

func (c *fragmentConn) Write(b []byte) (n int, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	// Do not fragment if it's not a TLS clientHello packet
	if len(b) < 7 || b[0] != 22 {
		return c.conn.Write(b)
	}

	clientHelloLen := int(binary.BigEndian.Uint16(b[3:5]))
	clientHelloData := b[5:]

	for fragmentStart := 0; fragmentStart < clientHelloLen; {
		fragmentEnd := fragmentStart + option.RandBetween(c.fragment.SizeMin, c.fragment.SizeMax)
		if fragmentEnd > clientHelloLen {
			fragmentEnd = clientHelloLen
		}

		header := make([]byte, 5)
		header[0] = b[0]
		binary.BigEndian.PutUint16(header[1:], binary.BigEndian.Uint16(b[1:3]))
		binary.BigEndian.PutUint16(header[3:], uint16(fragmentEnd-fragmentStart))
		payload := append(header, clientHelloData[fragmentStart:fragmentEnd]...)

		_, err := c.conn.Write(payload)
		if err != nil {
			c.err = err
			return 0, c.err
		}

		if c.fragment.SleepMax != 0 {
			time.Sleep(time.Duration(option.RandBetween(c.fragment.SleepMin, c.fragment.SleepMax)) * time.Millisecond)
		}

		fragmentStart = fragmentEnd
	}

	return len(b), nil
}

func (c *fragmentConn) Close() error {
	return common.Close(c.conn)
}

func (c *fragmentConn) LocalAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.LocalAddr()
}

func (c *fragmentConn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return M.Socksaddr{}
	}
	return c.conn.RemoteAddr()
}

func (c *fragmentConn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetDeadline(t)
}

func (c *fragmentConn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetReadDeadline(t)
}

func (c *fragmentConn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return os.ErrInvalid
	}
	return c.conn.SetWriteDeadline(t)
}

func (c *fragmentConn) Upstream() any {
	return c.conn
}

func (c *fragmentConn) ReaderReplaceable() bool {
	return c.conn != nil
}

func (c *fragmentConn) WriterReplaceable() bool {
	return c.conn != nil
}

func (c *fragmentConn) LazyHeadroom() bool {
	return c.conn == nil
}

func (c *fragmentConn) NeedHandshake() bool {
	return c.conn == nil
}

func (c *fragmentConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.conn == nil {
		return 0, c.err
	}
	return bufio.Copy(w, c.conn)
}
