package main

import (
	"io"
	"log"
	"net"
	"shadowsocksr"
	ssr "shadowsocksr"
	"shadowsocksr/tools/socks"
	"time"

	"github.com/txthinking/socks5"
)

var bi *ssr.BackendInfo

func init() {
	ssr_url := "ssr://UE5FVU1PTk9VTFRSQU1JQ1JPU0NPUElDU0lMSUNPVk9MQ0FOT0NPTklPU0lTLnNhYzkwOTBzYWMuZ3E6MzE1NjM6YXV0aF9hZXMxMjhfbWQ1OmNoYWNoYTIwLWlldGY6dGxzMS4yX3RpY2tldF9hdXRoOlZqRm5VMkpoUzJ0NlFnLz9vYmZzcGFyYW09VUU1RlZVMVBUazlWVEZSU1FVMUpRMUpQVTBOUFVFbERVMGxNU1VOUFZrOU1RMEZPVDBOUFRrbFBVMGxUTG5OaFl6a3dPVEJ6WVdNdVozRSZwcm90b3BhcmFtPSZyZW1hcmtzPTVZV042TFM1TlEmZ3JvdXA9"
	server := ssr.NewSSRServer(ssr_url, true)
	if server != nil && server.BackendInfo != nil {
		bi = server.BackendInfo
	}
}

type handle struct{}

func (this *handle) replyFailed(r *socks5.Request, w io.Writer) error {
	var p *socks5.Reply
	if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	} else {
		p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
	}
	if _, err := p.WriteTo(w); err != nil {
		return err
	}
	return nil
}

func (this *handle) replySuccess(a byte, addr []byte, port []byte, w io.Writer) error {
	p := socks5.NewReply(socks5.RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		return err
	}
	return nil
}

func (this *handle) TCPHandle(s *socks5.Server, localConn *net.TCPConn, req *socks5.Request) error {
	if bi == nil {
		return this.replyFailed(req, localConn)
	}
	rawaddr := socks.ParseAddr(req.Address())
	tmp, err := bi.DialSSRConn(rawaddr)
	if err != nil {
		return this.replyFailed(req, localConn)
	}
	remoteConn := tmp.(*shadowsocksr.SSTCPConn)
	a, addr, port, err := socks5.ParseAddress(remoteConn.LocalAddr().String())
	if err != nil {
		return this.replyFailed(req, localConn)
	}
	err = this.replySuccess(a, addr, port, localConn)
	if err != nil {
		return err
	}
	go PipeThenClose(localConn, remoteConn, nil)
	PipeThenClose(remoteConn, localConn, nil)
	return nil
}
func (this *handle) UDPHandle(s *socks5.Server, addr *net.UDPAddr, data *socks5.Datagram) error {
	return nil
}

func main() {
	s, err := socks5.NewClassicServer(":8080", "", "", "", 3000, 3000)
	if err != nil {
		log.Fatal(err)
	}
	s.ListenAndServe(&handle{})
}

var readTimeout = time.Second * 10

func SetReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}

// PipeThenClose copies data from src to dst, closes dst when done.
func PipeThenClose(src, dst net.Conn, addTraffic func(int)) {
	defer dst.Close()
	buf := leakyBuf.Get()
	defer leakyBuf.Put(buf)
	for {
		SetReadTimeout(src)
		n, err := src.Read(buf)
		if addTraffic != nil {
			addTraffic(n)
		}
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
	return
}

type LeakyBuf struct {
	bufSize  int // size of each buffer
	freeList chan []byte
}

const leakyBufSize = 4108 // data.len(2) + hmacsha1(10) + data(4096)
const maxNBuf = 2048

var leakyBuf = NewLeakyBuf(maxNBuf, leakyBufSize)

// NewLeakyBuf creates a leaky buffer which can hold at most n buffer, each
// with bufSize bytes.
func NewLeakyBuf(n, bufSize int) *LeakyBuf {
	return &LeakyBuf{
		bufSize:  bufSize,
		freeList: make(chan []byte, n),
	}
}

// Get returns a buffer from the leaky buffer or create a new buffer.
func (lb *LeakyBuf) Get() (b []byte) {
	select {
	case b = <-lb.freeList:
	default:
		b = make([]byte, lb.bufSize)
	}
	return
}

// Put add the buffer into the free buffer pool for reuse. Panic if the buffer
// size is not the same with the leaky buffer's. This is intended to expose
// error usage of leaky buffer.
func (lb *LeakyBuf) Put(b []byte) {
	if len(b) != lb.bufSize {
		panic("invalid buffer size that's put into leaky buffer")
	}
	select {
	case lb.freeList <- b:
	default:
	}
	return
}
