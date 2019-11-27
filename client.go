package shadowsocksr

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/10bits/shadowsocksR/obfs"
	"github.com/10bits/shadowsocksR/protocol"
	"github.com/10bits/shadowsocksR/ssr"
)

func NewSSRClient(u *url.URL) (*SSTCPConn, error) {
	query := u.Query()
	encryptMethod := query.Get("encrypt-method")
	encryptKey := query.Get("encrypt-key")
	cipher, err := NewStreamCipher(encryptMethod, encryptKey)
	if err != nil {
		return nil, err
	}
	_obfs := obfs.NewObfs(query.Get("obfs"))
	if _obfs == nil {
		return nil, errors.New("not support ssr obfs:", query.Get("obfs"))
	}
	_protocol := protocol.NewProtocol(query.Get("protocol"))
	if _protocol == nil {
		return nil, errors.New("not support ssr protocol:", query.Get("protocol"))
	}
	dialer := net.Dialer{
		Timeout:   time.Millisecond * 500,
		DualStack: true,
	}
	conn, err := dialer.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}

	ssconn := NewSSTCPConn(conn, cipher)
	if ssconn.Conn == nil || ssconn.RemoteAddr() == nil {
		return nil, errors.New("nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssconn.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])
	ssconn.IObfs = _obfs
	obfsServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("obfs-param"),
	}
	ssconn.IObfs.SetServerInfo(obfsServerInfo)
	ssconn.IProtocol = _protocol
	protocolServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  query.Get("protocol-param"),
	}
	ssconn.IProtocol.SetServerInfo(protocolServerInfo)
	return ssconn, nil
}
