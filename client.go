package shadowsocksr

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"shadowsocksr/obfs"
	"shadowsocksr/protocol"
	"shadowsocksr/ssr"
	"shadowsocksr/tools/socks"
	"strconv"
	"strings"
	"time"
)

type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

type SSRServer struct {
	SSInfo
	Address string
	Type    string
	Remarks string
	Group   string
}

func Base64Decode(s string) string {
	var b []byte
	b, _ = base64.RawURLEncoding.DecodeString(s)
	return string(b)
}

func NewSSRServer(ssr_url string, encode bool) *SSRServer {
	if !strings.HasPrefix(ssr_url, "ssr://") {
		return nil
	}
	ssr_url = strings.TrimLeft(ssr_url, "ssr://")
	if encode {
		ssr_url = Base64Decode(ssr_url)
	}
	v := strings.Split(ssr_url, ":")
	var host, port, protocol, encrypt, obfs string
	if len(v) < 2 {
		return nil
	}
	host, port = v[0], v[1]
	if len(v) > 2 {
		protocol = v[2]
		if len(v) > 3 {
			encrypt = v[3]
			if len(v) > 4 {
				obfs = v[4]
			}
		}
	}
	var password, obfsparam, protocolparam, remarks, group string
	if len(v) >= 5 {
		u, err := url.Parse("ssr://" + v[5])
		if err == nil {
			if encode {
				password = Base64Decode(u.Host)
				obfsparam = Base64Decode(u.Query().Get("obfsparam"))
				protocolparam = Base64Decode(u.Query().Get("protocolparam"))
				remarks = Base64Decode(u.Query().Get("remarks"))
				group = Base64Decode(u.Query().Get("group"))
			} else {
				password = u.Host
				obfsparam = u.Query().Get("obfsparam")
				protocolparam = u.Query().Get("protocolparam")
				remarks = u.Query().Get("remarks")
				group = u.Query().Get("group")
			}
		}
	}
	return &SSRServer{
		Address: host + ":" + port,
		Type:    "ssr",
		Remarks: remarks,
		Group:   group,
		SSInfo: SSInfo{
			EncryptMethod:   encrypt,
			EncryptPassword: password,
			SSRInfo: SSRInfo{
				Protocol:      protocol,
				ProtocolParam: protocolparam,
				Obfs:          obfs,
				ObfsParam:     obfsparam,
			},
		},
	}
}

type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}

func (bi *BackendInfo) DialSSRConn(rawaddr socks.Addr) (net.Conn, error) {
	u := &url.URL{
		Scheme: bi.Type,
		Host:   bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", bi.EncryptMethod)
	v.Set("encrypt-key", bi.EncryptPassword)
	v.Set("obfs", bi.Obfs)
	v.Set("obfs-param", bi.ObfsParam)
	v.Set("protocol", bi.Protocol)
	v.Set("protocol-param", bi.ProtocolParam)
	u.RawQuery = v.Encode()

	ssrconn, err := NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if bi.ObfsData == nil {
		bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(bi.ObfsData)

	if bi.ProtocolData == nil {
		bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(bi.ProtocolData)

	if _, err := ssrconn.Write(rawaddr); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

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
		return nil, errors.New("not support ssr obfs:" + query.Get("obfs"))
	}
	_protocol := protocol.NewProtocol(query.Get("protocol"))
	if _protocol == nil {
		return nil, errors.New("not support ssr protocol:" + query.Get("protocol"))
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
