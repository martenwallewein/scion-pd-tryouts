package socket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/martenwallewein/scion-pathdiscovery/packets"
	"github.com/martenwallewein/scion-pathdiscovery/pathselection"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/netsec-ethz/scion-apps/pkg/quicutil"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/path"
	log "github.com/sirupsen/logrus"
	"inet.af/netaddr"
)

type QUICReliableConn struct {
	internalConn quic.Stream
	session      quic.Session
	listener     quic.Listener
	path         *snet.Path
	peer         string
	remote       *snet.UDPAddr
	metrics      packets.PathMetrics
	local        *snet.UDPAddr
}

// This simply wraps conn.Read and will later collect metrics
func (qc *QUICReliableConn) Read(b []byte) (int, error) {
	n, err := qc.internalConn.Read(b)
	if err != nil {
		return n, err
	}
	qc.metrics.ReadBytes += int64(n)
	qc.metrics.ReadPackets++
	return n, err
}

// This simply wraps conn.Write and will later collect metrics
func (qc *QUICReliableConn) Write(b []byte) (int, error) {
	n, err := qc.internalConn.Write(b)
	qc.metrics.WrittenBytes += int64(n)
	qc.metrics.WrittenPackets++
	if err != nil {
		return n, err
	}
	return n, err
}

func (qc *QUICReliableConn) Close() error {
	if qc.internalConn == nil {
		return nil
	}
	err := qc.internalConn.Close()
	if err != nil {
		return err
	}

	if qc.session != nil {
		err := qc.session.CloseWithError(quic.ApplicationErrorCode(0), "done")
		if err != nil {
			return err
		}
	}

	if qc.listener != nil {
		err := qc.listener.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (qc *QUICReliableConn) GetMetrics() *packets.PathMetrics {
	return &qc.metrics
}

func (qc *QUICReliableConn) GetPath() *snet.Path {
	return qc.path
}

func (qc *QUICReliableConn) SetPath(path *snet.Path) error {
	qc.path = path
	return nil
}

func (qc *QUICReliableConn) GetRemote() *snet.UDPAddr {
	return qc.remote
}

func (qc *QUICReliableConn) LocalAddr() net.Addr {
	return qc.local
}

func (qc *QUICReliableConn) RemoteAddr() net.Addr {
	return qc.remote
}

func (qc *QUICReliableConn) SetDeadline(t time.Time) error {
	return qc.internalConn.SetDeadline(t)
}

func (qc *QUICReliableConn) SetReadDeadline(t time.Time) error {
	return qc.internalConn.SetReadDeadline(t)
}

func (qc *QUICReliableConn) SetWriteDeadline(t time.Time) error {
	return qc.internalConn.SetWriteDeadline(t)
}

var _ packets.UDPConn = (*QUICReliableConn)(nil)

var _ UnderlaySocket = (*QUICSocket)(nil)

type RemotePeer struct {
	Stream quic.Stream
	Remote *snet.UDPAddr
}

type QUICSocket struct {
	listener       quic.Listener
	local          string
	localAddr      *snet.UDPAddr
	conns          []*QUICReliableConn
	Stream         quic.Stream
	ConnectedPeers []RemotePeer
}

func NewQUICSocket(local string) *QUICSocket {
	s := QUICSocket{
		local:          local,
		conns:          make([]*QUICReliableConn, 0),
		ConnectedPeers: make([]RemotePeer, 0),
	}

	gob.Register(path.Path{})

	return &s
}

func (s *QUICSocket) Listen() error {
	lAddr, err := snet.ParseUDPAddr(s.local)
	if err != nil {
		return err
	}

	ipP := pan.IPPortValue{}
	shortAddr := fmt.Sprintf("%s:%d", lAddr.Host.IP, lAddr.Host.Port)
	ipP.Set(shortAddr)
	tlsCfg := &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		NextProtos:   []string{"scion-filetransfer"},
	}
	listener, err := pan.ListenQUIC(context.Background(), ipP.Get(), nil, tlsCfg, nil)
	if err != nil {
		return err
	}

	s.localAddr = lAddr
	s.listener = listener
	return err
}

// TODO: This needs to be done for each incoming conn
func (s *QUICSocket) WaitForIncomingConn(lAddr snet.UDPAddr) (packets.UDPConn, error) {
	ipP := pan.IPPortValue{}
	shortAddr := fmt.Sprintf("%s:%d", lAddr.Host.IP, lAddr.Host.Port)
	ipP.Set(shortAddr)
	tlsCfg := &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		NextProtos:   []string{"scion-filetransfer"},
	}
	listener, err := pan.ListenQUIC(context.Background(), ipP.Get(), nil, tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	log.Warn("PAN LISTEN NEW")

	session, err := listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}

	log.Warn("PAN SESSION NEW")

	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}

	log.Warn("PAN STREAM NEW")

	bts := make([]byte, packets.PACKET_SIZE)
	_, err = stream.Read(bts)
	if err != nil {
		return nil, err
	}

	p := DialPacketQuic{}
	network := bytes.NewBuffer(bts) // Stand-in for a network connection
	dec := gob.NewDecoder(network)
	err = dec.Decode(&p)
	if err != nil {
		return nil, err
	}

	log.Warn("GOt dial packet ", p)

	// Send reply
	ret := DialPacketQuic{}
	ret.Addr = lAddr
	ret.Path = p.Path

	var network2 bytes.Buffer
	enc := gob.NewEncoder(&network2)

	err = enc.Encode(ret)
	stream.Write(network2.Bytes())
	log.Warn("Wrote response")

	quicConn := &QUICReliableConn{
		internalConn: stream,
		session:      session,
		listener:     listener,
		path:         &p.Path,
		remote:       &p.Addr,
		metrics:      *packets.NewPathMetrics(1000 * time.Millisecond),
		local:        &lAddr,
	}

	log.Errorf("%p", quicConn)

	s.conns = append(s.conns, quicConn)

	return quicConn, nil
}

// TODO: This needs to be done for each incoming conn
func (s *QUICSocket) NextIncomingConn() (packets.UDPConn, error) {
	lAddr := s.localAddr.Copy()
	lAddr.Host.Port = lAddr.Host.Port + 14*(len(s.conns)+1)
	ipP := pan.IPPortValue{}
	shortAddr := fmt.Sprintf("%s:%d", lAddr.Host.IP, lAddr.Host.Port)
	ipP.Set(shortAddr)
	tlsCfg := &tls.Config{
		Certificates: quicutil.MustGenerateSelfSignedCert(),
		NextProtos:   []string{"scion-filetransfer"},
	}
	listener, err := pan.ListenQUIC(context.Background(), ipP.Get(), nil, tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	session, err := listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}

	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}

	bts := make([]byte, packets.PACKET_SIZE)
	_, err = stream.Read(bts)
	if err != nil {
		return nil, err
	}

	p := DialPacketQuic{}
	network := bytes.NewBuffer(bts) // Stand-in for a network connection
	dec := gob.NewDecoder(network)
	err = dec.Decode(&p)
	if err != nil {
		return nil, err
	}

	quicConn := &QUICReliableConn{
		internalConn: stream,
		session:      session,
		listener:     listener,
		path:         &p.Path,
		remote:       &p.Addr,
		metrics:      *packets.NewPathMetrics(1000 * time.Millisecond),
		local:        s.localAddr,
	}

	return quicConn, nil
}

func (s *QUICSocket) WaitForDialIn() (*snet.UDPAddr, error) {
	session, err := s.listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}

	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}

	log.Debugf("Got base conn")
	s.Stream = stream

	bts := make([]byte, packets.PACKET_SIZE)
	_, err = stream.Read(bts)
	if err != nil {
		return nil, err
	}

	p := HandshakePacketQuic{}
	network := bytes.NewBuffer(bts) // Stand-in for a network connection
	dec := gob.NewDecoder(network)
	err = dec.Decode(&p)
	if err != nil {
		return nil, err
	}

	log.Debug(p.Ports)

	remotePeer := RemotePeer{
		Stream: stream,
		Remote: &p.Addr,
	}
	s.ConnectedPeers = append(s.ConnectedPeers, remotePeer)

	var wg sync.WaitGroup
	ret := HandshakePacketQuic{}
	ret.Ports = make([]int, 0)
	for i := 0; i < p.NumPorts; i++ {
		wg.Add(1)
		ret.Ports = append(ret.Ports, s.localAddr.Host.Port+11*(i+1)+52*len(s.ConnectedPeers))
		go func(i int) {
			l := s.localAddr.Copy()
			l.Host.Port = l.Host.Port + 11*(i+1) + 52*len(s.ConnectedPeers)
			// l.Host.Port = p.Ports[i+1]
			log.Warn("Listen add on ", l.String())
			// Waitgroup here before sending back response
			_, err := s.WaitForIncomingConn(*l)
			if err != nil {
				log.Error(err)
				return
			}
			log.Debugf("Dialed In %d of %d on %s from remote %s", i+1, p.NumPorts, l.String(), p.Addr.String())
			wg.Done()
		}(i)
	}

	// Send reply

	ret.Addr = *s.localAddr
	ret.NumPorts = p.NumPorts
	// ret.Ports = p.Ports

	var network2 bytes.Buffer
	enc := gob.NewEncoder(&network2)

	err = enc.Encode(ret)
	stream.Write(network2.Bytes())
	log.Warn("Wrote response")
	// Wait for responses
	wg.Wait()
	addr := p.Addr
	return &addr, nil
}

func (s *QUICSocket) DialAll(remote snet.UDPAddr, path []pathselection.PathQuality, options DialOptions) ([]packets.UDPConn, error) {
	if options.NumPaths == 0 && len(path) > 0 {
		options.NumPaths = len(path)
	}

	panAddr, err := pan.ResolveUDPAddr(remote.String())
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"scion-filetransfer"},
	}
	// Set Pinging Selector with active probing on two paths
	selector := &pan.DefaultSelector{}
	// selector.SetActive(2)
	session, err := pan.DialQUIC(context.Background(), netaddr.IPPort{}, panAddr, nil, selector, "", tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	log.Debug("Dialed base conn to ", remote.String())

	// TODO: Check duplicates
	remotePeer := RemotePeer{
		Stream: stream,
		Remote: &remote,
	}
	s.ConnectedPeers = append(s.ConnectedPeers, remotePeer)

	// Send handshake
	ret := HandshakePacketQuic{}
	ret.Addr = *s.localAddr
	ret.NumPorts = options.NumPaths
	ret.Ports = make([]int, options.NumPaths)

	for i := 0; i < options.NumPaths; i++ {
		port := remote.Host.Port + (i+1)*11 + 52*len(s.ConnectedPeers) // TODO: Boundary check, better ranges
		ret.Ports = append(ret.Ports, port)
	}

	log.Debug(ret)

	var network2 bytes.Buffer
	enc := gob.NewEncoder(&network2)

	err = enc.Encode(ret)
	if err != nil {
		return nil, err
	}

	stream.Write(network2.Bytes())
	log.Warn("Wrote hs")

	bts := make([]byte, packets.PACKET_SIZE)
	_, err = stream.Read(bts)
	if err != nil {
		return nil, err
	}

	// TODO: Why is this packet not working properly
	// Wait for response
	/*bts, err := ioutil.ReadAll(stream)
	if err != nil {
		log.Error("From readAll")
		return nil, err
	}*/
	ps := HandshakePacketQuic{}
	network := bytes.NewBuffer(bts) // Stand-in for a network connection
	dec := gob.NewDecoder(network)
	err = dec.Decode(&ps)
	if err != nil {
		log.Error("From decode")
		return nil, err
	}

	log.Debug("Got response")

	// TODO: Ports may change here...
	var wg sync.WaitGroup

	for i, p := range path {
		wg.Add(1)
		go func(i int, p snet.Path) {
			l := remote.Copy()
			// l.Host.Port = l.Host.Port + (i+1)*11 + 52*len(s.ConnectedPeers)
			l.Host.Port = ps.Ports[i]
			log.Warn("Dial to ", l.String())
			local := s.localAddr.Copy()
			local.Host.Port = local.Host.Port + (i+1)*11 + 52*len(s.ConnectedPeers)
			// Waitgroup here before sending back response
			_, err := s.Dial(*local, *l, p)
			if err != nil {
				log.Error(err)
				return
			}
			log.Warnf("Dialed %d of %d on %s to remote %s", i, options.NumPaths, s.local, l.String())
			wg.Done()
		}(i, p.Path)
	}
	wg.Wait()

	log.Warn("DIAL ALL Done")

	return s.GetConnections(), nil
}

func (s *QUICSocket) Dial(local, remote snet.UDPAddr, path snet.Path) (packets.UDPConn, error) {
	panAddr, err := pan.ResolveUDPAddr(remote.String())
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"scion-filetransfer"},
	}

	ipP := pan.IPPortValue{}
	shortAddr := fmt.Sprintf("%s:%d", local.Host.IP, local.Host.Port)
	ipP.Set(shortAddr)

	// Set Pinging Selector with active probing on two paths
	selector := &pan.DefaultSelector{}
	log.Warn(panAddr)
	session, err := pan.DialQUIC(context.Background(), ipP.Get(), panAddr, nil, selector, "", tlsCfg, nil)
	if err != nil {
		return nil, err
	}

	log.Warn("SESSION FROM ", local.String(), " TO ", remote.String())

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	log.Warn("STREAM FROM ", local.String(), " TO ", remote.String())

	// Send handshake
	ret := DialPacketQuic{}
	ret.Addr = local
	ret.Path = path

	var network2 bytes.Buffer
	enc := gob.NewEncoder(&network2)

	err = enc.Encode(ret)
	if err != nil {
		return nil, err
	}

	quicConn := &QUICReliableConn{
		internalConn: stream,
		session:      session,
		path:         &path,
		remote:       &remote,
		metrics:      *packets.NewPathMetrics(1000 * time.Millisecond),
		// local:        session.LocalAddr(), // TODO: Local Addr
	}
	log.Errorf("%p", quicConn)

	/*go func() {
		for {
			time.Sleep(1 * time.Second)
			quicConn.Write(network2.Bytes())
		}

	}()*/

	// For loop, deadline, write packet, read response
	for i := 0; i < 5; i++ {
		log.Warn("WRITE PACKET")
		quicConn.Write(network2.Bytes())

		quicConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		bts := make([]byte, packets.PACKET_SIZE)
		n, err := quicConn.Read(bts)
		log.Warn("Read ", n, " FROM DIAL RESPONSE")
		if err != nil {
			log.Error("From DIAL Response ", err)
			i++
			continue
		}
		p := DialPacketQuic{}
		network := bytes.NewBuffer(bts) // Stand-in for a network connection
		dec := gob.NewDecoder(network)
		err = dec.Decode(&p)
		if err != nil {
			return nil, err
		}
		break
	}

	log.Error(ret)

	s.conns = append(s.conns, quicConn)
	return quicConn, nil
}

func (s *QUICSocket) GetConnections() []packets.UDPConn {
	conns := make([]packets.UDPConn, 0)
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	return conns
}

func (s *QUICSocket) CloseAll() []error {
	errors := make([]error, 0)
	for _, con := range s.conns {
		err := con.Close()
		if err != nil {
			errors = append(errors, err)
		}
	}

	s.conns = make([]*QUICReliableConn, 0)
	s.ConnectedPeers = make([]RemotePeer, 0)
	return errors
}
