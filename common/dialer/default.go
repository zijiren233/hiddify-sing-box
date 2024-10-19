package dialer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/conntrack"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/zijiren233/gwst/ws"
	"golang.org/x/exp/rand"
)

var _ WireGuardListener = (*DefaultDialer)(nil)

type DefaultDialer struct {
	dialer4             tcpDialer
	dialer6             tcpDialer
	udpDialer4          net.Dialer
	udpDialer6          net.Dialer
	udpListener         net.ListenConfig
	udpAddr4            string
	udpAddr6            string
	isWireGuardListener bool

	wsTunnelOptions option.WsTunnelOptions
}

func NewDefault(router adapter.Router, options option.DialerOptions) (*DefaultDialer, error) {
	var dialer net.Dialer
	var listener net.ListenConfig
	if options.BindInterface != "" {
		var interfaceFinder control.InterfaceFinder
		if router != nil {
			interfaceFinder = router.InterfaceFinder()
		} else {
			interfaceFinder = control.NewDefaultInterfaceFinder()
		}
		bindFunc := control.BindToInterface(interfaceFinder, options.BindInterface, -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.AutoDetectInterface() {
		bindFunc := router.AutoDetectInterfaceFunc()
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.DefaultInterface() != "" {
		bindFunc := control.BindToInterface(router.InterfaceFinder(), router.DefaultInterface(), -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	}
	if options.RoutingMark != 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(options.RoutingMark))
		listener.Control = control.Append(listener.Control, control.RoutingMark(options.RoutingMark))
	} else if router != nil && router.DefaultMark() != 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(router.DefaultMark()))
		listener.Control = control.Append(listener.Control, control.RoutingMark(router.DefaultMark()))
	}
	if options.ReuseAddr {
		listener.Control = control.Append(listener.Control, control.ReuseAddr())
	}
	if options.ProtectPath != "" {
		dialer.Control = control.Append(dialer.Control, control.ProtectPath(options.ProtectPath))
		listener.Control = control.Append(listener.Control, control.ProtectPath(options.ProtectPath))
	}
	if options.ConnectTimeout != 0 {
		dialer.Timeout = time.Duration(options.ConnectTimeout)
	} else {
		dialer.Timeout = C.TCPTimeout
	}
	// TODO: Add an option to customize the keep alive period
	dialer.KeepAlive = C.TCPKeepAliveInitial
	dialer.Control = control.Append(dialer.Control, control.SetKeepAlivePeriod(C.TCPKeepAliveInitial, C.TCPKeepAliveInterval))
	var udpFragment bool
	if options.UDPFragment != nil {
		udpFragment = *options.UDPFragment
	} else {
		udpFragment = options.UDPFragmentDefault
	}
	if !udpFragment {
		dialer.Control = control.Append(dialer.Control, control.DisableUDPFragment())
		listener.Control = control.Append(listener.Control, control.DisableUDPFragment())
	}
	var (
		dialer4    = dialer
		udpDialer4 = dialer
		udpAddr4   string
	)
	if options.Inet4BindAddress != nil {
		bindAddr := options.Inet4BindAddress.Build()
		dialer4.LocalAddr = &net.TCPAddr{IP: bindAddr.AsSlice()}
		udpDialer4.LocalAddr = &net.UDPAddr{IP: bindAddr.AsSlice()}
		udpAddr4 = M.SocksaddrFrom(bindAddr, 0).String()
	}
	var (
		dialer6    = dialer
		udpDialer6 = dialer
		udpAddr6   string
	)
	if options.Inet6BindAddress != nil {
		bindAddr := options.Inet6BindAddress.Build()
		dialer6.LocalAddr = &net.TCPAddr{IP: bindAddr.AsSlice()}
		udpDialer6.LocalAddr = &net.UDPAddr{IP: bindAddr.AsSlice()}
		udpAddr6 = M.SocksaddrFrom(bindAddr, 0).String()
	}
	if options.TCPMultiPath {
		if !go121Available {
			return nil, E.New("MultiPath TCP requires go1.21, please recompile your binary.")
		}
		setMultiPathTCP(&dialer4)
	}

	var tlsFragment *TLSFragment = nil
	if options.TLSFragment != nil && options.TLSFragment.Enabled {
		tlsFragment = &TLSFragment{}
		if options.TCPFastOpen {
			return nil, E.New("TLS Fragmentation is not compatible with TCP Fast Open, set `tcp_fast_open` to `false` in your outbound if you intend to enable TLS fragmentation.")
		}
		tlsFragment.Enabled = true

		sleep, err := option.Parse2IntRange(options.TLSFragment.Sleep)
		if err != nil {
			return nil, E.Cause(err, "invalid TLS fragment sleep period supplied")
		}
		tlsFragment.Sleep = sleep

		size, err := option.Parse2IntRange(options.TLSFragment.Size)
		if err != nil {
			return nil, E.Cause(err, "invalid TLS fragment size supplied")
		}
		tlsFragment.Size = size

	}
	if options.IsWireGuardListener {
		for _, controlFn := range wgControlFns {
			listener.Control = control.Append(listener.Control, controlFn)
		}
	}
	tcpDialer4, err := newTCPDialer(dialer4, options.TCPFastOpen, tlsFragment)
	if err != nil {
		return nil, err
	}
	tcpDialer6, err := newTCPDialer(dialer6, options.TCPFastOpen, tlsFragment)
	if err != nil {
		return nil, err
	}
	return &DefaultDialer{
		tcpDialer4,
		tcpDialer6,
		udpDialer4,
		udpDialer6,
		listener,
		udpAddr4,
		udpAddr6,
		options.IsWireGuardListener,
		options.WsTunnelOptions,
	}, nil
}

type wsConn struct {
	net.Conn
	f *ws.Forwarder
}

func (c *wsConn) Close() error {
	defer c.f.Close()
	return c.Conn.Close()
}

func (d *DefaultDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	if !address.IsValid() {
		return nil, E.New("invalid address")
	}
	switch N.NetworkName(network) {
	case N.NetworkUDP:
		if !d.wsTunnelOptions.Enabled {
			if !address.IsIPv6() {
				return trackConn(d.udpDialer4.DialContext(ctx, network, address.String()))
			} else {
				return trackConn(d.udpDialer6.DialContext(ctx, network, address.String()))
			}
		}
		port := strconv.Itoa(rand.Intn(65535-1024) + 1024)
		listen := fmt.Sprintf("127.0.0.1:%s", port)
		f := ws.NewForwarder(
			listen,
			ws.NewDialer(address.String(),
				d.wsTunnelOptions.Path,
				ws.WithHost(d.wsTunnelOptions.Host),
				ws.WithDialTLS(d.wsTunnelOptions.ServerName, d.wsTunnelOptions.Insecure),
				ws.WithTarget(d.wsTunnelOptions.Target),
				ws.WithNamedTarget(d.wsTunnelOptions.NamedTarget),
			),
			ws.WithDisableTCP(),
		)
		go func() {
			defer f.Close()
			f.Serve()
		}()
		<-f.OnListened()
		if err := f.ListenErr(); err != nil {
			return nil, fmt.Errorf("failed to listen ws tunnel on %s: %w", listen, err)
		}
		conn, err := trackConn(d.udpDialer4.DialContext(ctx, network, listen))
		if err != nil {
			return nil, err
		}
		return &wsConn{conn, f}, nil
	}
	if !d.wsTunnelOptions.Enabled {
		if !address.IsIPv6() {
			return trackConn(d.dialer4.DialContext(ctx, network, address))
		} else {
			return trackConn(d.dialer6.DialContext(ctx, network, address))
		}
	}
	port := strconv.Itoa(rand.Intn(65535-1024) + 1024)
	listen := fmt.Sprintf("127.0.0.1:%s", port)
	f := ws.NewForwarder(
		listen,
		ws.NewDialer(address.String(),
			d.wsTunnelOptions.Path,
			ws.WithFallbackAddrs(d.wsTunnelOptions.FallbackAddrs),
			ws.WithHost(d.wsTunnelOptions.Host),
			ws.WithDialTLS(d.wsTunnelOptions.ServerName, d.wsTunnelOptions.Insecure),
			ws.WithTarget(d.wsTunnelOptions.Target),
			ws.WithNamedTarget(d.wsTunnelOptions.NamedTarget),
		),
		ws.WithDisableUDP(),
	)
	go func() {
		defer f.Close()
		f.Serve()
	}()
	<-f.OnListened()
	if err := f.ListenErr(); err != nil {
		return nil, fmt.Errorf("failed to listen ws tunnel on %s: %w", listen, err)
	}
	conn, err := trackConn(d.dialer4.DialContext(ctx, network, M.ParseSocksaddr(listen)))
	if err != nil {
		return nil, err
	}
	return &wsConn{conn, f}, nil
}

func (d *DefaultDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.IsIPv6() {
		return trackPacketConn(d.udpListener.ListenPacket(ctx, N.NetworkUDP, d.udpAddr6))
	} else if destination.IsIPv4() && !destination.Addr.IsUnspecified() {
		return trackPacketConn(d.udpListener.ListenPacket(ctx, N.NetworkUDP+"4", d.udpAddr4))
	} else {
		return trackPacketConn(d.udpListener.ListenPacket(ctx, N.NetworkUDP, d.udpAddr4))
	}
}

func (d *DefaultDialer) ListenPacketCompat(network, address string) (net.PacketConn, error) {
	return trackPacketConn(d.udpListener.ListenPacket(context.Background(), network, address))
}

func trackConn(conn net.Conn, err error) (net.Conn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewConn(conn)
}

func trackPacketConn(conn net.PacketConn, err error) (net.PacketConn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewPacketConn(conn)
}
