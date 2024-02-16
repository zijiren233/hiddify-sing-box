//go:build with_wireguard

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound/houtbound"
	"github.com/sagernet/sing-box/transport/wireguard"
	dns "github.com/sagernet/sing-dns"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
)

var (
	_ adapter.Outbound                = (*WireGuard)(nil)
	_ adapter.InterfaceUpdateListener = (*WireGuard)(nil)
)

type WireGuard struct {
	myOutboundAdapter
	ctx           context.Context
	workers       int
	peers         []wireguard.PeerConfig
	useStdNetBind bool
	listener      N.Dialer
	ipcConf       string

	pauseManager     pause.Manager
	pauseCallback    *list.Element[pause.Callback]
	bind             conn.Bind
	device           *device.Device
	tunDevice        wireguard.Device
	hforwarder       *houtbound.Forwarder
	fakePackets      []int
	fakePacketsSize  []int
	fakePacketsDelay []int
	isClosed         bool        //hiddify
	wgDependencies   []WireGuard //hidify
	lastUpdate       time.Time
}

func NewWireGuard(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.WireGuardOutboundOptions) (*WireGuard, error) {
	hforwarder := houtbound.ApplyTurnRelay(houtbound.CommonTurnRelayOptions{ServerOptions: options.ServerOptions, TurnRelayOptions: options.TurnRelay})
	outbound := &WireGuard{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeWireGuard,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:            ctx,
		workers:        options.Workers,
		pauseManager:   service.FromContext[pause.Manager](ctx),
		hforwarder:     hforwarder, //hiddify
		isClosed:       false,
		wgDependencies: []WireGuard{},
		lastUpdate:     time.Now(),
	}
	outbound.fakePackets = []int{0, 0}
	outbound.fakePacketsSize = []int{0, 0}
	outbound.fakePacketsDelay = []int{0, 0}
	if options.FakePackets != "" {
		var err error
		outbound.fakePackets, err = option.ParseIntRange(options.FakePackets)
		if err != nil {
			return nil, err
		}
		outbound.fakePacketsSize = []int{40, 100}
		outbound.fakePacketsDelay = []int{200, 500}

		if options.FakePacketsSize != "" {
			var err error
			outbound.fakePacketsSize, err = option.ParseIntRange(options.FakePacketsSize)
			if err != nil {
				return nil, err
			}
		}

		if options.FakePacketsDelay != "" {
			var err error
			outbound.fakePacketsDelay, err = option.ParseIntRange(options.FakePacketsDelay)
			if err != nil {
				return nil, err
			}
		}

	}

	peers, err := wireguard.ParsePeers(options)
	if err != nil {
		return nil, err
	}
	outbound.peers = peers
	if len(options.LocalAddress) == 0 {
		return nil, E.New("missing local address")
	}
	if options.GSO {
		if options.GSO && options.Detour != "" {
			return nil, E.New("gso is conflict with detour")
		}
		options.IsWireGuardListener = true
		outbound.useStdNetBind = true
	}
	listener, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound.listener = listener
	var privateKey string
	{
		bytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		privateKey = hex.EncodeToString(bytes)
	}
	outbound.ipcConf = "private_key=" + privateKey
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1408
	}
	var wireTunDevice wireguard.Device
	if !options.SystemInterface && tun.WithGVisor {
		wireTunDevice, err = wireguard.NewStackDevice(options.LocalAddress, mtu)
	} else {
		wireTunDevice, err = wireguard.NewSystemDevice(router, options.InterfaceName, options.LocalAddress, mtu, options.GSO)
	}
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	outbound.tunDevice = wireTunDevice
	return outbound, nil
}

func (w *WireGuard) Start() error {
	err := wireguard.ResolvePeers(w.ctx, w.router, w.peers)
	if err != nil {
		return err
	}
	var bind conn.Bind
	if w.useStdNetBind {
		bind = conn.NewStdNetBind(w.listener.(dialer.WireGuardListener))
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		peerLen := len(w.peers)
		if peerLen == 1 {
			isConnect = true
			connectAddr = w.peers[0].Endpoint
			reserved = w.peers[0].Reserved
		}
		bind = wireguard.NewClientBind(w.ctx, w, w.listener, isConnect, connectAddr, reserved)
	}

	wgDevice := device.NewDevice(w.tunDevice, bind, &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			w.logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...interface{}) {
			w.logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}, w.workers, w.fakePackets, w.fakePacketsSize, w.fakePacketsDelay)
	ipcConf := w.ipcConf
	for _, peer := range w.peers {
		ipcConf += peer.GenerateIpcLines()
	}
	err = wgDevice.IpcSet(ipcConf)
	if err != nil {
		return E.Cause(err, "setup wireguard: \n", ipcConf)
	}
	w.device = wgDevice
	w.pauseCallback = w.pauseManager.RegisterCallback(w.onPauseUpdated)

	for _, d := range w.Dependencies() {
		dep_out, ok := w.router.Outbound(d)
		if !ok {
			continue
		}
		if wgout, ok2 := dep_out.(*WireGuard); ok2 {
			w.wgDependencies = append(w.wgDependencies, *wgout)
		}
	}

	for _, wg := range w.wgDependencies {
		for !wg.device.IsUp() { //not needed as singbox already handle it
			w.logger.Warn("Dependency ", wg.Tag(), " is not up yet! Waiting.")
			<-time.After(100 * time.Millisecond)
		}
	}

	return w.tunDevice.Start()
}

func (w *WireGuard) Close() error {
	if w.isClosed {
		return nil
	}
	w.isClosed = true
	for _, wgout := range w.wgDependencies {
		wgout.Close()
	}

	if w.hforwarder != nil { //hiddify
		w.hforwarder.Close() //hiddify
	} //hiddify
	if w.device != nil {
		w.device.Close()
	}
	if w.pauseCallback != nil {
		w.pauseManager.UnregisterCallback(w.pauseCallback)
	}
	w.tunDevice.Close()
	return nil
}

func (w *WireGuard) InterfaceUpdated() {
	w.logger.Warn("Hiddify! Wirguard! Interface updated!1")
	for _, wgout := range w.wgDependencies {
		wgout.InterfaceUpdated()
	}
	if time.Since(w.lastUpdate) < 50*time.Millisecond {
		return
	}
	w.lastUpdate = time.Now()
	w.logger.Warn("Hiddify! Wirguard! Interface updated!2")
	w.device.BindUpdate()
	return
}

func (w *WireGuard) onPauseUpdated(event int) {
	w.logger.Warn("Hiddify! Wirguard! on Pause updated!1")
	for _, wgout := range w.wgDependencies {
		wgout.onPauseUpdated(event)
	}
	if time.Since(w.lastUpdate) < 50*time.Millisecond {
		return
	}
	w.lastUpdate = time.Now()
	w.logger.Warn("Hiddify! Wirguard! on Pause updated!2")
	switch event {
	case pause.EventDevicePaused:
		w.device.Down()
	case pause.EventDeviceWake:
		w.device.Up()
	}
}

func (w *WireGuard) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if r := recover(); r != nil {
		fmt.Println("SWireguard error!", r, string(debug.Stack()))
	}

	switch network {
	case N.NetworkTCP:
		w.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if destination.IsFqdn() {
		destinationAddresses, err := w.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, w.tunDevice, network, destination, destinationAddresses)
	}
	return w.tunDevice.DialContext(ctx, network, destination)
}

func (w *WireGuard) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if r := recover(); r != nil {
		fmt.Println("SWireguard error!", r, string(debug.Stack()))
	}
	w.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsFqdn() {
		destinationAddresses, err := w.router.LookupDefault(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		packetConn, _, err := N.ListenSerial(ctx, w.tunDevice, destination, destinationAddresses)
		if err != nil {
			return nil, err
		}
		return packetConn, err
	}
	return w.tunDevice.ListenPacket(ctx, destination)
}

func (w *WireGuard) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewDirectConnection(ctx, w.router, w, conn, metadata, dns.DomainStrategyAsIS)
}

func (w *WireGuard) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewDirectPacketConnection(ctx, w.router, w, conn, metadata, dns.DomainStrategyAsIS)
}
