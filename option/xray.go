package option

type XrayOutboundOptions struct {
	DialerOptions
	Network          NetworkList        `json:"network,omitempty"`
	UDPOverTCP       *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XrayOutboundJson interface{}        `json:"xray_outbound_raw"`
}
