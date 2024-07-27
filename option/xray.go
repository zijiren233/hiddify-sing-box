package option

type XrayOutboundOptions struct {
	DialerOptions
	Network          NetworkList        `json:"network,omitempty"`
	UDPOverTCP       *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XrayOutboundJson map[string]any     `json:"xray_outbound_raw"`
	Fragment         *struct {
		Packets  string `json:"packets"`
		Length   string `json:"length"`
		Interval string `json:"interval"`
	} `json:"fragment"`
}
