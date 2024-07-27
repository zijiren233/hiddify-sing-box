package option

import "github.com/xtls/xray-core/proxy/freedom"

type XrayOutboundOptions struct {
	DialerOptions
	Network          NetworkList        `json:"network,omitempty"`
	UDPOverTCP       *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
	XrayOutboundJson *map[string]any    `json:"xray_outbound_raw"`
	Fragment         *freedom.Fragment  `json:"fragment"`
}
