package conf

import (
	"context"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "kcp", "mkcp":
		return "", errors.PrintRemovedFeatureError("mKCP transport", "XHTTP")
	case "grpc":
		return "", errors.PrintRemovedFeatureError("gRPC transport", "XHTTP stream-up H2")
	case "ws", "websocket":
		return "", errors.PrintRemovedFeatureError("WebSocket transport", "XHTTP H2 & H3")
	case "httpupgrade":
		return "", errors.PrintRemovedFeatureError("HTTPUpgrade transport", "XHTTP H2 & H3")
	case "h2", "h3", "http":
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
	case "quic":
		return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
	case "hysteria":
		return "", errors.PrintRemovedFeatureError("Hysteria transport", "XHTTP stream-one H3")
	case "masque":
		return "", errors.PrintRemovedFeatureError("MASQUE transport", "XHTTP")
	case "xdrive":
		return "", errors.PrintRemovedFeatureError("XDRIVE transport", "XHTTP")
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type StreamConfig struct {
	Address           *Address         `json:"address"`
	Port              uint16           `json:"port"`
	Method            *TransportProtocol `json:"method"`
	Network           *TransportProtocol `json:"network"`
	Security          string           `json:"security"`
	TLSSettings       *TLSConfig       `json:"tlsSettings"`
	REALITYSettings   *REALITYConfig   `json:"realitySettings"`
	RAWSettings       *TCPConfig       `json:"rawSettings"`
	TCPSettings       *TCPConfig       `json:"tcpSettings"`
	XHTTPSettings     *SplitHTTPConfig `json:"xhttpSettings"`
	SplitHTTPSettings *SplitHTTPConfig `json:"splithttpSettings"`
	SocketSettings    *SocketConfig    `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Method != nil {
		c.Network = c.Method
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}

	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
		if config.ProtocolName == "splithttp" && tlsSettings.ALPN != nil && slices.Equal(*tlsSettings.ALPN, StringList{"http/1.1"}) && tlsSettings.ECHConfigList == "" {
			// a fingerprint puts its own ALPN into the hello, except Go TLS and the
			// randomized ones, which take it from the config or send none
			if fp := tls.GetFingerprint(strings.ToLower(tlsSettings.Fingerprint)); fp != nil && fp.Client != utls.HelloGolang.Client &&
				!strings.HasPrefix(fp.Client, utls.HelloRandomized.Client) {
				errors.LogWarning(context.Background(), `XHTTP: "alpn" ["http/1.1"] reaches the wire only inside ECH, without "echConfigList" the hello carries the ALPN of the fingerprint and the server may pick h2`)
			}
		}
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" {
			return nil, errors.New("REALITY only supports RAW and XHTTP for now.")
		}
		if c.REALITYSettings == nil {
			return nil, errors.New(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}

	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}

	return config, nil
}
