package panel

import (
	"encoding/json"
	"os"
	"sync"

	"dario.cat/mergo"
	"github.com/r3labs/diff/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/Vietnamvpn/XrayR/api"
	"github.com/Vietnamvpn/XrayR/api/bunpanel"
	"github.com/Vietnamvpn/XrayR/api/gov2panel"
	"github.com/Vietnamvpn/XrayR/api/newV2board"
	"github.com/Vietnamvpn/XrayR/api/pmpanel"
	"github.com/Vietnamvpn/XrayR/api/proxypanel"
	"github.com/Vietnamvpn/XrayR/api/sspanel"
	"github.com/Vietnamvpn/XrayR/api/v2raysocks"
	"github.com/Vietnamvpn/XrayR/app/mydispatcher"
	_ "github.com/Vietnamvpn/XrayR/cmd/distro/all"
	"github.com/Vietnamvpn/XrayR/service"
	"github.com/Vietnamvpn/XrayR/service/controller"
)

// Panel Structure
type Panel struct {
	access      sync.Mutex
	panelConfig *Config
	Server      *core.Instance
	Service     []service.Service
	Running     bool
}

func New(panelConfig *Config) *Panel {
	p := &Panel{panelConfig: panelConfig}
	return p
}

func (p *Panel) loadCore(panelConfig *Config) *core.Instance {
	// Log Config
	coreLogConfig := &conf.LogConfig{}
	logConfig := getDefaultLogConfig()
	if panelConfig.LogConfig != nil {
		if _, err := diff.Merge(logConfig, panelConfig.LogConfig, logConfig); err != nil {
			log.Panicf("Read Log config failed: %s", err)
		}
	}
	coreLogConfig.LogLevel = logConfig.Level
	coreLogConfig.AccessLog = logConfig.AccessPath
	coreLogConfig.ErrorLog = logConfig.ErrorPath

	// DNS config
	coreDnsConfig := &conf.DNSConfig{}
	if panelConfig.DnsConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.DnsConfigPath); err != nil {
			log.Panicf("Failed to read DNS config file at: %s", panelConfig.DnsConfigPath)
		} else {
			if err = json.Unmarshal(data, coreDnsConfig); err != nil {
				log.Panicf("Failed to unmarshal DNS config: %s", panelConfig.DnsConfigPath)
			}
		}
	}

	// init controller's DNS config
	// for _, config := range p.panelConfig.NodesConfig {
	// 	config.ControllerConfig.DNSConfig = coreDnsConfig
	// }

	dnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand DNS config, Please check: https://xtls.github.io/config/dns.html for help: %s", err)
	}

	// Routing config
	coreRouterConfig := &conf.RouterConfig{}
	if panelConfig.RouteConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.RouteConfigPath); err != nil {
			log.Panicf("Failed to read Routing config file at: %s", panelConfig.RouteConfigPath)
		} else {
			if err = json.Unmarshal(data, coreRouterConfig); err != nil {
				log.Panicf("Failed to unmarshal Routing config: %s", panelConfig.RouteConfigPath)
			}
		}
	}
	routeConfig, err := coreRouterConfig.Build()
	if err != nil {
		log.Panicf("Failed to understand Routing config  Please check: https://xtls.github.io/config/routing.html for help: %s", err)
	}
	// Custom Inbound config
	var coreCustomInboundConfig []conf.InboundDetourConfig
	if panelConfig.InboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.InboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Inbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomInboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Inbound config: %s", panelConfig.OutboundConfigPath)
			}
		}
	}
	var inBoundConfig []*core.InboundHandlerConfig
	for _, config := range coreCustomInboundConfig {
		oc, err := config.Build()
		if err != nil {
			log.Panicf("Failed to understand Inbound config, Please check: https://xtls.github.io/config/inbound.html for help: %s", err)
		}
		inBoundConfig = append(inBoundConfig, oc)
	}
	// Custom Outbound config
	var coreCustomOutboundConfig []conf.OutboundDetourConfig
	if panelConfig.OutboundConfigPath != "" {
		if data, err := os.ReadFile(panelConfig.OutboundConfigPath); err != nil {
			log.Panicf("Failed to read Custom Outbound config file at: %s", panelConfig.OutboundConfigPath)
		} else {
			if err = json.Unmarshal(data, &coreCustomOutboundConfig); err != nil {
				log.Panicf("Failed to unmarshal Custom Outbound config: %s", panelConfig.OutboundConfigPath)
			}
		}
	}

	var outBoundConfig []*core.OutboundHandlerConfig
	for i := range coreCustomOutboundConfig {
		config := &coreCustomOutboundConfig[i]

		if config.Protocol == "hysteria2" || config.Protocol == "hysteria" {
			// --- 1. CHUẨN HOÁ GIAO THỨC ---
			config.Protocol = "hysteria"

			var address string
			var port interface{}
			var authPass string
			var obfsType string
			var obfsPass string

			// --- 2. HÚT THÔNG SỐ (Bao gồm cả OBFS) ---
			if config.Settings != nil {
				var raw map[string]interface{}
				if err := json.Unmarshal(*config.Settings, &raw); err == nil {
					if servers, ok := raw["servers"].([]interface{}); ok && len(servers) > 0 {
						if srv, ok := servers[0].(map[string]interface{}); ok {
							if pwd, exists := srv["password"]; exists {
								authPass, _ = pwd.(string)
							}
							if addr, exists := srv["address"]; exists {
								address, _ = addr.(string)
							}
							if p, exists := srv["port"]; exists {
								port = p
							}

							// Xử lý OBFS Salamander
							if obfsRaw, exists := srv["obfs"]; exists {
								if obfsData, ok := obfsRaw.(map[string]interface{}); ok {
									if t, ex := obfsData["type"]; ex {
										obfsType, _ = t.(string)
									}
									if p, ex := obfsData["password"]; ex {
										obfsPass, _ = p.(string)
									}
								}
							}
						}
					}
				}
			}

			// --- 3. ĐỊNH DẠNG LẠI SETTINGS GỐC ---
			newSettings := map[string]interface{}{
				"address": address,
				"port":    port,
				"version": 2,
			}
			newSettingsBytes, _ := json.Marshal(newSettings)
			msgSettings := json.RawMessage(newSettingsBytes)
			config.Settings = &msgSettings

			// --- 4. CẬP NHẬT CHÍNH XÁC STREAM SETTINGS ---
			if config.StreamSetting != nil {
				netStr := conf.TransportProtocol("hysteria")
				config.StreamSetting.Network = &netStr
				config.StreamSetting.Security = "tls"

				if config.StreamSetting.TLSSettings == nil {
					config.StreamSetting.TLSSettings = &conf.TLSConfig{}
				}

				// 4.1. ALPN rỗng và Fingerprint
				emptyAlpn := conf.StringList([]string{})
				config.StreamSetting.TLSSettings.ALPN = &emptyAlpn
				config.StreamSetting.TLSSettings.Fingerprint = "chrome"
				config.StreamSetting.TLSSettings.ECHConfigList = ""
				config.StreamSetting.TLSSettings.VerifyPeerCertByName = ""
				config.StreamSetting.TLSSettings.PinnedPeerCertSha256 = ""

				// 4.2. Bơm thông số HysteriaSettings (Đã thêm OBFS)
				hysteriaMap := map[string]interface{}{
					"version":                     2,
					"auth":                        authPass,
					"obfs":                        obfsType, // Bơm loại OBFS (salamander)
					"obfsPassword":                obfsPass, // Bơm mật khẩu OBFS
					"congestion":                  "",
					"up":                          "0",
					"down":                        "0",
					"initStreamReceiveWindow":     8388608,
					"maxStreamReceiveWindow":      8388608,
					"initConnectionReceiveWindow": 20971520,
					"maxConnectionReceiveWindow":  20971520,
					"maxIdleTimeout":              30,
					"keepAlivePeriod":             0,
					"disablePathMTUDiscovery":     false,
				}
				hysteriaBytes, _ := json.Marshal(hysteriaMap)

				var hConfig conf.HysteriaConfig
				if err := json.Unmarshal(hysteriaBytes, &hConfig); err == nil {
					config.StreamSetting.HysteriaSettings = &hConfig
				}
			}

		} else if config.StreamSetting != nil && config.StreamSetting.Network != nil && string(*config.StreamSetting.Network) == "udp" {
			tcpNet := conf.TransportProtocol("tcp")
			config.StreamSetting.Network = &tcpNet
		}

		oc, err := config.Build()
		if err != nil {
			log.Errorf("Bỏ qua Node lỗi [Tag: %s]: %s", config.Tag, err)
			continue
		}
		outBoundConfig = append(outBoundConfig, oc)
	}
	// Policy config
	levelPolicyConfig := parseConnectionConfig(panelConfig.ConnectionConfig)
	corePolicyConfig := &conf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*conf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Core Config
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&mydispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.Panicf("failed to create instance: %s", err)
	}

	return server
}

// Start the panel
func (p *Panel) Start() {
	p.access.Lock()
	defer p.access.Unlock()
	log.Print("Start the panel..")
	// Load Core
	server := p.loadCore(p.panelConfig)
	if err := server.Start(); err != nil {
		log.Panicf("Failed to start instance: %s", err)
	}
	p.Server = server

	// Load Nodes config
	for _, nodeConfig := range p.panelConfig.NodesConfig {
		var apiClient api.API
		switch nodeConfig.PanelType {
		case "SSpanel":
			apiClient = sspanel.New(nodeConfig.ApiConfig)
		case "NewV2board", "V2board":
			apiClient = newV2board.New(nodeConfig.ApiConfig)
		case "PMpanel":
			apiClient = pmpanel.New(nodeConfig.ApiConfig)
		case "Proxypanel":
			apiClient = proxypanel.New(nodeConfig.ApiConfig)
		case "V2RaySocks":
			apiClient = v2raysocks.New(nodeConfig.ApiConfig)
		case "GoV2Panel":
			apiClient = gov2panel.New(nodeConfig.ApiConfig)
		case "BunPanel":
			apiClient = bunpanel.New(nodeConfig.ApiConfig)
		default:
			log.Panicf("Unsupport panel type: %s", nodeConfig.PanelType)
		}
		var controllerService service.Service
		// Register controller service
		controllerConfig := getDefaultControllerConfig()
		if nodeConfig.ControllerConfig != nil {
			if err := mergo.Merge(controllerConfig, nodeConfig.ControllerConfig, mergo.WithOverride); err != nil {
				log.Panicf("Read Controller Config Failed")
			}
		}
		controllerService = controller.New(server, apiClient, controllerConfig, nodeConfig.PanelType)
		p.Service = append(p.Service, controllerService)

	}

	// Start all the service
	for _, s := range p.Service {
		err := s.Start()
		if err != nil {
			log.Panicf("Panel Start failed: %s", err)
		}
	}
	p.Running = true

}

// Close the panel
func (p *Panel) Close() {
	p.access.Lock()
	defer p.access.Unlock()
	for _, s := range p.Service {
		err := s.Close()
		if err != nil {
			log.Panicf("Panel Close failed: %s", err)
		}
	}
	p.Service = nil
	p.Server.Close()
	p.Running = false

}

func parseConnectionConfig(c *ConnectionConfig) (policy *conf.Policy) {
	connectionConfig := getDefaultConnectionConfig()
	if c != nil {
		if _, err := diff.Merge(connectionConfig, c, connectionConfig); err != nil {
			log.Panicf("Read ConnectionConfig failed: %s", err)
		}
	}
	policy = &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         &connectionConfig.Handshake,
		ConnectionIdle:    &connectionConfig.ConnIdle,
		UplinkOnly:        &connectionConfig.UplinkOnly,
		DownlinkOnly:      &connectionConfig.DownlinkOnly,
		BufferSize:        &connectionConfig.BufferSize,
	}
	return
}
