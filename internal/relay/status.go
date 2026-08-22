// status.go: 隧道状态快照与状态汇总(供外壳/管理 API/WebUI 展示)。

package relay

// TunnelStatus 一条隧道的状态快照 (供外壳/管理 API 展示)
type TunnelStatus struct {
	ID          string `json:"id"`
	Service     string `json:"service"`
	Channel     string `json:"channel"`
	Local       string `json:"local"`
	CertID      string `json:"cert_id"`
	Running     bool   `json:"running"`
	ActiveConns int64  `json:"active_conns"`
	ConnsTotal  int64  `json:"conns_total"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	LastError   string `json:"last_error,omitempty"`
}
