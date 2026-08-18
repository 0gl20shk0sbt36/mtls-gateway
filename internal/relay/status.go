package relay

// TunnelStatus 一条隧道的状态快照 (供外壳/管理 API 展示)
type TunnelStatus struct {
	ID          string `json:"id"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	Purpose     string `json:"purpose"`
	CertID      string `json:"cert_id"`
	Running     bool   `json:"running"`
	ActiveConns int64  `json:"active_conns"`
	ConnsTotal  int64  `json:"conns_total"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	LastError   string `json:"last_error,omitempty"`
}
