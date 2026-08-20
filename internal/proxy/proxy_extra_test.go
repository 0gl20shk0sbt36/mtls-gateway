package proxy

import "testing"

// flash 审计: 数字型 mapping id 歧义 —— id 优先于索引, 防权限错配
func TestResolveChannelIndexIDBeforeIndex(t *testing.T) {
	routes := []*route{{id: "1", port: "9443"}, {id: "2", port: "9444"}, {id: "dsh-main", port: "9445"}}
	// 纯数字 id "2" 应按 id 精确匹配(索引 1 的 id 恰是 "2", 但这里验证的是"先按 id")
	if got := resolveChannelIndex(routes, "2"); got != 1 {
		t.Fatalf("id \"2\" should resolve by id to index 1, got %d", got)
	}
	// 无匹配 id 时回退到数字索引(兼容旧配置): "1" 匹配 id="1"(索引0), 数字索引 1 会被 id="2" 占用
	// 用一个不存在的 id + 纯数字验证索引回退
	if got := resolveChannelIndex(routes, "0"); got != 0 {
		t.Fatalf("index fallback \"0\" should resolve to 0, got %d", got)
	}
	// 非数字且无匹配 id → -1
	if got := resolveChannelIndex(routes, "ghost"); got != -1 {
		t.Fatalf("ghost should resolve to -1, got %d", got)
	}
}
