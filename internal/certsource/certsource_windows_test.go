//go:build windows

package certsource

import "testing"

// Windows 冒烟测试(仅 CI windows-test 真机执行; 本机 Linux 不编译):
// 系统证书库源(CNG)可打开并枚举 — CurrentUser\My 存储恒存在。
// 覆盖审计指出的"Windows CNG 证书源零直接测试"缺口(此前 windows-test
// 只跑通用测试, 仓库无任何 windows 门控测试文件)。
func TestSystemSourceOpenWindows(t *testing.T) {
	s, err := OpenSystem()
	if err != nil {
		t.Fatalf("open system cert source on windows: %v", err)
	}
	if _, err := s.List(); err != nil {
		t.Fatalf("list system certs: %v", err)
	}
}
