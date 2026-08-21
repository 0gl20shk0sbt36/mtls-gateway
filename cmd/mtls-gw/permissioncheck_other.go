//go:build !linux

// 非 Linux 平台(Windows/macOS): 跳过启动权限预检(用户要求仅 Linux 检查)。
// 保持 checkStartupPaths 接口一致, main.go 无需条件编译。
package main

// checkStartupPaths 非 Linux 不检查, 恒返回空(全部通过)。
func checkStartupPaths(Config) []string { return nil }

// reportStartupFailures 非 Linux 无失败可报(空操作)。
func reportStartupFailures(Config, []string) {}
