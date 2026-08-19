// Package pathutil 路径工具: dot-segment 清理(防 .. 穿透前缀)
package pathutil

import "strings"

// CleanDotSegments 移除 .. 段与 . 段(保留 // 与尾斜杠语义; .. 钳制在根, 不丢失前导斜杠)
func CleanDotSegments(p string) string {
	segments := strings.Split(p, "/")
	var out []string
	for _, seg := range segments {
		switch seg {
		case "..":
			if len(out) > 1 || (len(out) == 1 && out[0] != "") {
				out = out[:len(out)-1] // 回退一层(根空段保留)
			}
		case ".":
			// 跳过
		default:
			out = append(out, seg)
		}
	}
	res := strings.Join(out, "/")
	if strings.HasPrefix(p, "/") {
		if res == "" {
			return "/"
		}
		if !strings.HasPrefix(res, "/") {
			res = "/" + res
		}
	}
	return res
}
