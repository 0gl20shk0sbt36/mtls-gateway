// Package pathutil 路径工具: dot-segment 清理(防 .. 穿透前缀)
package pathutil

import "strings"

// CleanDotSegments 移除 .. 段与 . 段(保留 // 与尾斜杠语义; .. 钳制在根, 不丢失前导斜杠)。
// 反斜杠视为分隔符一并处理(防 Windows 后端把 \..\ 归一化为路径分隔符导致逃逸)。
// 仅用于以 / 开头的 URL 路径。
func CleanDotSegments(p string) string {
	// 短路: 无点段且无反斜杠的路径原样返回(热路径零分配)
	if !strings.Contains(p, "/.") && !strings.Contains(p, "\\.") && !strings.Contains(p, "\\") {
		return p
	}
	p = strings.ReplaceAll(p, "\\", "/") // 反斜杠归一化为分隔符(URL path 中 \ 无特殊语义)
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
