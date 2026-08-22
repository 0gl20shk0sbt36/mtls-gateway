package eventlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// M-2: 并发写 + 滚动不丢数据/不竞态(-race 下运行)
func TestConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	l, err := New(filepath.Join(dir, "evt.log"), 1, 3) // 1MB 滚动, 写 700KB 事件触发滚动
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	big := strings.Repeat("z", 700*1024)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				l.Write(Event{Type: "access", Cert: fmt.Sprintf("c%d", n), Msg: big})
			}
		}(i)
	}
	wg.Wait()
	// 不崩溃即可; 文件存在且非空
	if len(l.Files()) == 0 {
		t.Fatal("no log files")
	}
}

// pro 深度审计补: 并发写 18 条必须全部落盘(跨滚动文件统计), 不止"文件存在"
func TestConcurrentWritesAllPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evt.log")
	l, err := New(path, 1, 20) // maxFile 足够: 18 条滚动后全部保留(验证并发写不丢行)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	big := strings.Repeat("z", 700*1024)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				l.Write(Event{Type: "access", Cert: fmt.Sprintf("c%d", n), Msg: big})
			}
		}(i)
	}
	wg.Wait()
	total := 0
	for _, f := range l.Files() { // Files() 已含当前文件 + 历史
		data, _ := os.ReadFile(f)
		total += strings.Count(string(data), `"type":"access"`)
	}
	if total != 18 {
		t.Fatalf("18 条事件应全部落盘, got %d", total)
	}
}
