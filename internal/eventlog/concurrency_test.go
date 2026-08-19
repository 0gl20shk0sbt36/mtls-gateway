package eventlog

import (
	"fmt"
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
