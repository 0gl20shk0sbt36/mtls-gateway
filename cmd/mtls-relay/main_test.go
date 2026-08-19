package main

import "testing"

func TestIsLoopbackAddr(t *testing.T) {
	ok := []string{"127.0.0.1:18081", "127.0.0.1", "localhost:18081", "[::1]:18081", "::1"}
	bad := []string{"0.0.0.0:18081", "192.168.1.5:18081", "100.64.0.2:18081", "evil.com:18081", ""}
	for _, a := range ok {
		if !isLoopbackAddr(a) {
			t.Errorf("should be loopback: %q", a)
		}
	}
	for _, a := range bad {
		if isLoopbackAddr(a) {
			t.Errorf("should NOT be loopback: %q", a)
		}
	}
}
