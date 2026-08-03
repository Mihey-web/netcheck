package env

import (
	"net"
	"strconv"
	"testing"
)

const tsRunningExit = `{
  "BackendState": "Running",
  "Self": {"HostName": "mihey-pc"},
  "Peer": {
    "key1": {"HostName": "de", "ExitNode": true, "Online": true},
    "key2": {"HostName": "ru", "ExitNode": false, "Online": true}
  }
}`

const tsRunningNoExit = `{
  "BackendState": "Running",
  "Self": {"HostName": "mihey-pc"},
  "Peer": {
    "key1": {"HostName": "de", "ExitNode": false, "Online": true}
  }
}`

const tsStopped = `{"BackendState": "Stopped"}`

func TestParseTailscaleStatus(t *testing.T) {
	if got := ParseTailscaleStatus([]byte(tsRunningExit)); got != "exit: de" {
		t.Fatalf("exit case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte(tsRunningNoExit)); got != "connected, no exit" {
		t.Fatalf("no-exit case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte(tsStopped)); got != "" {
		t.Fatalf("stopped case: got %q", got)
	}
	if got := ParseTailscaleStatus([]byte("not json")); got != "" {
		t.Fatalf("invalid json case: got %q", got)
	}
}

// fakeSocks5 отвечает на SOCKS5 method-selection (VER=5, METHOD=0).
func fakeSocks5(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 16)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				conn.Write([]byte{0x05, 0x00})
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestClassifyListenerSocks5(t *testing.T) {
	port := fakeSocks5(t)
	proto, ok := classifyListener(port)
	if !ok || proto != "socks5" {
		t.Fatalf("want socks5/true, got %q/%v", proto, ok)
	}
}

func TestClassifyListenerClosed(t *testing.T) {
	// порт 1 закрыт
	if _, ok := classifyListener(1); ok {
		t.Fatal("closed port must not classify")
	}
}
