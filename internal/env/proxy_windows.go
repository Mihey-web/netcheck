//go:build windows

package env

import (
	"golang.org/x/sys/windows/registry"
)

// systemProxy — включён ли системный прокси Windows (WinINET, им пользуются
// браузеры) и его адрес.
func systemProxy() (bool, string) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return false, ""
	}
	defer k.Close()
	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return false, ""
	}
	server, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return true, ""
	}
	return true, server
}
