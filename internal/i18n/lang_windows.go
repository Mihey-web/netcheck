//go:build windows

package i18n

import "syscall"

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultUILanguage = kernel32.NewProc("GetUserDefaultUILanguage")
)

// systemLang: русский UI Windows → RU, иначе EN.
func systemLang() Lang {
	langID, _, _ := procGetUserDefaultUILanguage.Call()
	if langID&0x3ff == 0x19 { // LANG_RUSSIAN
		return RU
	}
	return EN
}
