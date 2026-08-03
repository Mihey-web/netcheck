//go:build !windows

package i18n

import (
	"os"
	"strings"
)

func systemLang() Lang {
	if strings.HasPrefix(strings.ToLower(os.Getenv("LANG")), "ru") {
		return RU
	}
	return EN
}
