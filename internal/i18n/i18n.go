// Package i18n — все пользовательские строки netcheck на RU и EN.
// Логика оперирует message-id; текст собирается здесь.
package i18n

import "fmt"

type Lang string

const (
	RU Lang = "ru"
	EN Lang = "en"
)

// Resolve превращает значение конфига (auto|ru|en) в конкретный язык.
func Resolve(cfgLang string) Lang {
	switch cfgLang {
	case "ru":
		return RU
	case "en":
		return EN
	default:
		return systemLang()
	}
}

// T — строка по id с подстановкой аргументов. Неизвестный id возвращается
// как есть (заметно в UI и не роняет прогон).
func T(l Lang, id string, args ...any) string {
	m, ok := messages[id]
	if !ok {
		return id
	}
	tpl, ok := m[l]
	if !ok {
		tpl = m[EN]
	}
	if len(args) == 0 {
		return tpl
	}
	return fmt.Sprintf(tpl, args...)
}
