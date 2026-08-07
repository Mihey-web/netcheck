// Package fonts отдаёт фронту CSS со шрифтами: выбранные пользователем
// семейства и, при желании, произвольный файл шрифта с диска — он встраивается
// в CSS как data-URL (в репозитории никаких шрифтовых ассетов).
package fonts

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mihey/netcheck/internal/config"
)

// customFamily — имя семейства, под которым подключается файл с диска.
const customFamily = "ncCustomFont"

const (
	defaultHUD  = `'Bahnschrift SemiBold Condensed','Bahnschrift','Segoe UI',sans-serif`
	defaultMono = `'Cascadia Mono',Consolas,'Courier New',monospace`
)

// ReadFunc позволяет подменить чтение файла в тестах.
type ReadFunc func(path string) ([]byte, error)

// Scales — размеры интерфейса. Вёрстка задана в px, поэтому масштабируем
// страницу целиком через zoom: так растут и шрифты, и отступы, и таблица.
var Scales = map[string]float64{
	"s":  1.00,
	"m":  1.15,
	"l":  1.30,
	"xl": 1.50,
}

// DefaultScale — размер по умолчанию: исходная вёрстка мокапа читается мелко.
const DefaultScale = "m"

// ScaleFor — множитель для ключа размера; неизвестный ключ даёт дефолт.
func ScaleFor(key string) float64 {
	if v, ok := Scales[strings.ToLower(strings.TrimSpace(key))]; ok {
		return v
	}
	return Scales[DefaultScale]
}

// BuildCSS собирает таблицу стилей: @font-face для файла (если задан, читается
// и действительно является шрифтом) плюс переменные --hudfont/--mono.
// Нечитаемый или не-шрифтовый файл не применяется — приложение должно
// открыться в любом случае; причина уходит в лог.
func BuildCSS(ui config.UI, read ReadFunc) string {
	if read == nil {
		read = os.ReadFile
	}

	var sb strings.Builder
	hud := defaultHUD
	if fam := strings.TrimSpace(ui.FontHUD); fam != "" {
		hud = fmt.Sprintf("'%s',%s", escapeFamily(fam), defaultHUD)
	}
	mono := defaultMono
	if fam := strings.TrimSpace(ui.FontMono); fam != "" {
		mono = fmt.Sprintf("'%s',%s", escapeFamily(fam), defaultMono)
	}

	if path := strings.TrimSpace(ui.FontFile); path != "" {
		if raw, err := read(path); err != nil {
			log.Printf("fonts: файл %s не применён: %v", path, err)
		} else if err := validateFontFile(path, raw); err != nil {
			log.Printf("fonts: файл %s не применён: %v", path, err)
		} else {
			fmt.Fprintf(&sb, "@font-face{font-family:'%s';src:url(data:%s;base64,%s);font-display:swap}\n",
				customFamily, fontMIME(path), base64.StdEncoding.EncodeToString(raw))
			hud = fmt.Sprintf("'%s',%s", customFamily, hud)
		}
	}

	fmt.Fprintf(&sb, ":root{--hudfont:%s;--mono:%s}\n", hud, mono)
	fmt.Fprintf(&sb, "body{zoom:%.4g}\n", ScaleFor(ui.Scale))
	return sb.String()
}

// styleWords — начертания, которыми Windows разводит записи одного семейства
// по отдельным строкам реестра. Локаль системы влияет на язык этих слов.
// Ширина ("Narrow", "Condensed") сюда НЕ входит: это самостоятельные семейства,
// которые пользователь вправе выбрать.
var styleWords = []string{
	"Regular", "Bold", "Italic", "Oblique", "Demibold",
	"Обычный", "Полужирный", "Курсив", "Наклонный", "Светлый", "Жирный", "Тонкий",
}

// trimStyles срезает хвост из слов-начертаний, оставляя имя семейства:
// "Arial Narrow Полужирный Курсив" → "Arial Narrow".
func trimStyles(name string) string {
	words := strings.Fields(name)
	for len(words) > 1 {
		last := words[len(words)-1]
		matched := false
		for _, sw := range styleWords {
			if strings.EqualFold(last, sw) {
				matched = true
				break
			}
		}
		if !matched {
			break
		}
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}

// escapeFamily экранирует имя семейства для CSS-строки в одинарных кавычках.
// Имя приходит из конфига: без экранирования кавычка или бэкслеш в нём
// разорвали бы строку и позволили бы дописать в стиль произвольный CSS.
func escapeFamily(name string) string {
	name = strings.ReplaceAll(name, `\`, `\\`)
	return strings.ReplaceAll(name, `'`, `\'`)
}

// fontMagics — сигнатуры первых байтов форматов, которые мы готовы встроить:
// TrueType, OpenType/CFF, WOFF, WOFF2 и TTC-коллекция.
var fontMagics = [][]byte{
	{0x00, 0x01, 0x00, 0x00}, // TrueType
	[]byte("OTTO"),           // OpenType с CFF
	[]byte("wOFF"),           // WOFF
	[]byte("wOF2"),           // WOFF2
	[]byte("ttcf"),           // TrueType Collection
}

// validateFontFile проверяет, что путь из конфига указывает на настоящий шрифт:
// расширение из белого списка И знакомая сигнатура в начале файла. Иначе
// BuildCSS превращается в примитив чтения произвольных файлов с диска в
// страницу — достаточно подменить путь в конфиге.
func validateFontFile(path string, raw []byte) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ttf", ".otf", ".woff", ".woff2":
	default:
		return fmt.Errorf("расширение %q не похоже на шрифт", filepath.Ext(path))
	}
	for _, magic := range fontMagics {
		if bytes.HasPrefix(raw, magic) {
			return nil
		}
	}
	return fmt.Errorf("содержимое не похоже на шрифт: нет известной сигнатуры")
}

func fontMIME(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".otf":
		return "font/otf"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	default:
		return "font/ttf"
	}
}
