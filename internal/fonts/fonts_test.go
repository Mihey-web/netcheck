package fonts

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mihey/netcheck/internal/config"
)

func TestBuildCSSDefaults(t *testing.T) {
	css := BuildCSS(config.UI{}, nil)
	if !strings.Contains(css, "--hudfont") || !strings.Contains(css, "--mono") {
		t.Fatalf("defaults must define both variables:\n%s", css)
	}
	if strings.Contains(css, "@font-face") {
		t.Fatal("no custom file — no @font-face expected")
	}
	if !strings.Contains(css, "Bahnschrift") {
		t.Fatal("default HUD font must fall back to Bahnschrift")
	}
}

func TestBuildCSSInstalledFamilies(t *testing.T) {
	css := BuildCSS(config.UI{FontHUD: "Consolas", FontMono: "Courier New"}, nil)
	if !strings.Contains(css, `'Consolas'`) {
		t.Errorf("HUD family not applied:\n%s", css)
	}
	if !strings.Contains(css, `'Courier New'`) {
		t.Errorf("mono family not applied:\n%s", css)
	}
	// пользовательский выбор идёт первым, дефолт остаётся запасным
	if strings.Index(css, `'Consolas'`) > strings.Index(css, "Bahnschrift") {
		t.Error("user font must precede the fallback")
	}
}

func TestBuildCSSCustomFile(t *testing.T) {
	// валидная TrueType-сигнатура + произвольный хвост
	payload := []byte{0x00, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	read := func(path string) ([]byte, error) {
		if path != "C:\\fonts\\se.ttf" {
			return nil, errors.New("unexpected path " + path)
		}
		return payload, nil
	}
	css := BuildCSS(config.UI{FontFile: "C:\\fonts\\se.ttf"}, read)
	if !strings.Contains(css, "@font-face") {
		t.Fatalf("custom file must produce @font-face:\n%s", css)
	}
	if !strings.Contains(css, "base64,"+base64.StdEncoding.EncodeToString(payload)) {
		t.Errorf("font must be inlined as base64 data URL:\n%s", css)
	}
	if !strings.Contains(css, customFamily) {
		t.Errorf("custom family must be used in --hudfont:\n%s", css)
	}
}

func TestBuildCSSUnreadableFileFallsBack(t *testing.T) {
	read := func(string) ([]byte, error) { return nil, errors.New("no such file") }
	css := BuildCSS(config.UI{FontFile: "C:\\missing.ttf"}, read)
	if strings.Contains(css, "@font-face") {
		t.Fatal("unreadable font must be skipped, not injected")
	}
	if !strings.Contains(css, "Bahnschrift") {
		t.Fatal("must fall back to the default font")
	}
}

func TestBuildCSSRejectsNonFontContent(t *testing.T) {
	// расширение шрифтовое, но внутри не шрифт (например, exe или конфиг)
	read := func(string) ([]byte, error) { return []byte("MZ\x90\x00 definitely not a font"), nil }
	css := BuildCSS(config.UI{FontFile: "C:\\fonts\\fake.ttf"}, read)
	if strings.Contains(css, "@font-face") {
		t.Fatalf("file without a font signature must be rejected:\n%s", css)
	}
	if !strings.Contains(css, "Bahnschrift") {
		t.Fatal("must fall back to the default font")
	}
}

func TestBuildCSSRejectsNonFontExtension(t *testing.T) {
	// сигнатура подходящая, но расширение чужое: путь в конфиге не должен
	// позволять утащить в страницу произвольный файл
	read := func(string) ([]byte, error) { return []byte("wOF2 + payload"), nil }
	css := BuildCSS(config.UI{FontFile: "C:\\secrets\\config.yaml"}, read)
	if strings.Contains(css, "@font-face") {
		t.Fatalf("non-font extension must be rejected:\n%s", css)
	}
}

func TestBuildCSSAcceptsRealWOFF2(t *testing.T) {
	// настоящий файл на диске (t.TempDir) и настоящий os.ReadFile (read=nil)
	p := filepath.Join(t.TempDir(), "font.woff2")
	payload := append([]byte("wOF2"), 0x00, 0x01, 0x02, 0x03)
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	css := BuildCSS(config.UI{FontFile: p}, nil)
	if !strings.Contains(css, "@font-face") {
		t.Fatalf("real woff2 file must produce @font-face:\n%s", css)
	}
	if !strings.Contains(css, "font/woff2") {
		t.Errorf("MIME must match woff2:\n%s", css)
	}
}

func TestBuildCSSEscapesFamilyName(t *testing.T) {
	css := BuildCSS(config.UI{FontHUD: `Evil'},body{background:url('x`}, nil)
	if strings.Contains(css, "'Evil'}") {
		t.Fatalf("quote in family name must be escaped:\n%s", css)
	}
	if !strings.Contains(css, `Evil\'`) {
		t.Errorf("escaped quote expected in output:\n%s", css)
	}
	css = BuildCSS(config.UI{FontMono: `Back\slash`}, nil)
	if !strings.Contains(css, `Back\\slash`) {
		t.Errorf("backslash in family name must be escaped:\n%s", css)
	}
}

func TestScaleFor(t *testing.T) {
	if ScaleFor("s") != 1.0 {
		t.Errorf("s = %v, want 1.0", ScaleFor("s"))
	}
	if ScaleFor("XL") != 1.5 {
		t.Errorf("XL (uppercase) = %v, want 1.5", ScaleFor("XL"))
	}
	if ScaleFor("") != Scales[DefaultScale] {
		t.Errorf("empty must fall back to default")
	}
	if ScaleFor("garbage") != Scales[DefaultScale] {
		t.Errorf("unknown key must fall back to default")
	}
	// каждый следующий размер строго больше предыдущего
	prev := 0.0
	for _, k := range []string{"s", "m", "l", "xl"} {
		if Scales[k] <= prev {
			t.Fatalf("scales must increase: %s = %v after %v", k, Scales[k], prev)
		}
		prev = Scales[k]
	}
}

func TestBuildCSSZoom(t *testing.T) {
	css := BuildCSS(config.UI{Scale: "xl"}, nil)
	if !strings.Contains(css, "zoom:1.5") {
		t.Fatalf("xl scale must emit zoom:1.5:\n%s", css)
	}
	// дефолт тоже задаёт zoom, иначе размер не восстановится после сброса
	if !strings.Contains(BuildCSS(config.UI{}, nil), "zoom:") {
		t.Fatal("default must still emit a zoom rule")
	}
}

func TestTrimStyles(t *testing.T) {
	cases := map[string]string{
		"Arial":                          "Arial",
		"Arial Narrow":                   "Arial Narrow", // ширина — часть имени семейства
		"Arial Narrow Полужирный Курсив": "Arial Narrow",
		"Consolas Bold":                  "Consolas",
		"Times New Roman Italic":         "Times New Roman",
		"Bahnschrift SemiBold Condensed": "Bahnschrift SemiBold Condensed",
		"Bold":                           "Bold", // одно слово не срезаем — иначе останется пусто
	}
	for in, want := range cases {
		if got := trimStyles(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestFontMIME(t *testing.T) {
	cases := map[string]string{
		"a.ttf": "font/ttf", "b.OTF": "font/otf",
		"c.woff": "font/woff", "d.woff2": "font/woff2", "e.xyz": "font/ttf",
	}
	for path, want := range cases {
		if got := fontMIME(path); got != want {
			t.Errorf("%s: got %s, want %s", path, got, want)
		}
	}
}
