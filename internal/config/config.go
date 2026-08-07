// Package config — конфиг netcheck в %APPDATA%\netcheck\config.yaml.
// При первом запуске создаётся файл с дефолтами.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/mihey/netcheck/internal/catalog"
	"gopkg.in/yaml.v3"
)

// mu — как в history: операции над файлом конфига не пересекаются.
// Две параллельные Save рвали бы rename друг другу, а Load, попавший
// между временным файлом и rename, на Windows получает Access denied —
// файл, открытый на чтение, не даёт себя заменить.
var mu sync.Mutex

type Targets struct {
	Runet   []string `yaml:"runet"`
	Global  []string `yaml:"global"`
	Blocked []string `yaml:"blocked"`
	// GeoBlocked — сервисы, которые закрывают доступ сами по стране IP.
	// Их лечит не любой VPN, а только выход в подходящей стране, поэтому
	// диагноз для них отдельный.
	GeoBlocked []string `yaml:"geoblocked"`
}

// UI — внешний вид. Пустые значения означают «взять дефолтный шрифт».
// FontFile позволяет подключить произвольный .ttf/.otf с диска, не устанавливая
// его в систему (файл встраивается в CSS как data-URL).
type UI struct {
	FontHUD  string `yaml:"font_hud"`
	FontMono string `yaml:"font_mono"`
	FontFile string `yaml:"font_file"`
	// Scale — размер интерфейса: s|m|l|xl. Пусто = m.
	Scale string `yaml:"scale"`
	// Tab — вкладка, на которой закрыли программу: report|services|map.
	// Открывать всегда «Отчёт» неудобно тому, кто пришёл править список целей.
	Tab string `yaml:"tab"`
}

// Selection — что именно проверять. Хранится идентификаторами справочника,
// а не хостами: хосты сервисов меняются между релизами, идентификаторы нет.
type Selection struct {
	Enabled []string         `yaml:"enabled"`
	Custom  []catalog.Custom `yaml:"custom,omitempty"`
}

type Config struct {
	Lang     string    `yaml:"lang"` // auto|ru|en
	UI       UI        `yaml:"ui"`
	Services Selection `yaml:"services"`
	// Targets — производное от Services: раскладка по группам для прогона.
	// В файл не пишется, чтобы не заводить второй источник правды,
	// но уезжает во фронт вместе с конфигом.
	Targets Targets `yaml:"-"`
	Ping    struct {
		Gateway  bool   `yaml:"gateway"`
		GlobalIP string `yaml:"global_ip"`
	} `yaml:"ping"`
	ProxyPorts []int `yaml:"proxy_ports"`
	// Map — карта досягаемости регионов.
	Map struct {
		Enabled bool `yaml:"enabled"`
		// Style — вид карты: globe|countries|dots.
		Style string `yaml:"style"`
		// Spin — авто-вращение глобуса.
		Spin bool `yaml:"spin"`
		// GeoLookup спрашивает у внешнего сервиса, из какой страны ты виден.
		// Выключено по умолчанию: это единственное место, где netcheck
		// сообщает наружу что-то о тебе (твой IP).
		GeoLookup bool `yaml:"geo_lookup"`
	} `yaml:"map"`
	Timeouts   struct {
		ProbeMs int `yaml:"probe_ms"`
		RunMs   int `yaml:"run_ms"`
	} `yaml:"timeouts"`
	HistoryKeep int `yaml:"history_keep"`
}

func Default() Config {
	var c Config
	c.Lang = "auto"
	// «Стандартный» набор, а не весь справочник: прогон растёт линейно
	// по числу целей, и полсотни проверок с порога никому не нужны.
	c.Services.Enabled = append([]string{}, catalog.Presets["standard"]...)
	c.resolveTargets()
	c.UI.Scale = "m"
	c.Map.Enabled = true
	c.Map.Style = "globe"
	c.Map.Spin = true
	c.Map.GeoLookup = false
	c.Ping.Gateway = true
	c.Ping.GlobalIP = "1.1.1.1"
	c.ProxyPorts = []int{10808, 10809, 2080, 2081, 7890, 7897, 1080}
	c.Timeouts.ProbeMs = 3000
	c.Timeouts.RunMs = 20000
	c.HistoryKeep = 100
	return c
}

// Dir — %APPDATA%\netcheck, создаётся при необходимости.
func Dir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", err
		}
	}
	dir := filepath.Join(base, "netcheck")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Load читает конфиг; если файла нет — пишет дефолт и возвращает его.
func Load() (Config, error) {
	mu.Lock()
	defer mu.Unlock()
	p, err := path()
	if err != nil {
		return Default(), err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		c := Default()
		return c, c.save()
	}
	if err != nil {
		return Default(), err
	}
	c := Default() // недостающие поля остаются дефолтными
	if err := yaml.Unmarshal(raw, &c); err != nil {
		// Файл цел, но не разбирается — хватит одной лишней табуляции.
		// Откладываем его в сторону под своим именем: иначе первое же
		// переключение языка сохранит поверх дефолты, и выбор целей,
		// который можно было починить руками, пропадёт навсегда.
		os.Rename(p, p+".broken")
		d := Default()
		d.resolveTargets()
		return d, err
	}
	c.migrate(raw)
	c.resolveTargets()
	c.clampTimeouts()
	return c, nil
}

// clampTimeouts защищает от значений, при которых прогон бессмысленен:
// probe_ms: 0 в файле означал уже истёкший контекст на каждую пробу,
// то есть мгновенный отказ по всем проверкам без единого отправленного пакета.
func (c *Config) clampTimeouts() {
	d := Default()
	clamp := func(v *int, min, max, def int) {
		switch {
		case *v == 0:
			*v = def
		case *v < min:
			*v = min
		case *v > max:
			*v = max
		}
	}
	clamp(&c.Timeouts.ProbeMs, 500, 30000, d.Timeouts.ProbeMs)
	clamp(&c.Timeouts.RunMs, 5000, 120000, d.Timeouts.RunMs)
}

// resolveTargets раскладывает выбранные сервисы по группам прогона.
func (c *Config) resolveTargets() {
	r, g, b, geo := catalog.Resolve(c.Services.Enabled, c.Services.Custom)
	c.Targets = Targets{Runet: r, Global: g, Blocked: b, GeoBlocked: geo}
}

// migrate переносит конфиг доисторической версии, где цели хранились
// списками хостов. Хост из справочника становится идентификатором, чужой —
// пользовательской целью: ничего из выбранного пользователем не теряется.
func (c *Config) migrate(raw []byte) {
	var old struct {
		Services *Selection `yaml:"services"`
		Targets  *Targets   `yaml:"targets"`
	}
	if err := yaml.Unmarshal(raw, &old); err != nil {
		return
	}
	if old.Services != nil || old.Targets == nil {
		return // конфиг уже новый — трогать нечего
	}
	var sel Selection
	move := func(hosts []string, group string) {
		for _, h := range hosts {
			if id, ok := catalog.IDForHost(h); ok {
				sel.Enabled = append(sel.Enabled, id)
			} else {
				sel.Custom = append(sel.Custom, catalog.Custom{Host: h, Group: group})
			}
		}
	}
	move(old.Targets.Runet, catalog.GroupRunet)
	move(old.Targets.Global, catalog.GroupGlobal)
	move(old.Targets.Blocked, catalog.GroupBlock)
	move(old.Targets.GeoBlocked, catalog.GroupGeo)
	c.Services = sel
}

func (c Config) Save() error {
	mu.Lock()
	defer mu.Unlock()
	return c.save()
}

// save — запись без блокировки: для вызова из-под уже взятого mu.
func (c Config) save() error {
	p, err := path()
	if err != nil {
		return err
	}
	raw, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	// Пишем во временный файл рядом и переименовываем поверх (как в history):
	// прямая запись сначала обнуляла файл и только потом заполняла заново,
	// и выключение питания в этот момент оставляло пустой конфиг вместо настроек.
	tmp := p + ".tmp"
	// 0600: конфиг — личные настройки пользователя, другим учёткам он ни к чему.
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
