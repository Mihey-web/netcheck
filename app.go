package main

import (
	"context"
	"time"

	"github.com/mihey/netcheck/internal/catalog"
	"github.com/mihey/netcheck/internal/config"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/fonts"
	"github.com/mihey/netcheck/internal/history"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/runner"
	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App — прослойка между фронтом и ядром: грузит конфиг, гоняет прогон,
// стримит прогресс, пишет историю.
type App struct {
	ctx context.Context
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// RunCheck — полный прогон. Прогресс по слоям уходит событием "progress".
func (a *App) RunCheck() runner.Report {
	cfg, _ := config.Load() // при ошибке чтения получаем дефолт
	lang := i18n.Resolve(cfg.Lang)

	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	snap := env.Detect(ctx, cfg.ProxyPorts)
	if a.ctx != nil {
		wr.EventsEmit(a.ctx, "env", snap)
	}

	rep := runner.Run(ctx, cfg, lang, runner.Live{}, snap, func(p runner.Progress) {
		if a.ctx != nil {
			wr.EventsEmit(a.ctx, "progress", p)
		}
	})

	history.Append(history.Record{Entry: history.Summarize(rep, lang), Report: &rep}, cfg.HistoryKeep)
	return rep
}

func (a *App) GetHistory() []history.Entry {
	entries, err := history.LoadLocalized(a.lang())
	if err != nil {
		return nil
	}
	return entries
}

// GetRun — полный отчёт прошлого прогона по времени (RFC3339), с вердиктом на
// текущем языке. Пустой at — самый свежий прогон. Так результат виден сразу
// после запуска приложения, а не только до его закрытия.
func (a *App) GetRun(at string) *runner.Report {
	if at == "" {
		entries, err := history.Load()
		if err != nil || len(entries) == 0 {
			return nil
		}
		at = entries[0].At.Format(time.RFC3339Nano)
	}
	rep := history.ReportAt(at)
	if rep == nil {
		return nil
	}
	loc := runner.Relocalize(*rep, a.lang())
	return &loc
}

func (a *App) lang() i18n.Lang {
	cfg, _ := config.Load()
	return i18n.Resolve(cfg.Lang)
}

func (a *App) GetConfig() config.Config {
	cfg, _ := config.Load()
	return cfg
}

func (a *App) SaveConfig(c config.Config) error { return c.Save() }

// SetTab запоминает открытую вкладку, чтобы программа поднималась там же,
// где её закрыли.
func (a *App) SetTab(tab string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.UI.Tab == tab {
		return nil // не трогаем файл на каждое переключение
	}
	cfg.UI.Tab = tab
	return cfg.Save()
}

// Catalog — справочник проверяемых сервисов на текущем языке.
func (a *App) Catalog() []catalog.Item { return catalog.Localized(string(a.lang())) }

// Presets — готовые наборы: имя набора → идентификаторы сервисов.
func (a *App) Presets() map[string][]string { return catalog.Presets }

// SetServices сохраняет выбор целей. Отдельно от SaveConfig: вкладка
// «Сервисы» правит только выбор и не должна тащить с собой весь конфиг,
// который мог измениться в другом месте.
func (a *App) SetServices(enabled []string, custom []catalog.Custom) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}
	if enabled == nil {
		enabled = []string{} // «ничего не выбрано» — это выбор, а не отсутствие настройки
	}
	cfg.Services.Enabled = enabled
	cfg.Services.Custom = custom
	return cfg.Save()
}

// ListFonts — установленные в системе семейства шрифтов для выпадающего списка
// в настройках.
func (a *App) ListFonts() []string { return fonts.List() }

// FontCSS — готовая таблица стилей со шрифтами и масштабом интерфейса
// (включая встроенный файл, если он выбран). Фронт просто кладёт её в <style>.
func (a *App) FontCSS() string {
	cfg, _ := config.Load()
	return fonts.BuildCSS(cfg.UI, nil)
}

// базовые размеры вёрстки при масштабе 1.0
const (
	baseMinW = 900
	baseMinH = 620
)

// ApplyWindowScale подгоняет окно под выбранный масштаб: вёрстка задана в px,
// поэтому при zoom>1 ей нужно пропорционально больше места, иначе контент
// обрежется (у body overflow:hidden).
func (a *App) ApplyWindowScale() {
	if a.ctx == nil {
		return
	}
	cfg, _ := config.Load()
	s := fonts.ScaleFor(cfg.UI.Scale)
	minW, minH := int(float64(baseMinW)*s), int(float64(baseMinH)*s)

	wr.WindowSetMinSize(a.ctx, minW, minH)
	if w, h := wr.WindowGetSize(a.ctx); w < minW || h < minH {
		wr.WindowSetSize(a.ctx, max(w, minW), max(h, minH))
	}
}

// CurrentLang — язык, на котором сейчас говорит бэкенд ("ru"|"en").
func (a *App) CurrentLang() string {
	cfg, _ := config.Load()
	return string(i18n.Resolve(cfg.Lang))
}

func (a *App) SetLang(l string) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.Default()
	}
	cfg.Lang = l
	return cfg.Save()
}

// Version — версия сборки для шапки окна.
func (a *App) Version() string { return version }
