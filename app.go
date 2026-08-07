package main

import (
	"context"
	"sync"
	"sync/atomic"
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
	// busy — прогон уже идёт. Защита во фронте есть, но она снимается
	// перезагрузкой страницы, а два прогона разом смешали бы события
	// в одной таблице и потеряли бы одну из двух записей истории.
	busy atomic.Bool
	// cancelRun — отмена текущего прогона. Под мьютексом: ставится из
	// RunCheck, дёргается из CancelCheck — это разные вызовы биндингов.
	cancelMu  sync.Mutex
	cancelRun context.CancelFunc
	// cfgMu сериализует read-modify-write конфига: SetTab и SetServices из
	// параллельных вызовов биндингов иначе затирали бы правки друг друга.
	cfgMu sync.Mutex
	// emit — отправка события фронту. Поле, а не прямой вызов, чтобы тесты
	// могли перехватывать события без Wails-рантайма.
	emit func(name string, data ...interface{})
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// event шлёт событие фронту; без Wails-контекста молчит.
func (a *App) event(name string, data ...interface{}) {
	if a.emit != nil {
		a.emit(name, data...)
		return
	}
	if a.ctx != nil {
		wr.EventsEmit(a.ctx, name, data...)
	}
}

// RunCheck — полный прогон. Прогресс по слоям уходит событием "progress",
// итог — событием "done": перезагруженная посреди прогона страница теряет
// промис RunCheck навсегда, и без события она не дожила бы до отчёта.
func (a *App) RunCheck() runner.Report {
	if !a.busy.CompareAndSwap(false, true) {
		// Прогон уже идёт. Молчаливый пустой Report выглядел во фронте как
		// «проверка мгновенно закончилась ничем» — теперь об этом сказано.
		a.event("run-busy")
		return runner.Report{}
	}
	defer a.busy.Store(false)

	cfg, err := config.Load()
	if err != nil {
		// Битый конфиг молча подменялся дефолтом; пользователь должен знать,
		// что прогон идёт не с его настройками.
		a.event("config-error", err.Error())
	}
	lang := i18n.Resolve(cfg.Lang)

	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	a.cancelMu.Lock()
	a.cancelRun = cancel
	a.cancelMu.Unlock()
	defer func() {
		a.cancelMu.Lock()
		a.cancelRun = nil
		a.cancelMu.Unlock()
		cancel()
	}()

	snap := env.Detect(runCtx, cfg.ProxyPorts)
	a.event("env", snap)

	rep := runner.Run(runCtx, cfg, lang, runner.Live{}, snap, func(p runner.Progress) {
		a.event("progress", p)
	})

	// Отменённый прогон в историю не пишем: его замеры — таймауты умершего
	// контекста, и запись «Интернета нет» рядом с честными была бы враньём.
	if shouldRecord(runCtx, rep) {
		// Не сохранилось — надо сказать. Молча потерянный прогон после
		// перезапуска выглядит как «результат исчез сам».
		if err := history.Append(
			history.Record{Entry: history.Summarize(rep, lang), Report: &rep},
			cfg.HistoryKeep,
		); err != nil {
			a.event("hist-error", err.Error())
		}
	}
	a.event("done", rep)
	return rep
}

// shouldRecord — писать ли прогон в историю: отменённый не пишем.
func shouldRecord(ctx context.Context, rep runner.Report) bool {
	return !rep.Canceled && ctx.Err() == nil
}

// CancelCheck прерывает текущий прогон; без прогона ничего не делает.
// Итог всё равно придёт событием "done" — уже с пометкой Canceled.
func (a *App) CancelCheck() {
	a.cancelMu.Lock()
	if a.cancelRun != nil {
		a.cancelRun()
	}
	a.cancelMu.Unlock()
}

func (a *App) GetHistory() []history.Entry {
	entries, err := history.LoadLocalized(a.lang())
	if err != nil {
		return nil
	}
	return entries
}

// DeleteRuns убирает из истории выбранные прогоны (время в RFC3339).
func (a *App) DeleteRuns(ats []string) error { return history.Delete(ats) }

// ClearHistory стирает историю прогонов целиком.
func (a *App) ClearHistory() error { return history.Clear() }

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

func (a *App) SaveConfig(c config.Config) error {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	return c.Save()
}

// SetTab запоминает открытую вкладку, чтобы программа поднималась там же,
// где её закрыли.
func (a *App) SetTab(tab string) error {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
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
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	// Конфиг не прочитался — не сохраняем поверх него дефолты: так первое же
	// изменение галочки стирало выбор целей, который ещё можно было починить
	// руками. Load уже отложил битый файл в сторону, и следующая попытка
	// пройдёт по чистому.
	cfg, err := config.Load()
	if err != nil {
		return err
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
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Lang = l
	return cfg.Save()
}

// Version — версия сборки для шапки окна.
func (a *App) Version() string { return version }
