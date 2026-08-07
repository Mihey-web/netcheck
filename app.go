package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mihey/netcheck/internal/catalog"
	"github.com/mihey/netcheck/internal/config"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/fonts"
	"github.com/mihey/netcheck/internal/history"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
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
	// prober — сетевые операции прогона. Поле по той же причине, что emit:
	// тесты подменяют его фейком и гоняют RunSingle без выхода в сеть.
	prober runner.Prober
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
	return a.runFlow(nil, true, "done")
}

// refConnectivityHost — эталон связности для точечного прогона: без него
// «сайт не открылся» неотличимо от «интернета нет вообще».
const refConnectivityHost = "cloudflare.com"

// RunSingle — точечный вопрос «работает ли этот сайт»: базовые слои
// (шлюз, DNS, эталон связности) плюс одна цель host в группе blocked.
// Busy-флаг общий с RunCheck — два прогона разом делили бы сеть и таймауты.
// В историю НЕ пишется: это вопрос про один сайт, а не срез сети.
// Итог, помимо возврата, уходит событием "single-done" — не "done",
// чтобы точечный ответ не подменял собой главный отчёт.
func (a *App) RunSingle(host string) (runner.Report, error) {
	h, err := normalizeHost(host)
	if err != nil {
		return runner.Report{}, err
	}
	return a.runFlow(func(cfg *config.Config) {
		cfg.Targets = config.Targets{
			Global:  []string{refConnectivityHost},
			Blocked: []string{h},
		}
		cfg.Map.Enabled = false // точечному вопросу карта не нужна
	}, false, "single-done"), nil
}

// hostRe — та же грубая проверка, что hostOk во фронте: латиница/цифры,
// точки и дефисы, метка не начинается и не кончается дефисом.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// normalizeHost отрезает схему, путь и хвостовую точку и проверяет остаток.
// Фронт валидирует то же самое до вызова, но биндинг не должен верить фронту.
func normalizeHost(raw string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || !hostRe.MatchString(h) {
		return "", fmt.Errorf("некорректное имя хоста: %q", raw)
	}
	return h, nil
}

// runFlow — общий каркас RunCheck и RunSingle: busy, отмена, снимок
// окружения, прогон, события. tune правит конфиг под точечный прогон,
// record решает про историю, doneEvent — каким событием отдать итог.
func (a *App) runFlow(tune func(*config.Config), record bool, doneEvent string) runner.Report {
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
	if tune != nil {
		tune(&cfg)
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

	p := a.prober
	if p == nil {
		p = runner.Live{}
	}
	rep := runner.Run(runCtx, cfg, lang, p, snap, func(pr runner.Progress) {
		a.event("progress", pr)
	})

	// Отменённый прогон в историю не пишем: его замеры — таймауты умершего
	// контекста, и запись «Интернета нет» рядом с честными была бы враньём.
	if record && shouldRecord(runCtx, rep) {
		// Не сохранилось — надо сказать. Молча потерянный прогон после
		// перезапуска выглядит как «результат исчез сам».
		if err := history.Append(
			history.Record{Entry: history.Summarize(rep, lang), Report: &rep},
			cfg.HistoryKeep,
		); err != nil {
			a.event("hist-error", err.Error())
		}
	}
	a.event(doneEvent, rep)
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

// SpeedResult — итог замера замедления (§4 спеки «Сервисо-центричная выдача»).
type SpeedResult struct {
	ServiceMbps float64 `json:"serviceMbps"`
	RefMbps     float64 `json:"refMbps"`
	// ProxyServiceMbps — тот же файл через VPN; 0 — прокси нет или замер
	// через него не удался (вспомогательный, его неудача не роняет итог).
	ProxyServiceMbps float64 `json:"proxyServiceMbps,omitempty"`
	// Status: slow | maybe_slow | normal | error.
	Status string `json:"status"`
	Err    string `json:"err,omitempty"`
}

// MeasureSpeed — замер замедления сервиса по кнопке: эталон Cloudflare,
// затем файл сервиса (YouTube — по ссылке, добытой через Innertube),
// при живом прокси — ещё раз через него. Busy общий с прогоном: замер
// и прогон делят один канал и портили бы результаты друг друга.
// Любая неудача — честный status "error", а не «не замедлен».
func (a *App) MeasureSpeed(serviceID string) SpeedResult {
	fail := func(err error) SpeedResult {
		return SpeedResult{Status: "error", Err: err.Error()}
	}

	marker := catalog.SpeedURL(serviceID)
	if marker == "" {
		return fail(fmt.Errorf("для сервиса %q замер скорости не предусмотрен", serviceID))
	}
	if !a.busy.CompareAndSwap(false, true) {
		a.event("run-busy")
		return fail(errors.New("уже идёт прогон или замер"))
	}
	defer a.busy.Store(false)

	cfg, _ := config.Load()
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// Отмена — тем же механизмом, что у прогона: кнопка «Отменить» и
	// закрытие окна обрывают и замер тоже.
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
	proxy := runner.FirstProxyURL(snap)

	// Ссылки нужны разные для прямого замера и для замера через VPN:
	// в адрес googlevideo вшит IP того, кто его запросил, и с чужого
	// адреса сервер такую ссылку не отдаёт. Одна ссылка на оба замера
	// давала бы «через VPN тоже не качается» на ровном месте.
	svcURL, proxySvcURL := marker, marker
	if marker == catalog.SpeedURLYouTube {
		u, err := probe.YouTubeSpeedURL(runCtx, nil)
		if err == nil {
			svcURL = u
		}
		if proxy != nil {
			if pu, perr := probe.YouTubeSpeedURL(runCtx, proxy); perr == nil {
				proxySvcURL = pu
				// Сам youtube.com заблокирован — ссылку взяли через VPN,
				// но качаем по ней напрямую: именно прямой канал до CDN
				// и нужно измерить.
				if err != nil {
					svcURL, err = pu, nil
				}
			}
		}
		if err != nil {
			return fail(err)
		}
	}

	// Замеры строго по очереди: параллельные качалки делили бы канал,
	// и каждая показала бы половину настоящей скорости.
	res := SpeedResult{}
	ref, err := probe.MeasureSpeed(runCtx, catalog.RefSpeedURL, nil)
	if err != nil {
		return fail(fmt.Errorf("эталон: %w", err))
	}
	res.RefMbps = ref
	// Провал замера сервиса при живом эталоне — это не «не удалось
	// замерить», а сам ответ: данные с CDN сервиса не идут вовсе, хотя
	// канал качает. Ноль Мбит/с — честная цифра, пороги разберут её как
	// удушение. Ошибку сохраняем в Err для подсказки, статус не ломаем.
	svc, err := probe.MeasureSpeed(runCtx, svcURL, nil)
	if err != nil {
		res.Err = err.Error()
	} else {
		res.ServiceMbps = svc
	}

	if proxy != nil {
		p, perr := probe.MeasureSpeed(runCtx, proxySvcURL, proxy)
		if perr == nil {
			res.ProxyServiceMbps = p
		} else if res.Err == "" {
			// Молчать нельзя: контраст «через VPN качается, напрямую нет» —
			// главное доказательство удушения, и его отсутствие человек
			// должен видеть как факт, а не как пустое место.
			res.Err = "через VPN: " + perr.Error()
		}
	}
	res.Status = speedStatus(res.ServiceMbps, res.RefMbps, res.ProxyServiceMbps)
	return res
}

// speedStatus — пороги §4. «Замедлен» произносится, только когда сервис
// одновременно сильно отстаёт от эталона И медленен сам по себе: четверть
// от гигабитного канала — не замедление, там всё ещё сотни мегабит.
func speedStatus(service, ref, proxy float64) string {
	if ref <= 0 {
		return "error" // эталон не замерился — сравнивать не с чем
	}
	// Ноль у сервиса при живом эталоне — не ошибка замера, а его результат:
	// данные с CDN не идут вовсе. Это самое сильное удушение, какое бывает,
	// и молчать о нём («не удалось замерить») — обманывать человека.
	if service <= 0 {
		return "slow"
	}
	st := "normal"
	switch {
	case service < 0.25*ref && service < 2:
		st = "slow"
	case service < 0.5*ref:
		st = "maybe_slow"
	}
	// Через VPN тот же файл идёт в 4+ раза быстрее — душат именно прямой
	// путь, и «похоже на замедление» превращается в уверенное slow.
	if st == "maybe_slow" && proxy >= 4*service {
		st = "slow"
	}
	return st
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
