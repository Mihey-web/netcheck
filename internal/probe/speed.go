package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Параметры замера скорости (спека «Сервисо-центричная выдача», §4):
// качаем до speedMaxBytes или speedMaxTime — что наступит раньше.
// Первые speedWarmup байт в расчёт не идут: TCP slow start и burst до
// срабатывания шейпера завышали бы скорость задушенного канала — ТСПУ
// пропускает первые сотни килобайт на полной скорости и лишь потом душит.
const (
	speedMaxBytes = 5 << 20 // 5 МБ — хватает для оценки и не съедает трафик
	speedMaxTime  = 8 * time.Second
	speedWarmup   = 256 << 10
)

// MeasureSpeed скачивает rawURL и возвращает скорость в Мбит/с.
// proxy == nil — напрямую, иначе через прокси (socks5:// и http:// понимает
// сам http.Transport). Уважает ctx: закрытие приложения обрывает замер
// с ошибкой, а не держит соединение до конца бюджета.
func MeasureSpeed(ctx context.Context, rawURL string, proxy *url.URL) (float64, error) {
	// свой бюджет времени поверх внешнего ctx: 8 с — штатный конец замера,
	// а отмена родителя — обрыв, и различать их надо по обоим контекстам
	mctx, cancel := context.WithTimeout(ctx, speedMaxTime)
	defer cancel()

	tr := &http.Transport{DisableKeepAlives: true}
	// Transport на каждый вызов, как в HTTPGet: соединение не должно
	// доживать до следующего замера и делить с ним канал.
	defer tr.CloseIdleConnections()
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	req, err := http.NewRequestWithContext(mctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", BrowserUA)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("http %d", resp.StatusCode)
	}

	buf := make([]byte, 64<<10)
	var total, measured int64
	var start time.Time // отсчёт времени начинается после разгона
	for total < speedMaxBytes {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
			switch {
			case !start.IsZero():
				measured += int64(n)
			case total >= speedWarmup:
				// Разгон кончился где-то внутри этого куска. Его хвост
				// в замер не идёт: он уже пришёл, и засчитать его с этой
				// секунды значило бы посчитать байты бесплатными по времени.
				start = time.Now()
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break // файл кончился — штатный конец
			}
			// Вышел наш бюджет времени — тоже штатный конец: считаем по тому,
			// что успело прийти. Отмена внешнего ctx — уже обрыв.
			if mctx.Err() != nil && ctx.Err() == nil {
				break
			}
			return 0, rerr
		}
	}

	// За весь бюджет не пришло даже разгонных 256 КБ — по такому замеру
	// скорость не считается. Честная ошибка, а не выдуманная цифра.
	if start.IsZero() || measured == 0 {
		return 0, errors.New("ответ короче разгонных 256 КБ — скорость не посчитать")
	}
	elapsed := time.Since(start)
	if elapsed <= 0 {
		elapsed = time.Millisecond // всё пришло мгновенно из буферов
	}
	return float64(measured) * 8 / elapsed.Seconds() / 1e6, nil
}
