// Package history хранит краткие итоги прогонов в %APPDATA%\netcheck\runs.jsonl.
package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mihey/netcheck/internal/config"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
	"github.com/mihey/netcheck/internal/runner"
)

const fileName = "runs.jsonl"

// Entry — строка списка прогонов (без деталей, чтобы UI грузился быстро).
type Entry struct {
	At       time.Time     `json:"at"`
	Status   probe.Status  `json:"status"`
	Summary  string        `json:"summary"`
	Duration time.Duration `json:"duration"`
}

// Record — то, что реально лежит в файле: строка списка плюс полный отчёт,
// чтобы прошлый прогон можно было открыть после перезапуска.
type Record struct {
	Entry
	Report *runner.Report `json:"report,omitempty"`
}

func path() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fileName), nil
}

// Append дописывает запись и оставляет keep самых свежих.
func Append(rec Record, keep int) error {
	mu.Lock()
	defer mu.Unlock()

	records, err := loadRecords()
	if err != nil {
		return err
	}
	records = append([]Record{rec}, records...)
	sort.SliceStable(records, func(i, j int) bool { return records[i].At.After(records[j].At) })
	if keep > 0 && len(records) > keep {
		records = records[:keep]
	}
	return writeRecords(records)
}

// Delete убирает прогоны с указанным временем (RFC3339). Неизвестное время
// молча игнорируется: удалять уже удалённое — не ошибка.
func Delete(ats []string) error {
	if len(ats) == 0 {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()

	want := make(map[int64]bool, len(ats))
	for _, s := range ats {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			want[t.UnixNano()] = true
		}
	}
	records, err := loadRecords()
	if err != nil {
		return err
	}
	kept := records[:0]
	for _, r := range records {
		if !want[r.At.UnixNano()] {
			kept = append(kept, r)
		}
	}
	return writeRecords(kept)
}

// Clear стирает историю целиком вместе с сохранёнными отчётами.
func Clear() error {
	mu.Lock()
	defer mu.Unlock()

	p, err := path()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// mu — история читается и переписывается целиком, поэтому две операции
// одновременно затирают друг друга: удалённая запись возвращалась, а прогон,
// сохранённый параллельно с удалением, пропадал.
var mu sync.Mutex

// writeRecords перезаписывает файл целиком: формат — по строке JSON
// на прогон, дописывать частями тут нечего.
//
// Пишем во временный файл рядом и переименовываем поверх. Прямая запись
// сначала обнуляла файл и только потом заполняла его заново: выключение
// питания в этот момент стоило бы не одной записи, а всей истории.
func writeRecords(records []Record) error {
	p, err := path()
	if err != nil {
		return err
	}
	var sb strings.Builder
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		sb.Write(raw)
		sb.WriteByte('\n')
	}

	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadLocalized — список прогонов с итогами, пересобранными на языке lang.
// Для записей без сохранённого отчёта (старый формат) остаётся исходный текст.
func LoadLocalized(l i18n.Lang) ([]Entry, error) {
	records, err := loadRecords()
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(records))
	for _, r := range records {
		e := r.Entry
		if r.Report != nil {
			e.Summary = Summarize(runner.Relocalize(*r.Report, l), l).Summary
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ReportAt возвращает полный отчёт прогона по его времени (RFC3339).
// nil — если такого прогона нет или он записан старой версией без отчёта.
func ReportAt(at string) *runner.Report {
	want, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil
	}
	records, err := loadRecords()
	if err != nil {
		return nil
	}
	for _, r := range records {
		if r.At.Equal(want) {
			return r.Report
		}
	}
	return nil
}

// Load возвращает строки списка, свежие первыми (без отчётов).
// Отсутствие файла — не ошибка.
func Load() ([]Entry, error) {
	records, err := loadRecords()
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(records))
	for _, r := range records {
		entries = append(entries, r.Entry)
	}
	return entries, nil
}

func loadRecords() ([]Record, error) {
	p, err := path()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []Record
	sc := bufio.NewScanner(f)
	// строка с полным отчётом крупнее прежней однострочной сводки
	sc.Buffer(make([]byte, 0, 256*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue // битую строку пропускаем, историю не роняем
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].At.After(records[j].At) })
	return records, nil
}

// Summarize — однострочный итог прогона: худший статус слоёв плюс список
// проблемных сервисов.
func Summarize(r runner.Report, l i18n.Lang) Entry {
	worst := probe.StatusOK
	for _, layer := range r.Layers {
		switch layer.Status {
		case probe.StatusFail:
			worst = probe.StatusFail
		case probe.StatusWarn:
			if worst == probe.StatusOK {
				worst = probe.StatusWarn
			}
		}
	}

	var broken []string
	for _, s := range r.Services {
		if !s.DirectOK {
			broken = append(broken, s.Host)
		}
	}

	// Сводка — первая строка вердикта, а не список упавших сервисов вместо неё.
	// Раньше прогон без интернета подписывался «блокировки: youtube.com, …»,
	// хотя никаких блокировок никто не измерял: измерять было нечем.
	summary := ""
	if len(r.Verdict.Lines) > 0 {
		summary = r.Verdict.Lines[0]
	}
	if len(broken) > 0 {
		label := "не открываются"
		if l == i18n.EN {
			label = "down"
		}
		tail := label + ": " + strings.Join(broken, ", ")
		if summary == "" {
			summary = tail
		} else {
			summary += " " + tail
		}
	}
	if summary == "" {
		summary = string(worst)
	}

	at := r.StartedAt
	if at.IsZero() {
		at = time.Now()
	}
	return Entry{At: at, Status: worst, Summary: summary, Duration: r.Duration}
}
