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
	records, err := loadRecords()
	if err != nil {
		return err
	}
	records = append([]Record{rec}, records...)
	sort.SliceStable(records, func(i, j int) bool { return records[i].At.After(records[j].At) })
	if keep > 0 && len(records) > keep {
		records = records[:keep]
	}

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
	return os.WriteFile(p, []byte(sb.String()), 0o644)
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

	summary := strings.Join(r.Verdict.Lines, " ")
	if len(broken) > 0 {
		label := "блокировки"
		if l == i18n.EN {
			label = "blocked"
		}
		summary = label + ": " + strings.Join(broken, ", ")
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
