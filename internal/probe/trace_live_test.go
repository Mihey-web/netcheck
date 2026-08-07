//go:build live

package probe

import (
	"context"
	"testing"
	"time"
)

// Живая проверка трассировки: раскладка структур WinAPI — это ровно то место,
// где ошибка не видна ни компилятору, ни табличным тестам, а проявляется
// мусором в адресах. Запуск: go test -tags live -run TestLiveTrace -v ./internal/probe/
func TestLiveTrace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, target := range []string{"1.1.1.1", "8.8.8.8"} {
		t.Run(target, func(t *testing.T) {
			start := time.Now()
			hops, err := Trace(ctx, target)
			if err != nil {
				t.Fatalf("Trace: %v", err)
			}
			t.Logf("%s: %d шагов за %v", target, len(hops), time.Since(start).Round(time.Millisecond))
			for _, h := range hops {
				fork := ""
				if h.Ambiguous {
					fork = "  ← развилка"
				}
				t.Logf("  %2d  %-16s %5d мс  %-11s %-45s%s%s",
					h.N, h.IP, h.RTTms, h.Status, h.Host, h.Detail, fork)
			}

			if len(hops) == 0 {
				t.Fatal("маршрут пуст — не ответил вообще никто")
			}
			// Первый шаг — домашний роутер. Если он не ответил, проверять
			// дальше нечего: либо сети нет, либо трассировка не работает.
			if !hops[0].Responded() {
				t.Error("первый шаг молчит — до роутера трассировка не дошла")
			}
			last, ok := LastResponding(hops)
			if !ok {
				t.Fatal("ни одного ответившего шага")
			}
			t.Logf("  последний ответивший: %s (шаг %d), цель достигнута: %v",
				last.IP, last.N, Reached(hops))

			// Публичные резолверы отвечают на ICMP всегда. Если сюда мы
			// не дошли, значит сломана либо сеть, либо сама трассировка.
			if !Reached(hops) {
				t.Errorf("до %s не дошли — обрыв на %s (шаг %d)", target, last.IP, last.N)
			}
			// Параллельный опрос обязан укладываться в один таймаут,
			// а не в двадцать подряд.
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("трассировка заняла %v — похоже, шаги идут по очереди", d)
			}
		})
	}
}
