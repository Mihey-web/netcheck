//go:build live

// Живой тест Innertube: go test -tags live -run TestLiveYouTubeSpeed -v ./internal/probe
// Ходит в настоящий YouTube — обычные прогоны его не трогают. Необязателен:
// сам механизм best-effort, и падение здесь означает «YouTube поменял API»,
// а не сломанный код.
package probe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLiveYouTubeSpeed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	u, err := YouTubeSpeedURL(ctx, nil)
	if err != nil {
		t.Fatalf("Innertube не отдал прямой URL: %v", err)
	}
	if !strings.Contains(u, "googlevideo.com") {
		t.Logf("неожиданный хост сегмента: %s", u)
	}
	mbps, err := MeasureSpeed(ctx, u, nil)
	if err != nil {
		t.Fatalf("замер по добытому URL упал: %v", err)
	}
	t.Logf("скорость YouTube: %.2f Мбит/с", mbps)
	if mbps <= 0 {
		t.Error("скорость обязана быть положительной")
	}
}
