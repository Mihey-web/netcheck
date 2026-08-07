package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withInnertube подменяет эндпоинт Innertube на локальный сервер.
func withInnertube(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := innertubeURL
	innertubeURL = srv.URL
	t.Cleanup(func() { innertubeURL = old })
}

func TestYouTubeSpeedURLPicksHeaviestDirect(t *testing.T) {
	withInnertube(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Innertube ждёт POST, пришёл %s", r.Method)
		}
		fmt.Fprint(w, `{
			"playabilityStatus": {"status": "OK"},
			"streamingData": {
				"adaptiveFormats": [
					{"url": "https://video.example/light", "bitrate": 100},
					{"signatureCipher": "s=...", "bitrate": 9000},
					{"url": "https://video.example/heavy", "bitrate": 5000}
				],
				"formats": [{"url": "https://video.example/muxed", "bitrate": 700}]
			}
		}`)
	})
	got, err := YouTubeSpeedURL(context.Background(), nil)
	if err != nil {
		t.Fatalf("не добыли URL: %v", err)
	}
	// подписанный формат с самым толстым битрейтом должен быть пропущен
	if got != "https://video.example/heavy" {
		t.Errorf("got %q, want самый тяжёлый из прямых", got)
	}
}

// Все ссылки подписаны — честная ошибка, а не пустой URL.
func TestYouTubeSpeedURLAllSigned(t *testing.T) {
	withInnertube(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"playabilityStatus": {"status": "OK"},
			"streamingData": {"adaptiveFormats": [{"signatureCipher": "s=...", "bitrate": 1}]}
		}`)
	})
	if got, err := YouTubeSpeedURL(context.Background(), nil); err == nil {
		t.Errorf("подписанные ссылки обязаны дать ошибку, а не %q", got)
	}
}

// Видео недоступно (LOGIN_REQUIRED и прочее) — ошибка с причиной.
func TestYouTubeSpeedURLUnplayable(t *testing.T) {
	withInnertube(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"playabilityStatus": {"status": "LOGIN_REQUIRED", "reason": "Sign in"}}`)
	})
	_, err := YouTubeSpeedURL(context.Background(), nil)
	if err == nil {
		t.Fatal("недоступное видео обязано дать ошибку")
	}
	if !strings.Contains(err.Error(), "LOGIN_REQUIRED") {
		t.Errorf("в ошибке нет причины: %v", err)
	}
}

func TestYouTubeSpeedURLHTTPError(t *testing.T) {
	withInnertube(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	})
	if _, err := YouTubeSpeedURL(context.Background(), nil); err == nil {
		t.Fatal("HTTP-ошибка Innertube обязана дать ошибку")
	}
}
