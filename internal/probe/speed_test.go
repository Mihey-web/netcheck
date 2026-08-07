package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// throttledHandler отдаёт warmup байт сразу (разгон, который замер обязан
// отбросить), а дальше — кусками chunk каждые step, всего body байт.
// Так httptest-сервер изображает канал с искусственным лимитом скорости.
func throttledHandler(warmup, body, chunk int, step time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(warmup+body))
		fl, _ := w.(http.Flusher)
		w.Write(make([]byte, warmup))
		if fl != nil {
			fl.Flush()
		}
		sent := 0
		for sent < body {
			n := chunk
			if body-sent < n {
				n = body - sent
			}
			time.Sleep(step)
			w.Write(make([]byte, n))
			if fl != nil {
				fl.Flush()
			}
			sent += n
		}
	}
}

// Задушенный канал: 256 КБ разгона мгновенно, затем ~250 КБ за ~1 с.
// Скорость обязана считаться по задушенной части (~2 Мбит/с), а не по
// мгновенному разгону (иначе замер объявлял бы задушенный канал быстрым).
func TestMeasureSpeedThrottled(t *testing.T) {
	srv := httptest.NewServer(throttledHandler(256<<10, 250<<10, 25<<10, 100*time.Millisecond))
	defer srv.Close()

	mbps, err := MeasureSpeed(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("замер упал: %v", err)
	}
	// ~2 Мбит/с; границы широкие — таймеры CI не эталон
	if mbps < 0.5 || mbps > 10 {
		t.Errorf("mbps = %.2f, ждали ~2 (замер посчитал разгон?)", mbps)
	}
}

// Быстрый канал: 5 МБ без задержек — скорость высокая, ошибок нет.
func TestMeasureSpeedFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 5<<20))
	}))
	defer srv.Close()

	mbps, err := MeasureSpeed(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("замер упал: %v", err)
	}
	if mbps < 10 {
		t.Errorf("mbps = %.2f — локальный сервер не бывает таким медленным", mbps)
	}
}

// Обрыв посреди тела — ошибка, а не цифра из половины замера.
func TestMeasureSpeedAborted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(5<<20))
		w.Write(make([]byte, 300<<10))
		panic(http.ErrAbortHandler) // сервер рвёт соединение
	}))
	defer srv.Close()

	if mbps, err := MeasureSpeed(context.Background(), srv.URL, nil); err == nil {
		t.Errorf("обрыв обязан дать ошибку, а не %.2f Мбит/с", mbps)
	}
}

// Ответ короче разгонных 256 КБ: скорость по нему не считается.
func TestMeasureSpeedTooShort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 100<<10))
	}))
	defer srv.Close()

	if mbps, err := MeasureSpeed(context.Background(), srv.URL, nil); err == nil {
		t.Errorf("короткий ответ обязан дать ошибку, а не %.2f Мбит/с", mbps)
	}
}

// Ошибка HTTP — ошибка замера: качать нечего.
func TestMeasureSpeedHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	if _, err := MeasureSpeed(context.Background(), srv.URL, nil); err == nil {
		t.Error("HTTP 403 обязан дать ошибку")
	}
}

// Отмена внешнего контекста (закрытие приложения) обрывает замер ошибкой.
func TestMeasureSpeedCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(5<<20))
		w.Write(make([]byte, 300<<10))
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		cancel() // «пользователь закрыл окно» посреди скачивания
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	if mbps, err := MeasureSpeed(ctx, srv.URL, nil); err == nil {
		t.Errorf("отменённый контекст обязан дать ошибку, а не %.2f Мбит/с", mbps)
	}
}
