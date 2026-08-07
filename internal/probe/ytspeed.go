// Замер скорости YouTube: прямой URL сегмента видео через Innertube.
//
// Весь файл — best-effort. Innertube — внутренний API YouTube: клиент
// ANDROID с публичным ключом получает в streamingData прямые (unsigned)
// ссылки на googlevideo.com — без расшифровки подписи, которую требует
// веб-клиент. YouTube может поменять API в любой день; при любой неудаче
// наружу уходит честная ошибка «не удалось замерить», а НЕ «не замедлен».
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// innertubeURL — var, а не const: тесты подменяют его на httptest-сервер.
var innertubeURL = "https://www.youtube.com/youtubei/v1/player"

const (
	// Публичный API-ключ клиента — не секрет: он вшит в само приложение
	// YouTube и одинаков у всех его установок.
	//
	// Клиент IOS, а не ANDROID: ANDROID теперь отвечает на такой запрос
	// FAILED_PRECONDITION (требует подтверждения устройства), а
	// iOS-клиент по-прежнему отдаёт прямые ссылки на googlevideo без
	// подписи — только по ним и можно замерить настоящую скорость до CDN.
	innertubeKey     = "AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w"
	innertubeClient  = "IOS"
	innertubeVersion = "20.10.4"
	// ytSpeedVideoID — стабильное публичное видео (Big Buck Bunny с
	// официального канала Blender): без возрастных ограничений и достаточно
	// длинное, чтобы поток весил заметно больше 5 МБ замера.
	ytSpeedVideoID = "aqz-KE-bpKQ"
)

// ytPlayerResponse — только нужные поля ответа /player.
type ytPlayerResponse struct {
	PlayabilityStatus struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"playabilityStatus"`
	StreamingData struct {
		Formats         []ytFormat `json:"formats"`
		AdaptiveFormats []ytFormat `json:"adaptiveFormats"`
	} `json:"streamingData"`
}

type ytFormat struct {
	URL      string `json:"url"`
	MimeType string `json:"mimeType"`
	Bitrate  int    `json:"bitrate"`
	// SignatureCipher непустой у подписанных ссылок — такие нам не годятся:
	// расшифровка подписи требует исполнения их JS-плеера.
	SignatureCipher string `json:"signatureCipher"`
}

// YouTubeSpeedURL добывает прямой URL видеосегмента для замера скорости.
//
// proxy нужен, когда сам youtube.com заблокирован: ссылку на сегмент тогда
// берём через VPN, а качать по ней будем напрямую — именно прямой канал до
// CDN нас и интересует. Без прокси (nil) запрос идёт напрямую.
func YouTubeSpeedURL(ctx context.Context, proxy *url.URL) (string, error) {
	body, err := json.Marshal(map[string]any{
		"context": map[string]any{
			"client": map[string]any{
				"clientName":        innertubeClient,
				"clientVersion":     innertubeVersion,
				"deviceModel": "iPhone16,2",
				"hl":                "en",
				"gl":                "US",
			},
		},
		"videoId": ytSpeedVideoID,
	})
	if err != nil {
		return "", err
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost,
		innertubeURL+"?key="+innertubeKey, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	// представляемся приложением YouTube: с чужим UA ANDROID-клиент
	// получает подписанные ссылки или отказ
	req.Header.Set("User-Agent",
		"com.google.ios.youtube/"+innertubeVersion+
			" (iPhone16,2; U; CPU iOS 18_3_2 like Mac OS X)")

	tr := &http.Transport{DisableKeepAlives: true}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("innertube: http %d", resp.StatusCode)
	}

	var pr ytPlayerResponse
	// лимит на чтение: ответ /player — сотни КБ, мегабайтный лимит с запасом
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&pr); err != nil {
		return "", fmt.Errorf("innertube: разбор ответа: %w", err)
	}
	if s := pr.PlayabilityStatus.Status; s != "OK" {
		return "", fmt.Errorf("innertube: видео недоступно (%s: %s)", s, pr.PlayabilityStatus.Reason)
	}

	// Берём самый тяжёлый по битрейту формат с прямой ссылкой: чем толще
	// поток, тем меньше шанс упереться в конец файла раньше конца замера.
	var best ytFormat
	all := append(append([]ytFormat{}, pr.StreamingData.AdaptiveFormats...),
		pr.StreamingData.Formats...)
	for _, f := range all {
		if f.URL == "" || f.SignatureCipher != "" {
			continue
		}
		if f.Bitrate > best.Bitrate || best.URL == "" {
			best = f
		}
	}
	if best.URL == "" {
		return "", errors.New("innertube: прямых ссылок нет — формат ответа изменился")
	}
	return best.URL, nil
}
