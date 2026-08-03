// Package geo выясняет, из какой страны тебя видит интернет.
//
// Это единственное место, где netcheck сообщает наружу что-то о пользователе
// (свой IP стороннему сервису), поэтому вызывается только при явно включённой
// настройке map.geo_lookup.
package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Info struct {
	IP      string  `json:"ip"`
	Country string  `json:"country"`     // человекочитаемое имя
	Code    string  `json:"countryCode"` // ISO alpha-2
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	// ViaProxy — это выход через VPN-прокси, а не прямой.
	ViaProxy bool `json:"viaProxy"`
}

// providers — несколько на случай, если один недоступен из РФ.
var providers = []string{
	"https://ipapi.co/json/",
	"https://ifconfig.co/json",
}

// Lookup спрашивает провайдера, как выглядит наш выход в интернет.
// proxy == nil — прямой путь; иначе через прокси.
func Lookup(ctx context.Context, proxy *url.URL) (*Info, error) {
	tr := &http.Transport{DisableKeepAlives: true}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{Transport: tr}

	var lastErr error
	for _, p := range providers {
		info, err := fetch(ctx, client, p)
		if err != nil {
			lastErr = err
			continue
		}
		info.ViaProxy = proxy != nil
		return info, nil
	}
	return nil, lastErr
}

func fetch(ctx context.Context, client *http.Client, endpoint string) (*Info, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netcheck/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geo: http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	if err != nil {
		return nil, err
	}
	return parse(raw)
}

// parse понимает оба формата: ipapi.co и ifconfig.co.
func parse(raw []byte) (*Info, error) {
	var v struct {
		IP          string  `json:"ip"`
		Country     string  `json:"country"`      // ifconfig.co: имя; ipapi.co: код
		CountryName string  `json:"country_name"` // ipapi.co
		CountryCode string  `json:"country_code"` // ipapi.co
		CountryISO  string  `json:"country_iso"`  // ifconfig.co
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v.IP == "" {
		return nil, fmt.Errorf("geo: в ответе нет IP")
	}

	info := &Info{IP: v.IP, City: v.City, Lat: v.Latitude, Lon: v.Longitude}
	switch {
	case v.CountryCode != "":
		info.Code, info.Country = v.CountryCode, v.CountryName
	case v.CountryISO != "":
		info.Code, info.Country = v.CountryISO, v.Country
	default:
		info.Country = v.Country
	}
	if info.Country == "" {
		info.Country = info.Code
	}
	return info, nil
}
