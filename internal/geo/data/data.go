// Package data — офлайн-база «IPv4 → страна, AS», вшитая в бинарник.
//
// Вшита сознательно: карта должна работать тогда, когда сеть уже сломана,
// а спрашивать страну у внешнего сервиса в этот момент — и бесполезно,
// и означало бы рассказывать третьей стороне, куда пользователь ходит.
//
// Распаковывается при первом обращении, а не при старте: пользователю,
// который открыл netcheck ради вердикта и не заглянул в карту, эти
// мегабайты в памяти не нужны.
//
// Данные: DB-IP Lite, выпуск 2026-08 (CC BY 4.0, https://db-ip.com).
// Пересобирается командой cmd/geogen — см. NOTICE.
package data

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"sync"

	"github.com/mihey/netcheck/internal/geo/ipdb"
)

//go:embed ip.bin.gz
var packed []byte

var (
	once sync.Once
	db   *ipdb.DB
	err  error
)

// Load распаковывает и открывает базу. Повторные вызовы отдают то же самое,
// в том числе ту же ошибку: битая база не чинится повторной попыткой.
func Load() (*ipdb.DB, error) {
	once.Do(func() { db, err = open(packed) })
	return db, err
}

func open(raw []byte) (*ipdb.DB, error) {
	gz, e := gzip.NewReader(bytes.NewReader(raw))
	if e != nil {
		return nil, fmt.Errorf("geo/data: %w", e)
	}
	defer gz.Close()

	plain, e := io.ReadAll(gz)
	if e != nil {
		return nil, fmt.Errorf("geo/data: %w", e)
	}
	return ipdb.Open(plain)
}
