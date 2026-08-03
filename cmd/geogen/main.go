// Команда geogen собирает офлайн-базу «IPv4 → страна, AS» для netcheck.
//
// Запускается руками при обновлении данных, в сборку не входит:
//
//	go run ./cmd/geogen \
//	  -country dbip-country-lite-2026-08.mmdb \
//	  -asn     dbip-asn-lite-2026-08.mmdb \
//	  -out     internal/geo/data/ip.bin.gz
//
// Исходники — DB-IP Lite (CC BY 4.0, https://db-ip.com), качаются с
// https://download.db-ip.com/free/. Лицензия требует указания автора:
// он указан в NOTICE и в интерфейсе программы.
//
// Зачем перегонять, а не вшить MMDB как есть: MMDB несёт лишнее и весит
// 17 МБ на две базы. Нужны три поля, и в упакованном виде они занимают
// около 3 МБ — при том, что netcheck это один exe, который качают руками.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/mihey/netcheck/internal/geo/ipdb"
	"github.com/oschwald/maxminddb-golang/v2"
)

func main() {
	log.SetFlags(0)
	countryPath := flag.String("country", "", "путь к dbip-country-lite-*.mmdb")
	asnPath := flag.String("asn", "", "путь к dbip-asn-lite-*.mmdb")
	out := flag.String("out", filepath.Join("internal", "geo", "data", "ip.bin.gz"), "куда писать базу")
	flag.Parse()

	if *countryPath == "" || *asnPath == "" {
		flag.Usage()
		log.Fatal("нужны обе исходные базы")
	}

	countries, err := readCountries(*countryPath)
	if err != nil {
		log.Fatalf("страны: %v", err)
	}
	asns, err := readASNs(*asnPath)
	if err != nil {
		log.Fatalf("автономные системы: %v", err)
	}

	log.Printf("страны: %d диапазонов, AS: %d диапазонов", len(countries), len(asns))

	if err := write(*out, countries, asns); err != nil {
		log.Fatalf("запись: %v", err)
	}

	st, err := os.Stat(*out)
	if err != nil {
		log.Fatalf("проверка результата: %v", err)
	}
	log.Printf("готово: %s, %.2f МБ", *out, float64(st.Size())/(1<<20))
}

// span — диапазон IPv4 в хостовом порядке, границы включительные.
type span struct{ start, end uint32 }

// v4span приводит сеть из MMDB к диапазону IPv4. Второе значение — false
// для IPv6-сетей: их база сознательно не покрывает.
func v4span(p netip.Prefix) (span, bool) {
	addr := p.Addr().Unmap()
	if !addr.Is4() {
		return span{}, false
	}
	bits := p.Bits()
	if bits > 32 { // сеть записана как 4-in-6, префикс считан в v6-разрядах
		bits -= 96
	}
	a := addr.As4()
	start := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	size := uint32(1)<<(32-bits) - 1
	return span{start, start + size}, true
}

func readCountries(path string) ([]ipdb.Country, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var out []ipdb.Country
	for res := range db.Networks() {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := res.Decode(&rec); err != nil {
			return nil, err
		}
		code := rec.Country.ISOCode
		if len(code) != 2 {
			continue // «страна неизвестна» — пусть остаётся дыркой
		}
		s, ok := v4span(res.Prefix())
		if !ok {
			continue
		}
		// Соседние сети одной страны склеиваем: в MMDB одна страна разбита
		// на сотни префиксов, и без склейки база раздувается вчетверо.
		if n := len(out); n > 0 && out[n-1].Code == code && out[n-1].End+1 == s.start {
			out[n-1].End = s.end
			continue
		}
		out = append(out, ipdb.Country{Start: s.start, End: s.end, Code: code})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

func readASNs(path string) ([]ipdb.ASN, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var out []ipdb.ASN
	for res := range db.Networks() {
		var rec struct {
			Number uint32 `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if err := res.Decode(&rec); err != nil {
			return nil, err
		}
		if rec.Number == 0 {
			continue // ноль в формате означает «не знаю»
		}
		s, ok := v4span(res.Prefix())
		if !ok {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Number == rec.Number && out[n-1].End+1 == s.start {
			out[n-1].End = s.end
			continue
		}
		out = append(out, ipdb.ASN{Start: s.start, End: s.end, Number: rec.Number, Org: rec.Org})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, nil
}

func write(path string, cs []ipdb.Country, as []ipdb.ASN) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	if err := ipdb.Build(gz, cs, as); err != nil {
		return fmt.Errorf("сборка: %w", err)
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}
