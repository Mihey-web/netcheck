package ipdb

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// build — собирает базу из диапазонов и сразу открывает её.
func build(t *testing.T, cs []Country, as []ASN) *DB {
	t.Helper()
	var buf bytes.Buffer
	if err := Build(&buf, cs, as); err != nil {
		t.Fatalf("Build: %v", err)
	}
	db, err := Open(buf.Bytes())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return db
}

func ip(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// Основной набор: две страны с дыркой между ними и три автономные системы.
//
//	1.0.0.0   – 1.255.255.255  RU
//	(дырка)
//	8.0.0.0   – 8.255.255.255  US
//
//	1.0.0.0   – 1.0.255.255    AS12389 Rostelecom
//	1.1.0.0   – 1.255.255.255  AS31133 MegaFon
//	(дырка)
//	8.8.8.0   – 8.8.8.255      AS15169 Google LLC
var (
	testCountries = []Country{
		{Start: 0x01000000, End: 0x01FFFFFF, Code: "RU"},
		{Start: 0x08000000, End: 0x08FFFFFF, Code: "US"},
	}
	testASNs = []ASN{
		{Start: 0x01000000, End: 0x0100FFFF, Number: 12389, Org: "Rostelecom"},
		{Start: 0x01010000, End: 0x01FFFFFF, Number: 31133, Org: "MegaFon"},
		{Start: 0x08080800, End: 0x080808FF, Number: 15169, Org: "Google LLC"},
	}
)

func TestLookup(t *testing.T) {
	db := build(t, testCountries, testASNs)

	tests := []struct {
		name string
		addr string
		want Record
	}{
		{"первый адрес первого диапазона", "1.0.0.0", Record{"RU", 12389, "Rostelecom"}},
		{"середина", "1.0.128.7", Record{"RU", 12389, "Rostelecom"}},
		{"последний адрес диапазона AS", "1.0.255.255", Record{"RU", 12389, "Rostelecom"}},
		{"первый адрес следующего диапазона AS", "1.1.0.0", Record{"RU", 31133, "MegaFon"}},
		{"конец страны", "1.255.255.255", Record{"RU", 31133, "MegaFon"}},
		{"дырка между странами", "2.0.0.0", Record{}},
		{"страна есть, AS нет", "8.0.0.1", Record{Country: "US"}},
		{"страна и AS есть", "8.8.8.8", Record{"US", 15169, "Google LLC"}},
		{"после последнего диапазона", "9.9.9.9", Record{}},
		{"до первого диапазона", "0.255.255.255", Record{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db.Lookup(ip(t, tt.addr))
			if got != tt.want {
				t.Errorf("Lookup(%s) = %+v, хотели %+v", tt.addr, got, tt.want)
			}
		})
	}
}

// Приватные адреса в базе отсутствуют по определению, и это не ошибка:
// первый хоп трассировки — всегда домашний роутер.
func TestLookupPrivate(t *testing.T) {
	db := build(t, testCountries, testASNs)
	for _, s := range []string{"192.168.1.1", "10.0.0.1", "100.64.0.1", "127.0.0.1"} {
		if got := db.Lookup(ip(t, s)); got != (Record{}) {
			t.Errorf("Lookup(%s) = %+v, хотели пустую запись", s, got)
		}
	}
}

// IPv6 база не покрывает — честно отвечаем «не знаю», а не врём страной.
func TestLookupIPv6(t *testing.T) {
	db := build(t, testCountries, testASNs)
	if got := db.Lookup(ip(t, "2a02:6b8::2:242")); got != (Record{}) {
		t.Errorf("Lookup(v6) = %+v, хотели пустую запись", got)
	}
}

// IPv4-адрес, приехавший в v6-обёртке (::ffff:8.8.8.8), должен находиться:
// именно в таком виде адреса приходят из некоторых системных вызовов.
func TestLookupIPv4In6(t *testing.T) {
	db := build(t, testCountries, testASNs)
	want := Record{"US", 15169, "Google LLC"}
	if got := db.Lookup(netip.AddrFrom16(ip(t, "8.8.8.8").As16())); got != want {
		t.Errorf("Lookup(::ffff:8.8.8.8) = %+v, хотели %+v", got, want)
	}
}

// Одно и то же имя AS встречается в тысячах диапазонов. Класть его в пул
// повторно — значит раздуть базу на мегабайты впустую.
func TestBuildDedupesNames(t *testing.T) {
	var buf bytes.Buffer
	as := []ASN{
		{Start: 0x01000000, End: 0x0100FFFF, Number: 12389, Org: "Rostelecom"},
		{Start: 0x02000000, End: 0x0200FFFF, Number: 12389, Org: "Rostelecom"},
		{Start: 0x03000000, End: 0x0300FFFF, Number: 12389, Org: "Rostelecom"},
	}
	if err := Build(&buf, nil, as); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if n := strings.Count(buf.String(), "Rostelecom"); n != 1 {
		t.Errorf("имя в базе встречается %d раз, хотели 1", n)
	}
}

func TestBuildRejectsUnsorted(t *testing.T) {
	unsorted := []Country{
		{Start: 0x08000000, End: 0x08FFFFFF, Code: "US"},
		{Start: 0x01000000, End: 0x01FFFFFF, Code: "RU"},
	}
	if err := Build(&bytes.Buffer{}, unsorted, nil); err == nil {
		t.Error("Build принял неотсортированные диапазоны, хотели ошибку")
	}
}

func TestBuildRejectsOverlap(t *testing.T) {
	overlapping := []Country{
		{Start: 0x01000000, End: 0x01FFFFFF, Code: "RU"},
		{Start: 0x01FFFFFF, End: 0x08FFFFFF, Code: "US"},
	}
	if err := Build(&bytes.Buffer{}, overlapping, nil); err == nil {
		t.Error("Build принял пересекающиеся диапазоны, хотели ошибку")
	}
}

func TestBuildRejectsBadCode(t *testing.T) {
	bad := []Country{{Start: 0x01000000, End: 0x01FFFFFF, Code: "RUS"}}
	if err := Build(&bytes.Buffer{}, bad, nil); err == nil {
		t.Error("Build принял трёхбуквенный код страны, хотели ошибку")
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  []byte
	}{
		{"пусто", nil},
		{"не наш формат", []byte("это точно не база")},
		{"обрезано на заголовке", []byte(magic + "\x01")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Open(tt.raw); err == nil {
				t.Error("Open принял мусор, хотели ошибку")
			}
		})
	}
}

// Пустая база — законное состояние: генератор мог не отработать.
// Она обязана открываться и честно отвечать «не знаю» на любой адрес.
func TestEmptyDB(t *testing.T) {
	db := build(t, nil, nil)
	if got := db.Lookup(ip(t, "8.8.8.8")); got != (Record{}) {
		t.Errorf("Lookup в пустой базе = %+v, хотели пустую запись", got)
	}
	if n := db.Len(); n != 0 {
		t.Errorf("Len() = %d, хотели 0", n)
	}
}

func TestLen(t *testing.T) {
	db := build(t, testCountries, testASNs)
	if got, want := db.Len(), len(testCountries)+len(testASNs); got != want {
		t.Errorf("Len() = %d, хотели %d", got, want)
	}
}

// Дата выпуска данных едет в заголовке и возвращается как есть: без неё
// устаревшая на годы база неотличима от свежей.
func TestReleasedDate(t *testing.T) {
	var buf bytes.Buffer
	released := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	if err := BuildReleased(&buf, testCountries, testASNs, released); err != nil {
		t.Fatalf("BuildReleased: %v", err)
	}
	db, err := Open(buf.Bytes())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := db.Released(); got != "2026-08-07" {
		t.Errorf("Released() = %q, хотели 2026-08-07", got)
	}
	if got := db.Lookup(ip(t, "8.8.8.8")); got != (Record{"US", 15169, "Google LLC"}) {
		t.Errorf("данные после добавления даты поехали: %+v", got)
	}

	// Build без даты обязан честно отвечать «неизвестна», а не выдумывать.
	db = build(t, testCountries, testASNs)
	if got := db.Released(); got != "" {
		t.Errorf("Released() без даты = %q, хотели пустую строку", got)
	}
}

// Старые файлы версии 1 (без даты в заголовке) обязаны открываться:
// пересборка базы — не условие работы карты.
func TestOpenReadsVersion1(t *testing.T) {
	// Пустая база в формате v1, собранная руками: magic, версия 1, резерв,
	// три нулевых счётчика — и ни байта больше.
	raw := append([]byte(magic), 1, 0)
	raw = append(raw, make([]byte, 12)...)

	db, err := Open(raw)
	if err != nil {
		t.Fatalf("Open(v1): %v", err)
	}
	if got := db.Released(); got != "" {
		t.Errorf("Released() у файла v1 = %q, хотели пустую строку", got)
	}
	if got := db.Lookup(ip(t, "8.8.8.8")); got != (Record{}) {
		t.Errorf("Lookup в пустой v1-базе = %+v, хотели пустую запись", got)
	}

	// Будущую версию 3 по-прежнему не читаем: угадывать раскладку нельзя.
	bad := append([]byte(magic), 3, 0)
	bad = append(bad, make([]byte, 16)...)
	if _, err := Open(bad); err == nil {
		t.Error("Open принял версию 3, хотели ошибку")
	}
}
