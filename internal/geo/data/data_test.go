package data

import (
	"net/netip"
	"testing"

	"github.com/mihey/netcheck/internal/geo/ipdb"
)

// Проверяем не читалку формата (у неё свои тесты), а что вшитый блоб —
// это действительно база, а не пустой файл, забытый после неудачной сборки.
func TestLoad(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// В боевой базе сотни тысяч диапазонов. Порог грубый нарочно: он ловит
	// пустой и обрезанный блоб, но не ломается от обновления данных.
	if n := db.Len(); n < 100_000 {
		t.Errorf("в базе %d диапазонов — похоже, собралась не та", n)
	}
}

// Адреса выбраны из тех, что не меняют владельца годами: если такой ответ
// поехал, значит сломался генератор, а не мир.
func TestKnownAddresses(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		addr    string
		country string
		asn     uint32
	}{
		{"8.8.8.8", "US", 15169},   // Google Public DNS
		{"1.1.1.1", "", 13335},     // Cloudflare, anycast — страна необязательна
		{"77.88.8.8", "RU", 13238}, // Яндекс.DNS
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := db.Lookup(netip.MustParseAddr(tt.addr))
			if got.ASN != tt.asn {
				t.Errorf("ASN = %d (%s), хотели %d", got.ASN, got.Org, tt.asn)
			}
			if tt.country != "" && got.Country != tt.country {
				t.Errorf("страна = %q, хотели %q", got.Country, tt.country)
			}
			if got.Org == "" {
				t.Error("имя автономной системы пустое")
			}
		})
	}
}

// Первый хоп трассировки — домашний роутер. База обязана честно ответить
// «не знаю», иначе карта нарисует пользователя в чужой стране.
func TestPrivateStaysUnknown(t *testing.T) {
	db, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, s := range []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "100.64.0.1"} {
		if got := db.Lookup(netip.MustParseAddr(s)); got != (ipdb.Record{}) {
			t.Errorf("Lookup(%s) = %+v, хотели пустую запись", s, got)
		}
	}
}
