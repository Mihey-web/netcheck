package geo

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mihey/netcheck/internal/geo/ipdb"
	"github.com/mihey/netcheck/internal/probe"
)

// testDB — крошечная база под форму настоящих трассировок 2026-08-02.
// Сеть, с которой делались замеры, представлена диапазоном для документации
// (RFC 5737) и номером AS оттуда же (RFC 5398): называть конкретного
// абонента в тесте незачем.
//
//	95.71.0.0/16      RU  AS12389 Rostelecom
//	104.18.0.0/16     US  AS13335 Cloudflare
//	198.51.100.0/24   RU  AS64500 Example ISP
//
// Порядок возрастающий: Build того и требует, и не зря — молча склеенные
// внахлёст диапазоны потом объясняли бы пользователю, что его провайдер
// находится в Парагвае.
func testDB(t *testing.T) *ipdb.DB {
	t.Helper()
	countries := []ipdb.Country{
		{Start: 0x5F470000, End: 0x5F47FFFF, Code: "RU"}, // 95.71.0.0/16
		{Start: 0x68120000, End: 0x6812FFFF, Code: "US"}, // 104.18.0.0/16
		{Start: 0xC6336400, End: 0xC63364FF, Code: "RU"}, // 198.51.100.0/24
	}
	asns := []ipdb.ASN{
		{Start: 0x5F470000, End: 0x5F47FFFF, Number: 12389, Org: "Rostelecom"},
		{Start: 0x68120000, End: 0x6812FFFF, Number: 13335, Org: "Cloudflare"},
		{Start: 0xC6336400, End: 0xC63364FF, Number: 64500, Org: "Example ISP"},
	}
	var buf bytes.Buffer
	if err := ipdb.Build(&buf, countries, asns); err != nil {
		t.Fatalf("сборка базы: %v", err)
	}
	db, err := ipdb.Open(buf.Bytes())
	if err != nil {
		t.Fatalf("открытие базы: %v", err)
	}
	return db
}

func hop(n int, ip string, rtt int64, st probe.HopStatus) probe.Hop {
	return probe.Hop{N: n, IP: ip, RTTms: rtt, Status: st}
}

// Домашний роутер обязан остаться без страны: подписать 192.168.1.1 хоть
// чем-нибудь — значит нарисовать пользователя не там, где он есть.
func TestAnnotateMarksLocal(t *testing.T) {
	nodes := Annotate([]probe.Hop{
		hop(1, "192.168.1.1", 1, probe.HopOK),
		hop(2, "100.64.0.1", 3, probe.HopOK),
		hop(3, "198.51.100.1", 5, probe.HopOK),
	}, testDB(t))

	if !nodes[0].Private || nodes[0].Country != "" {
		t.Errorf("домашний адрес размечен как %+v", nodes[0])
	}
	if !nodes[1].Private {
		t.Errorf("адрес провайдерского NAT не помечен как внутренний: %+v", nodes[1])
	}
	if nodes[2].Country != "RU" || nodes[2].ASN != 64500 || nodes[2].Org != "Example ISP" {
		t.Errorf("публичный адрес размечен как %+v", nodes[2])
	}
}

// Молчащий шаг остаётся в маршруте пустым — он часть картинки,
// но подписывать его нечем.
func TestAnnotateKeepsSilent(t *testing.T) {
	nodes := Annotate([]probe.Hop{hop(1, "", 0, probe.HopSilent)}, testDB(t))
	if len(nodes) != 1 {
		t.Fatalf("шагов %d, хотели 1", len(nodes))
	}
	if nodes[0].Country != "" || nodes[0].Private {
		t.Errorf("молчащий шаг размечен как %+v", nodes[0])
	}
}

// База может не открыться — карта обязана продолжать работать,
// просто без подписей.
func TestAnnotateWithoutDB(t *testing.T) {
	nodes := Annotate([]probe.Hop{hop(1, "198.51.100.1", 5, probe.HopOK)}, nil)
	if nodes[0].Country != "" || nodes[0].ASN != 0 {
		t.Errorf("без базы шаг размечен как %+v", nodes[0])
	}
	if nodes[0].IP != "198.51.100.1" {
		t.Errorf("без базы потерялся адрес: %+v", nodes[0])
	}
}

func TestHomeCountry(t *testing.T) {
	db := testDB(t)
	tests := []struct {
		name string
		hops []probe.Hop
		want string
	}{
		{
			name: "берём первый публичный шаг, а не домашний",
			hops: []probe.Hop{hop(1, "192.168.1.1", 1, probe.HopOK), hop(2, "198.51.100.1", 5, probe.HopOK)},
			want: "RU",
		},
		{
			name: "неизвестные адреса пропускаем",
			hops: []probe.Hop{hop(1, "203.0.113.1", 5, probe.HopOK), hop(2, "95.71.2.226", 9, probe.HopOK)},
			want: "RU",
		},
		{
			name: "спросить не у кого",
			hops: []probe.Hop{hop(1, "192.168.1.1", 1, probe.HopOK)},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HomeCountry(Annotate(tt.hops, db)); got != tt.want {
				t.Errorf("HomeCountry() = %q, хотели %q", got, tt.want)
			}
		})
	}
}

func TestBuildRoute(t *testing.T) {
	db := testDB(t)

	t.Run("путь оборвался — точкой обрыва становится последний ответивший", func(t *testing.T) {
		r := BuildRoute("instagram.com", "31.13.72.174", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "198.51.100.1", 5, probe.HopOK),
		}, db, false, nil)

		if r.Reached {
			t.Error("маршрут считается дошедшим, хотя цель не ответила")
		}
		if r.Break == nil || r.Break.IP != "198.51.100.1" {
			t.Fatalf("точка обрыва: %+v", r.Break)
		}
		if r.Break.Org != "Example ISP" {
			t.Errorf("обрыв не подписан владельцем: %+v", r.Break)
		}
		if !strings.Contains(r.Note, "AS64500") {
			t.Errorf("в пояснении нет автономной системы: %q", r.Note)
		}
		if r.Home != "RU" {
			t.Errorf("Home = %q, хотели RU", r.Home)
		}
	})

	t.Run("явный отказ называется отказом, а не тишиной", func(t *testing.T) {
		r := BuildRoute("web.telegram.org", "149.154.167.99", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "95.71.2.226", 9, probe.HopUnreach),
		}, db, false, nil)

		if !strings.Contains(r.Note, "закрыт") {
			t.Errorf("отказ описан как %q", r.Note)
		}
		if strings.Contains(r.Note, "тишина") {
			t.Errorf("отказ назван тишиной: %q", r.Note)
		}
	})

	t.Run("дошли до цели — обрыва нет", func(t *testing.T) {
		r := BuildRoute("ya.ru", "95.71.2.226", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "95.71.2.226", 9, probe.HopFinal),
		}, db, true, nil)

		if !r.Reached {
			t.Error("маршрут дошёл, но Reached == false")
		}
		if r.Note != "" {
			t.Errorf("у дошедшего маршрута появилось пояснение: %q", r.Note)
		}
		if r.FarCountry {
			t.Error("цель в своей же стране помечена как далёкая")
		}
	})

	// Главное, ради чего всё затевалось: 104.18.x числится за США,
	// но отвечает за 32 мс. Из Москвы это физически невозможно —
	// значит отвечает московская точка присутствия, и красить США нельзя.
	t.Run("быстрый ответ из «далёкой» страны — это точка присутствия", func(t *testing.T) {
		r := BuildRoute("chatgpt.com", "104.18.32.47", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "198.51.100.1", 5, probe.HopOK),
			hop(3, "104.18.32.47", 32, probe.HopFinal),
		}, db, true, nil)

		if !r.FarCountry {
			t.Errorf("ответ за 32 мс из США не распознан как точка присутствия: %+v", r)
		}
		if !strings.Contains(r.Note, "точк") {
			t.Errorf("пояснение не про точку присутствия: %q", r.Note)
		}
	})

	// А вот честный дальний ответ — 140 мс до США — сомнению не подлежит.
	t.Run("медленный ответ из далёкой страны сомнению не подлежит", func(t *testing.T) {
		r := BuildRoute("example.com", "104.18.32.47", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "198.51.100.1", 5, probe.HopOK),
			hop(3, "104.18.32.47", 140, probe.HopFinal),
		}, db, true, nil)

		if r.FarCountry {
			t.Error("ответ за 140 мс из США помечен как ближайшая точка присутствия")
		}
	})

	// Половина магистральных роутеров не отвечает на ICMP, и трассировка
	// до живого сервиса регулярно не доходит. Крест в таком месте
	// противоречил бы отчёту на соседней вкладке.
	t.Run("сервис отвечает, а трассировка нет — это не обрыв", func(t *testing.T) {
		r := BuildRoute("netflix.com", "23.246.2.1", []probe.Hop{
			hop(1, "192.168.1.1", 1, probe.HopOK),
			hop(2, "198.51.100.1", 5, probe.HopOK),
		}, db, true, nil)

		if !r.Opaque {
			t.Error("живой сервис с недошедшей трассировкой не помечен как непрослеживаемый")
		}
		if strings.Contains(r.Note, "тишина") || strings.Contains(r.Note, "закрыт") {
			t.Errorf("непрослеживаемый маршрут описан как обрыв: %q", r.Note)
		}
		if !strings.Contains(r.Note, "ICMP") {
			t.Errorf("в пояснении нет причины — фильтрации ICMP: %q", r.Note)
		}
	})

	t.Run("не ответил никто", func(t *testing.T) {
		r := BuildRoute("instagram.com", "31.13.72.174", nil, db, false, nil)
		if r.Break != nil {
			t.Errorf("на пустом маршруте нашлась точка обрыва: %+v", r.Break)
		}
		if r.Note == "" {
			t.Error("пустой маршрут остался без объяснения")
		}
	})
}
