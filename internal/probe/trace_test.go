package probe

import (
	"reflect"
	"testing"
)

// hop — короткая запись шага для таблиц ниже.
func hop(n int, ip string, st HopStatus) Hop {
	return Hop{N: n, IP: ip, Status: st, RTTms: int64(n)}
}

// Маршруты повторяют форму настоящих трассировок 2026-08-02 (см. спеку
// probe-v2): instagram обрывается на втором шаге, telegram получает явный
// отказ, chatgpt проходит целиком. Адреса домашней сети и провайдера взяты
// из диапазонов для документации (RFC 5737).
func TestTrimHops(t *testing.T) {
	tests := []struct {
		name string
		in   []Hop
		want []Hop
	}{
		{
			name: "цель достигнута — хвост после неё не нужен",
			in: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "95.71.2.226", HopOK),
				hop(3, "104.18.32.47", HopFinal),
				hop(4, "", HopSilent),
				hop(5, "", HopSilent),
			},
			want: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "95.71.2.226", HopOK),
				hop(3, "104.18.32.47", HopFinal),
			},
		},
		{
			name: "путь оборвался — хвост молчания сворачивается",
			in: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "198.51.100.1", HopOK),
				hop(3, "", HopSilent),
				hop(4, "", HopSilent),
				hop(5, "", HopSilent),
			},
			want: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "198.51.100.1", HopOK),
			},
		},
		{
			name: "явный отказ — это ответ, его не срезаем",
			in: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "185.0.13.75", HopUnreach),
				hop(3, "", HopSilent),
			},
			want: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "185.0.13.75", HopUnreach),
			},
		},
		{
			name: "молчание в середине маршрута сохраняется",
			in: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "", HopSilent),
				hop(3, "198.51.100.1", HopOK),
				hop(4, "", HopSilent),
			},
			want: []Hop{
				hop(1, "192.168.1.1", HopOK),
				hop(2, "", HopSilent),
				hop(3, "198.51.100.1", HopOK),
			},
		},
		{
			name: "не ответил никто",
			in:   []Hop{hop(1, "", HopSilent), hop(2, "", HopSilent)},
			want: []Hop{},
		},
		{name: "пустой маршрут", in: []Hop{}, want: []Hop{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimHops(tt.in)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TrimHops() = %+v,\nхотели %+v", got, tt.want)
			}
		})
	}
}

func TestLastResponding(t *testing.T) {
	tests := []struct {
		name   string
		in     []Hop
		wantIP string
		wantOK bool
	}{
		{
			name:   "последний ответивший — он же точка обрыва",
			in:     []Hop{hop(1, "192.168.1.1", HopOK), hop(2, "198.51.100.1", HopOK), hop(3, "", HopSilent)},
			wantIP: "198.51.100.1",
			wantOK: true,
		},
		{
			name:   "отказавший роутер тоже ответил",
			in:     []Hop{hop(1, "192.168.1.1", HopOK), hop(2, "185.0.13.75", HopUnreach)},
			wantIP: "185.0.13.75",
			wantOK: true,
		},
		{
			name:   "цель ответила сама",
			in:     []Hop{hop(1, "192.168.1.1", HopOK), hop(2, "104.18.32.47", HopFinal)},
			wantIP: "104.18.32.47",
			wantOK: true,
		},
		{
			name:   "не ответил никто",
			in:     []Hop{hop(1, "", HopSilent)},
			wantOK: false,
		},
		{name: "пусто", in: nil, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LastResponding(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, хотели %v", ok, tt.wantOK)
			}
			if ok && got.IP != tt.wantIP {
				t.Errorf("IP = %q, хотели %q", got.IP, tt.wantIP)
			}
		})
	}
}

func TestReached(t *testing.T) {
	tests := []struct {
		name string
		in   []Hop
		want bool
	}{
		{"дошли", []Hop{hop(1, "1.1.1.1", HopFinal)}, true},
		{"оборвалось", []Hop{hop(1, "192.168.1.1", HopOK), hop(2, "", HopSilent)}, false},
		{"отказ — это не «дошли»", []Hop{hop(1, "185.0.13.75", HopUnreach)}, false},
		{"пусто", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Reached(tt.in); got != tt.want {
				t.Errorf("Reached() = %v, хотели %v", got, tt.want)
			}
		})
	}
}

// Молчащий шаг не считается ответившим, даже если адрес почему-то заполнен:
// иначе точка обрыва уехала бы вперёд по маршруту.
func TestHopResponded(t *testing.T) {
	tests := []struct {
		hop  Hop
		want bool
	}{
		{Hop{IP: "1.1.1.1", Status: HopOK}, true},
		{Hop{IP: "1.1.1.1", Status: HopFinal}, true},
		{Hop{IP: "1.1.1.1", Status: HopUnreach}, true},
		{Hop{IP: "1.1.1.1", Status: HopSilent}, false},
		{Hop{IP: "", Status: HopOK}, false},
	}
	for _, tt := range tests {
		if got := tt.hop.Responded(); got != tt.want {
			t.Errorf("Hop%+v.Responded() = %v, хотели %v", tt.hop, got, tt.want)
		}
	}
}
