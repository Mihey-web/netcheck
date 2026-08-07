package catalog

import "testing"

// Каждый идентификатор из пресетов обязан существовать в справочнике:
// Resolve молча пропускает неизвестные ID, и опечатка в пресете тихо
// выкидывала бы сервис из прогона — никто бы этого не заметил.
func TestPresetIDsExist(t *testing.T) {
	for preset, ids := range Presets {
		for _, id := range ids {
			if _, ok := byID[id]; !ok {
				t.Errorf("пресет %q ссылается на несуществующий ID %q — сервис молча выпадет из прогона", preset, id)
			}
		}
	}
}

// Дубль ID в справочнике молча затёр бы предыдущий сервис в byID.
func TestServiceIDsUnique(t *testing.T) {
	seen := map[string]string{}
	for _, s := range Services {
		if prev, ok := seen[s.ID]; ok {
			t.Errorf("ID %q встречается дважды: %s и %s", s.ID, prev, s.Host)
		}
		seen[s.ID] = s.Host
	}
}

func TestResolve(t *testing.T) {
	runet, global, blocked, geo := Resolve(
		[]string{
			"ya",         // runet
			"cloudflare", // global
			"youtube",    // blocked
			"chatgpt",    // geo
			"no-such-id", // опечатка: молча пропускается, прогон не падает
		},
		[]Custom{
			{Host: "my.example.com", Group: GroupRunet},
			// Неизвестная группа — цель не теряется, а падает в blocked:
			// «не знаю, куда» не повод выкинуть то, что человек добавил руками.
			{Host: "odd.example.com", Group: "какая-то"},
			{Host: "", Group: GroupGlobal}, // пустой хост пропускается
		},
	)

	has := func(list []string, host string) bool {
		for _, h := range list {
			if h == host {
				return true
			}
		}
		return false
	}
	if !has(runet, "ya.ru") || !has(runet, "my.example.com") {
		t.Errorf("runet = %v, ждали ya.ru и my.example.com", runet)
	}
	if !has(global, "cloudflare.com") {
		t.Errorf("global = %v, ждали cloudflare.com", global)
	}
	if !has(blocked, "youtube.com") {
		t.Errorf("blocked = %v, ждали youtube.com", blocked)
	}
	if !has(geo, "chatgpt.com") {
		t.Errorf("geo = %v, ждали chatgpt.com", geo)
	}
	if !has(blocked, "odd.example.com") {
		t.Errorf("цель с неизвестной группой должна падать в blocked, got %v", blocked)
	}
	total := len(runet) + len(global) + len(blocked) + len(geo)
	if total != 6 {
		t.Errorf("всего целей %d, ждали 6: пустой хост и неизвестный ID должны пропускаться", total)
	}
}

func TestIDForHost(t *testing.T) {
	cases := []struct {
		host   string
		wantID string
		wantOK bool
	}{
		{"ya.ru", "ya", true},
		{"web.telegram.org", "telegram", true},
		{"store.steampowered.com", "steam", true},
		{"nosuch.example.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		id, ok := IDForHost(c.host)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("IDForHost(%q) = (%q, %v), want (%q, %v)", c.host, id, ok, c.wantID, c.wantOK)
		}
	}
}
