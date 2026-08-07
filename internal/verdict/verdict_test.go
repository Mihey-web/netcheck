package verdict

import (
	"strings"
	"testing"

	"github.com/mihey/netcheck/internal/analyze"
	"github.com/mihey/netcheck/internal/env"
	"github.com/mihey/netcheck/internal/i18n"
	"github.com/mihey/netcheck/internal/probe"
)

// Сценарий из мокапа: интернет жив, блокировки с разными механизмами,
// x.com лежит даже через VPN, системный прокси выключен при живом листенере.
func TestBuildBlockedScenario(t *testing.T) {
	in := Input{
		Env: env.Snapshot{
			Proxies:       []env.ProxyHint{{Kind: "listener", Proto: "socks5", Addr: "127.0.0.1:10808", Active: true}},
			SystemProxyOn: false,
		},
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusWarn},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []ServiceVerdict{
			{Host: "youtube.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDPI},
			{Host: "discord.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseIPBlock},
			{Host: "instagram.com", DirectOK: false, ProxyOK: true, Cause: analyze.CauseDNSSpoof},
			{Host: "x.com", DirectOK: false, ProxyOK: false, Cause: analyze.CauseProxyToo},
		},
	}
	v := Build(i18n.RU, in)
	joined := strings.ToLower(strings.Join(append(append([]string{}, v.Lines...), v.Warnings...), " "))

	for _, want := range []string{"youtube", "discord", "instagram"} {
		if !strings.Contains(joined, want) {
			t.Errorf("verdict must mention %s: %q", want, joined)
		}
	}
	if !strings.Contains(joined, "мимо") {
		t.Error("verdict must warn that browser bypasses VPN (системный прокси выключен)")
	}
	if !strings.Contains(joined, "vpn") {
		t.Error("verdict must mention VPN for x.com case")
	}
	if len(v.Chain) != 5 {
		t.Errorf("chain must keep all 5 layers, got %d", len(v.Chain))
	}
}

func TestBuildAllOK(t *testing.T) {
	in := Input{
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusOK},
		},
	}
	v := Build(i18n.EN, in)
	if len(v.Lines) == 0 {
		t.Fatal("all-ok verdict must still say something")
	}
	if len(v.Warnings) != 0 {
		t.Fatalf("no warnings expected, got %v", v.Warnings)
	}
}

func TestBuildGatewayDown(t *testing.T) {
	in := Input{
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusFail},
			{Layer: "dns", Status: probe.StatusFail},
			{Layer: "runet", Status: probe.StatusFail},
			{Layer: "global", Status: probe.StatusFail},
			{Layer: "blocked", Status: probe.StatusFail},
		},
	}
	v := Build(i18n.RU, in)
	joined := strings.ToLower(strings.Join(v.Lines, " "))
	if !strings.Contains(joined, "роутер") && !strings.Contains(joined, "локальн") {
		t.Errorf("gateway-down verdict must point at local network: %q", joined)
	}
}

// Антибот ставится ровно по признаку «через другую страну ответ тот же».
// Дописывать к нему «не работает даже через VPN — проблема на стороне
// VPN-сервера» значит спорить с собой в соседней строке того же вердикта.
func TestAntibotDoesNotBlameTheVPN(t *testing.T) {
	v := Build(i18n.RU, Input{
		Env: env.Snapshot{Gateway: "192.168.0.1", Proxies: []env.ProxyHint{
			{Kind: "http", Addr: "127.0.0.1:10809", Active: true}}},
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []ServiceVerdict{
			{Host: "chatgpt.com", DirectOK: false, ProxyOK: false, ProxyTried: true,
				Cause: analyze.CauseAntibot},
		},
	})
	all := strings.Join(v.Lines, "\n")
	if !strings.Contains(all, "chatgpt.com") {
		t.Fatalf("сервис пропал из вердикта:\n%s", all)
	}
	if strings.Contains(all, "VPN-сервера") {
		t.Errorf("защиту от роботов свалили на VPN-сервер:\n%s", all)
	}
}

// Геоблок сам объясняет неудачу через VPN: «сайт отказал по стране» и
// «похоже, проблема на стороне VPN-сервера» — спор двух соседних строк,
// когда выход VPN просто оказался в неподходящей стране.
func TestGeoBlockDoesNotBlameTheVPN(t *testing.T) {
	v := Build(i18n.RU, Input{
		Env: env.Snapshot{Gateway: "192.168.0.1", Proxies: []env.ProxyHint{
			{Kind: "http", Addr: "127.0.0.1:10809", Active: true}}},
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK},
			{Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK},
			{Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []ServiceVerdict{
			{Host: "gemini.google.com", DirectOK: false, ProxyOK: false, ProxyTried: true,
				Cause: analyze.CauseGeoBlock},
		},
	})
	all := strings.Join(v.Lines, "\n")
	if !strings.Contains(all, "gemini.google.com") {
		t.Fatalf("сервис пропал из вердикта:\n%s", all)
	}
	if strings.Contains(all, "VPN-сервера") {
		t.Errorf("отказ по стране свалили на VPN-сервер:\n%s", all)
	}
}

// Через VPN открывается почти всё — и человек обязан это прочитать.
// Прежде сообщение показывалось, только если через VPN работало всё
// до единого: трёх сервисов, не работающих нигде, хватало, чтобы
// программа промолчала про остальные двадцать.
func TestVerdictCountsWhatOpensViaVPN(t *testing.T) {
	svc := []ServiceVerdict{
		{Host: "youtube.com", DirectOK: false, ProxyOK: true, ProxyTried: true, Cause: analyze.CauseDPI},
		{Host: "discord.com", DirectOK: false, ProxyOK: true, ProxyTried: true, Cause: analyze.CauseDPI},
		{Host: "rutracker.org", DirectOK: false, ProxyOK: true, ProxyTried: true, Cause: analyze.CauseDPI},
		// эти не открываются нигде — раньше они и затыкали весь отчёт
		{Host: "web.telegram.org", DirectOK: false, ProxyOK: false, ProxyTried: true, Cause: analyze.CauseIPBlock},
		{Host: "web.whatsapp.com", DirectOK: false, ProxyOK: false, ProxyTried: true, Cause: analyze.CauseIPBlock},
	}
	v := Build(i18n.RU, Input{
		Env: env.Snapshot{Gateway: "192.168.0.1", Proxies: []env.ProxyHint{
			{Kind: "listener", Proto: "socks5", Addr: "127.0.0.1:10808", Active: true}}},
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK}, {Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK}, {Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: svc,
	})
	all := strings.Join(v.Lines, "\n")
	if !strings.Contains(all, "3 из 5") {
		t.Errorf("вердикт молчит о том, что через VPN открывается 3 из 5:\n%s", all)
	}
}

// Непокрытые ветки Build: три исхода контрольного запроса (captive),
// три причины мёртвого шлюза (APIPA / нет маршрута / шлюз молчит)
// и недоступный рунет с VPN и без. Ожидания заданы ключами словаря:
// тест проверяет, что выбрана именно та строка, а не пересказывает текст.
func TestBuildUncoveredBranches(t *testing.T) {
	ok, fail := probe.StatusOK, probe.StatusFail
	layers := func(gw, dns, runet, global probe.Status) []LayerStatus {
		return []LayerStatus{
			{Layer: "gateway", Status: gw}, {Layer: "dns", Status: dns},
			{Layer: "runet", Status: runet}, {Layer: "global", Status: global},
		}
	}
	cases := []struct {
		name    string
		in      Input
		want    []string // ключи i18n, чьи строки обязаны быть в вердикте
		notWant []string // ключи, чьих строк быть не должно
	}{
		{
			name: "captive portal — вход через браузер",
			in:   Input{Layers: layers(ok, fail, fail, fail), Captive: CaptivePortal},
			want: []string{"verdict.captive"}, notWant: []string{"verdict.no_internet"},
		},
		{
			name: "captive open — наружу ходим, а сайты не открываются",
			in:   Input{Layers: layers(ok, fail, fail, fail), Captive: CaptiveOpen},
			want: []string{"verdict.http_only"}, notWant: []string{"verdict.no_internet"},
		},
		{
			name: "captive dead — наружу не уходит ни один пакет",
			in:   Input{Layers: layers(ok, fail, fail, fail), Captive: CaptiveDead},
			want: []string{"verdict.no_internet"},
		},
		{
			// APIPA важнее пустого шлюза: 169.254.x.x сам по себе значит,
			// что роутер не выдал адрес, и шлюза не будет заведомо.
			name:    "APIPA: роутер не выдал адрес",
			in:      Input{Env: env.Snapshot{IP: "169.254.10.20"}, Layers: layers(fail, fail, fail, fail)},
			want:    []string{"verdict.apipa", "verdict.aborted"},
			notWant: []string{"verdict.no_route", "verdict.gateway_down"},
		},
		{
			name:    "пустой шлюз — маршрута наружу нет",
			in:      Input{Env: env.Snapshot{IP: "192.168.1.23"}, Layers: layers(fail, fail, fail, fail)},
			want:    []string{"verdict.no_route", "verdict.aborted"},
			notWant: []string{"verdict.apipa"},
		},
		{
			name: "шлюз задан, но молчит",
			in: Input{Env: env.Snapshot{IP: "192.168.1.23", Gateway: "192.168.1.1"},
				Layers: layers(fail, fail, fail, fail)},
			want: []string{"verdict.gateway_down", "verdict.aborted"},
		},
		{
			// «VPN заворачивает и российский трафик» можно говорить только
			// тому, у кого трафик действительно идёт через туннель.
			name: "рунет лежит при дефолте через туннель — вина VPN",
			in: Input{Env: env.Snapshot{DefaultViaTunnel: true},
				Layers: layers(ok, ok, fail, ok)},
			want: []string{"verdict.runet_down_vpn"}, notWant: []string{"verdict.runet_down"},
		},
		{
			name: "рунет лежит без VPN — вопрос к провайдеру",
			in:   Input{Layers: layers(ok, ok, fail, ok)},
			want: []string{"verdict.runet_down"}, notWant: []string{"verdict.runet_down_vpn"},
		},
	}
	for _, c := range cases {
		v := Build(i18n.RU, c.in)
		all := strings.Join(append(append([]string{}, v.Lines...), v.Warnings...), "\n")
		for _, key := range c.want {
			if !strings.Contains(all, i18n.T(i18n.RU, key)) {
				t.Errorf("%s: нет строки %s:\n%s", c.name, key, all)
			}
		}
		for _, key := range c.notWant {
			if strings.Contains(all, i18n.T(i18n.RU, key)) {
				t.Errorf("%s: лишняя строка %s:\n%s", c.name, key, all)
			}
		}
	}
}

// «Не находится ни одним резолвером» про три и больше доменов разом — это
// самоопровержение: столько доменов одновременно не исчезает. Диагнозы
// обязаны схлопнуться в «спрашивать было нечем», а хосты — уйти из списка
// блокировок. Ровно два — ещё честный пересчёт по хостам.
func TestBuildCollapsesMassDNSFailure(t *testing.T) {
	okLayers := []LayerStatus{
		{Layer: "gateway", Status: probe.StatusOK}, {Layer: "dns", Status: probe.StatusOK},
		{Layer: "runet", Status: probe.StatusOK}, {Layer: "global", Status: probe.StatusOK},
		{Layer: "blocked", Status: probe.StatusFail},
	}
	nx := func(host string, cause analyze.Cause) ServiceVerdict {
		return ServiceVerdict{Host: host, DirectOK: false, ProxyOK: false, Cause: cause}
	}

	// больше двух — схлопывается
	v := Build(i18n.RU, Input{Layers: okLayers, Services: []ServiceVerdict{
		nx("one.example.com", analyze.CauseNXDomain),
		nx("two.example.com", analyze.CauseNXDomain),
		nx("three.example.com", analyze.CauseDNSSilent),
	}})
	all := strings.Join(v.Lines, "\n")
	if !strings.Contains(all, i18n.T(i18n.RU, "svc.dns_unreachable")) {
		t.Errorf("массовый DNS-отказ не схлопнулся в «спрашивать было нечем»:\n%s", all)
	}
	for _, h := range []string{"one.example.com", "two.example.com", "three.example.com"} {
		if strings.Contains(all, h) {
			t.Errorf("домен %s всё равно попал в список блокировок:\n%s", h, all)
		}
	}

	// ровно два — перечисляются по хостам, без схлопывания
	v = Build(i18n.RU, Input{Layers: okLayers, Services: []ServiceVerdict{
		nx("one.example.com", analyze.CauseNXDomain),
		nx("two.example.com", analyze.CauseNXDomain),
	}})
	all = strings.Join(v.Lines, "\n")
	if strings.Contains(all, i18n.T(i18n.RU, "svc.dns_unreachable")) {
		t.Errorf("два домена схлопнулись, хотя порог — больше двух:\n%s", all)
	}
	for _, h := range []string{"one.example.com", "two.example.com"} {
		if !strings.Contains(all, h) {
			t.Errorf("домен %s пропал из вердикта:\n%s", h, all)
		}
	}
}
