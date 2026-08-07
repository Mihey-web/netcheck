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

// Табличный тест Cause→(Status, Advice): каждая причина из causeOutcome
// обязана быть здесь, и наоборот — новая причина без строки в этой таблице
// валит тест, а не молча уезжает во фронт как undefined.
func TestServiceOutcomeCoversEveryCause(t *testing.T) {
	cases := []struct {
		cause                  analyze.Cause
		wantStatus, wantAdvice string
	}{
		{analyze.CauseDPI, SvcNeedVPN, AdviceVPN},
		{analyze.CauseIPBlock, SvcNeedVPN, AdviceVPN},
		{analyze.CauseStateful, SvcNeedVPN, AdviceVPN},
		{analyze.CauseHTTPDrop, SvcNeedVPN, AdviceVPN},
		{analyze.CauseStub, SvcNeedVPN, AdviceVPN},
		{analyze.CauseMITM, SvcNeedVPN, AdviceVPN},
		{analyze.CauseDNSSpoof, SvcNeedVPN, AdviceDNS},
		{analyze.CauseGeoBlock, SvcGeo, AdviceGeo},
		{analyze.CauseAntibot, SvcChallenge, AdviceBrowser},
		{analyze.CauseDown, SvcDown, AdviceWait},
		{analyze.CauseProxyToo, SvcDown, AdviceVPNFail},
		{analyze.CauseNXDomain, SvcUnknown, AdviceNone},
		{analyze.CauseDNSSilent, SvcUnknown, AdviceNone},
		{analyze.CauseUnknown, SvcUnknown, AdviceNone},
	}
	if len(cases) != len(causeOutcome) {
		t.Errorf("в causeOutcome %d причин, в тесте %d — таблицы разъехались",
			len(causeOutcome), len(cases))
	}
	for _, c := range cases {
		if _, ok := causeOutcome[c.cause]; !ok {
			t.Errorf("%s: причины нет в causeOutcome", c.cause)
			continue
		}
		// ProxyOK=true и vpnCoversBrowser=false, чтобы проверить именно
		// базовую раскладку таблицы: уточнения («через VPN пробовали и не
		// вышло», «браузер накрыт VPN») проверяются отдельно.
		st, adv := ServiceOutcome(ServiceVerdict{
			Host: "example.com", Cause: c.cause, ProxyTried: true, ProxyOK: true,
		}, false)
		if st != c.wantStatus || adv != c.wantAdvice {
			t.Errorf("%s: got (%s, %s), want (%s, %s)", c.cause, st, adv, c.wantStatus, c.wantAdvice)
		}
	}
}

// Уточнения поверх таблицы: DirectOK, капча, «через VPN тоже не открылось»,
// «браузер сейчас накрыт VPN» и пустой Cause при провале. Статус отвечает
// на вопрос «откроется ли у меня в браузере сейчас», поэтому одна и та же
// блокировка при covers=true/false даёт ok_via_vpn/need_vpn.
func TestServiceOutcomeRefinements(t *testing.T) {
	cases := []struct {
		name                   string
		sv                     ServiceVerdict
		covers                 bool
		wantStatus, wantAdvice string
	}{
		{"работает напрямую", ServiceVerdict{DirectOK: true}, false, SvcOK, AdviceNone},
		{"капча важнее причины", ServiceVerdict{Challenged: true, Cause: analyze.CauseDown},
			false, SvcChallenge, AdviceBrowser},
		{"блокировка, VPN пробовали и не вышло — «ни напрямую, ни через VPN»",
			ServiceVerdict{Cause: analyze.CauseDPI, ProxyTried: true, ProxyOK: false},
			false, SvcDown, AdviceVPNFail},
		// даже когда браузер накрыт VPN: замер через VPN провалился, работать нечему
		{"блокировка, VPN не вышло, браузер накрыт — всё равно down",
			ServiceVerdict{Cause: analyze.CauseDPI, ProxyTried: true, ProxyOK: false},
			true, SvcDown, AdviceVPNFail},
		// подмена DNS обходится сменой резолвера и без VPN — совет остаётся
		{"подмена DNS, VPN не вышло — совет про DNS остаётся",
			ServiceVerdict{Cause: analyze.CauseDNSSpoof, ProxyTried: true, ProxyOK: false},
			false, SvcDown, AdviceDNS},
		{"блокировка, VPN не пробовали — совет VPN остаётся",
			ServiceVerdict{Cause: analyze.CauseDPI}, false, SvcNeedVPN, AdviceVPN},
		// сердце фикса: та же блокировка, тот же удачный замер через VPN —
		// но статус зависит от того, идёт ли браузер через VPN сейчас
		{"через VPN открылся, браузер накрыт — работает (ok_via_vpn)",
			ServiceVerdict{Cause: analyze.CauseDPI, ProxyTried: true, ProxyOK: true},
			true, SvcOKViaVPN, AdviceVPNKeep},
		{"через VPN открылся, браузер мимо VPN — нужен VPN",
			ServiceVerdict{Cause: analyze.CauseDPI, ProxyTried: true, ProxyOK: true},
			false, SvcNeedVPN, AdviceVPN},
		// «VPN не пробовали» — надежда, а не замер: ok_via_vpn не ставится
		{"браузер накрыт, но через VPN не мерили — по-прежнему need_vpn",
			ServiceVerdict{Cause: analyze.CauseDPI}, true, SvcNeedVPN, AdviceVPN},
		{"геоблок не превращается в down от неудачи VPN: выход не в той стране",
			ServiceVerdict{Cause: analyze.CauseGeoBlock, ProxyTried: true, ProxyOK: false},
			false, SvcGeo, AdviceGeo},
		// и в need_vpn геоблок не превращается тоже — даже при накрытом браузере
		{"геоблок, VPN не вышло, браузер накрыт — остаётся geo",
			ServiceVerdict{Cause: analyze.CauseGeoBlock, ProxyTried: true, ProxyOK: false},
			true, SvcGeo, AdviceGeo},
		// а вот удачный замер через VPN при накрытом браузере — работает:
		// выход VPN оказался в подходящей стране
		{"геоблок, через VPN открылся, браузер накрыт — работает",
			ServiceVerdict{Cause: analyze.CauseGeoBlock, ProxyTried: true, ProxyOK: true},
			true, SvcOKViaVPN, AdviceVPNKeep},
		{"пустой Cause при провале", ServiceVerdict{}, false, SvcUnknown, AdviceNone},
	}
	for _, c := range cases {
		st, adv := ServiceOutcome(c.sv, c.covers)
		if st != c.wantStatus || adv != c.wantAdvice {
			t.Errorf("%s: got (%s, %s), want (%s, %s)", c.name, st, adv, c.wantStatus, c.wantAdvice)
		}
	}
}

// Build обязан отдать выдачу целиком: успешные сервисы со status:"ok" тоже
// в списке, у проблемных — локализованная причина.
func TestBuildFillsVerdictServices(t *testing.T) {
	v := Build(i18n.RU, Input{
		Layers: []LayerStatus{
			{Layer: "gateway", Status: probe.StatusOK}, {Layer: "dns", Status: probe.StatusOK},
			{Layer: "runet", Status: probe.StatusOK}, {Layer: "global", Status: probe.StatusOK},
			{Layer: "blocked", Status: probe.StatusFail},
		},
		Services: []ServiceVerdict{
			{Host: "youtube.com", DirectOK: false, ProxyOK: true, ProxyTried: true, Cause: analyze.CauseDPI},
			{Host: "chatgpt.com", DirectOK: true},
		},
	})
	if len(v.Services) != 2 {
		t.Fatalf("в выдаче %d сервисов, ждали 2 (включая работающий)", len(v.Services))
	}
	yt, gpt := v.Services[0], v.Services[1]
	if yt.Status != SvcNeedVPN || yt.Advice != AdviceVPN {
		t.Errorf("youtube: got (%s, %s), want (%s, %s)", yt.Status, yt.Advice, SvcNeedVPN, AdviceVPN)
	}
	if !strings.Contains(yt.Reason, "YouTube") {
		t.Errorf("причина должна называть сервис по-человечески: %q", yt.Reason)
	}
	if gpt.Status != SvcOK || gpt.Advice != AdviceNone || gpt.Reason != "" {
		t.Errorf("работающий сервис: got (%s, %s, %q), want (ok, advice.none, «»)",
			gpt.Status, gpt.Advice, gpt.Reason)
	}
}

// vpnCoversBrowser — «браузер сейчас идёт через VPN»: TUN-режим или системный
// прокси Windows, за адресом которого реально слушает прокси. Запущенный
// листенер без системного прокси браузер НЕ накрывает.
func TestVPNCoversBrowser(t *testing.T) {
	listener := env.ProxyHint{Kind: "listener", Proto: "http", Addr: "127.0.0.1:10808", Active: true}
	cases := []struct {
		name string
		env  env.Snapshot
		want bool
	}{
		{"TUN: весь трафик в туннеле", env.Snapshot{DefaultViaTunnel: true}, true},
		{"системный прокси указывает на живой листенер",
			env.Snapshot{SystemProxyOn: true, SystemProxyAddr: "127.0.0.1:10808",
				Proxies: []env.ProxyHint{listener}}, true},
		// форма реестра «http=...;socks=...» тоже должна опознаваться
		{"системный прокси в форме по протоколам",
			env.Snapshot{SystemProxyOn: true, SystemProxyAddr: "http=127.0.0.1:10808;https=127.0.0.1:10808",
				Proxies: []env.ProxyHint{listener}}, true},
		{"листенер жив, но системный прокси выключен — браузер мимо",
			env.Snapshot{SystemProxyOn: false, Proxies: []env.ProxyHint{listener}}, false},
		{"системный прокси смотрит не на тот порт — браузер сломан, не накрыт",
			env.Snapshot{SystemProxyOn: true, SystemProxyAddr: "127.0.0.1:9999",
				Proxies: []env.ProxyHint{listener}}, false},
		// порт прокси не из проверяемого списка: листенеров не нащупали,
		// опровергнуть включённый прокси нечем — верим ему
		{"системный прокси включён, листенеры не проверялись",
			env.Snapshot{SystemProxyOn: true, SystemProxyAddr: "127.0.0.1:8080"}, true},
		{"ничего не запущено", env.Snapshot{}, false},
	}
	for _, c := range cases {
		if got := vpnCoversBrowser(c.env); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Сценарий владельца: VPN включён (системный прокси на живой листенер),
// YouTube в браузере открывается — а приложение показывало тревожное
// «только через VPN». Теперь тот же прогон обязан дать зелёное ok_via_vpn
// и флаг «VPN накрывает браузер» для строки контекста на фронте.
func TestBuildOwnersScenarioOKViaVPN(t *testing.T) {
	withProxy := env.Snapshot{
		Gateway: "192.168.0.1", SystemProxyOn: true, SystemProxyAddr: "127.0.0.1:10808",
		Proxies: []env.ProxyHint{
			{Kind: "system", Proto: "http", Addr: "127.0.0.1:10808", Active: true},
			{Kind: "listener", Proto: "http", Addr: "127.0.0.1:10808", Active: true},
		},
	}
	layers := []LayerStatus{
		{Layer: "gateway", Status: probe.StatusOK}, {Layer: "dns", Status: probe.StatusOK},
		{Layer: "runet", Status: probe.StatusOK}, {Layer: "global", Status: probe.StatusOK},
		{Layer: "blocked", Status: probe.StatusFail},
	}
	svc := []ServiceVerdict{
		{Host: "youtube.com", DirectOK: false, ProxyOK: true, ProxyTried: true, Cause: analyze.CauseDPI},
		// web.whatsapp.com из того же прогона: не открылся и через VPN —
		// совет обязан говорить «ни напрямую, ни через VPN», а не «сервис лежит»
		{Host: "web.whatsapp.com", DirectOK: false, ProxyOK: false, ProxyTried: true, Cause: analyze.CauseIPBlock},
	}

	v := Build(i18n.RU, Input{Env: withProxy, Layers: layers, Services: svc})
	if !v.VPNCoversBrowser {
		t.Error("VPNCoversBrowser должен быть true: системный прокси смотрит на живой листенер")
	}
	if yt := v.Services[0]; yt.Status != SvcOKViaVPN || yt.Advice != AdviceVPNKeep {
		t.Errorf("youtube при накрытом браузере: got (%s, %s), want (%s, %s)",
			yt.Status, yt.Advice, SvcOKViaVPN, AdviceVPNKeep)
	}
	if wa := v.Services[1]; wa.Status != SvcDown || wa.Advice != AdviceVPNFail {
		t.Errorf("whatsapp: got (%s, %s), want (%s, %s)", wa.Status, wa.Advice, SvcDown, AdviceVPNFail)
	}

	// тот же прогон, но системный прокси выключен: браузер мимо VPN — need_vpn
	bypassed := withProxy
	bypassed.SystemProxyOn, bypassed.SystemProxyAddr = false, ""
	bypassed.Proxies = []env.ProxyHint{
		{Kind: "listener", Proto: "http", Addr: "127.0.0.1:10808", Active: true},
	}
	v = Build(i18n.RU, Input{Env: bypassed, Layers: layers, Services: svc})
	if v.VPNCoversBrowser {
		t.Error("VPNCoversBrowser должен быть false: системный прокси выключен")
	}
	if yt := v.Services[0]; yt.Status != SvcNeedVPN || yt.Advice != AdviceVPN {
		t.Errorf("youtube при браузере мимо VPN: got (%s, %s), want (%s, %s)",
			yt.Status, yt.Advice, SvcNeedVPN, AdviceVPN)
	}
}
