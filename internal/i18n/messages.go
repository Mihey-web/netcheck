package i18n

// messages — единственное место с пользовательским текстом.
// %s в svc.* — перечисление сервисов через запятую.
var messages = map[string]map[Lang]string{
	// слои
	"layer.gateway": {RU: "Шлюз", EN: "Gateway"},
	"layer.dns":     {RU: "DNS", EN: "DNS"},
	"layer.runet":   {RU: "Рунет", EN: "RuNet"},
	"layer.global":  {RU: "Заграница", EN: "Global"},
	"layer.blocked": {RU: "Блокируемые сервисы", EN: "Blocked services"},

	// общий вердикт по слоям
	"verdict.internet_ok": {
		RU: "Интернет работает.",
		EN: "The internet is working.",
	},
	"verdict.gateway_down": {
		RU: "Нет связи с роутером — проблема в локальной сети или Wi-Fi.",
		EN: "Can't reach the router — the problem is in your local network or Wi-Fi.",
	},
	"verdict.aborted": {
		RU: "Проверка остановлена: пока не отвечает роутер, всё остальное всё равно покажет «недоступно».",
		EN: "The run was stopped: while the router is unreachable, everything above would report \"unreachable\" anyway.",
	},
	"warn.gateway_icmp": {
		RU: "Роутер не отвечает на ping, но наружу связь есть — он просто режет ICMP. Это нормально.",
		EN: "The router ignores ping, yet the outside world is reachable — it just filters ICMP. That's normal.",
	},
	"verdict.no_internet": {
		RU: "Интернета нет: роутер отвечает, но дальше ничего не открывается — похоже, проблема у провайдера.",
		EN: "No internet: the router responds, but nothing beyond it opens — looks like an ISP problem.",
	},
	"verdict.global_down": {
		RU: "Рунет работает, но заграничные сайты недоступны.",
		EN: "Local (RU) sites work, but foreign sites are unreachable.",
	},
	"verdict.runet_down": {
		RU: "Заграница работает, а рунет недоступен — похоже, VPN заворачивает и российский трафик.",
		EN: "Foreign sites work, but local (RU) sites are unreachable — the VPN is probably routing local traffic too.",
	},
	"dns.spoof": {
		RU: "Провайдер подменяет DNS-ответы (системный DNS расходится с DoH).",
		EN: "Your ISP is spoofing DNS answers (system DNS differs from DoH).",
	},

	// блокировки по механизмам
	"svc.blocked.dpi_sni": {
		RU: "Провайдер режет %s по SNI (DPI)",
		EN: "Your ISP cuts %s by SNI (DPI)",
	},
	"svc.blocked.ip_block": {
		RU: "Провайдер блокирует %s по IP",
		EN: "Your ISP blocks %s by IP",
	},
	"svc.blocked.dns_spoof": {
		RU: "Провайдер подменяет DNS для %s",
		EN: "Your ISP spoofs DNS for %s",
	},
	"svc.blocked.isp_stub": {
		RU: "%s перенаправляется на заглушку провайдера",
		EN: "%s is redirected to an ISP stub page",
	},
	"svc.blocked.geo_block": {
		RU: "%s сам не пускает из твоей страны (нужен VPN с выходом в подходящей стране)",
		EN: "%s refuses your country itself (you need a VPN exit in a suitable country)",
	},
	"svc.blocked.antibot": {
		RU: "%s отвечает защитой от роботов — это не блокировка, VPN тут не поможет (через другую страну ответ тот же)",
		EN: "%s answers with an anti-bot challenge — not a block; a VPN won't help (the same answer comes from other countries)",
	},
	"svc.blocked.service_down": {
		RU: "%s отвечает ошибкой сервера — проблема на их стороне, а не у тебя",
		EN: "%s answers with a server error — the problem is on their side, not yours",
	},
	"svc.blocked.tls_mitm": {
		RU: "%s подсовывают чужой сертификат — соединение кто-то вскрывает по пути",
		EN: "%s is served a foreign certificate — someone is intercepting the connection",
	},
	"svc.blocked.http_drop": {
		RU: "%s: соединение шифруется как надо, но ответа на запрос нет — режут уже содержимое",
		EN: "%s: the encrypted connection is fine, but no answer comes back — the payload itself is dropped",
	},
	"svc.blocked.ip_block_stateful": {
		RU: "%s замолкает после соединения — похоже на блокировку, но по какому признаку, установить не удалось",
		EN: "%s goes silent after connecting — looks blocked, but the trigger couldn't be identified",
	},
	"svc.blocked.dns_nxdomain": {
		RU: "%s не находится ни одним резолвером — возможно, домен больше не существует",
		EN: "%s resolves nowhere — the domain may no longer exist",
	},
	"svc.blocked.unknown": {
		RU: "%s недоступен, причина не определена",
		EN: "%s is unreachable, cause undetermined",
	},
	"svc.via_proxy_ok": {
		RU: "— через VPN они доступны.",
		EN: "— they are reachable through the VPN.",
	},
	"svc.proxy_fails": {
		RU: "%s не работает даже через VPN — похоже, проблема на стороне VPN-сервера.",
		EN: "%s doesn't work even through the VPN — the problem is likely on the VPN side.",
	},

	// предупреждения об окружении
	"warn.proxy_bypass": {
		RU: "Внимание: VPN-прокси запущен, но системный прокси выключен — браузер ходит МИМО VPN.",
		EN: "Warning: a VPN proxy is running, but the system proxy is off — your browser goes AROUND the VPN.",
	},
}
