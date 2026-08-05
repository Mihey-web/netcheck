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
	"verdict.runet_down_vpn": {
		RU: "Заграница работает, а рунет недоступен — похоже, VPN заворачивает и российский трафик.",
		EN: "Foreign sites work, but local (RU) sites are unreachable — the VPN is probably routing local traffic too.",
	},
	// то же самое, но без VPN: сваливать на него, когда его нет, — выдумка
	"verdict.runet_down": {
		RU: "Заграница работает, а российские сайты не открываются — похоже на проблему маршрутизации у провайдера.",
		EN: "Foreign sites work, but Russian sites don't open — this looks like a routing problem at your ISP.",
	},
	"verdict.apipa": {
		RU: "Роутер не выдал адрес: Windows назначила себе временный 169.254.x.x. Wi-Fi подключён, но сети за ним нет — переподключитесь к сети или перезагрузите роутер.",
		EN: "The router handed out no address: Windows fell back to a temporary 169.254.x.x. Wi-Fi is connected, but there is no network behind it — reconnect or restart the router.",
	},
	"verdict.no_route": {
		RU: "У соединения нет маршрута наружу: шлюз не задан. Сеть подключена, но не настроена.",
		EN: "The connection has no route out: no gateway is set. The network is attached but not configured.",
	},
	"verdict.captive": {
		RU: "Это сеть с входом через браузер: контрольный запрос перехватывают и отвечают на него вместо адресата. Откройте браузер и авторизуйтесь в сети — до этого не заработает ничего.",
		EN: "This network wants you to sign in through a browser: the control request is intercepted and answered by someone else. Open a browser and log in — nothing will work until you do.",
	},
	"verdict.http_only": {
		RU: "Наружу связь есть — обычный HTTP-запрос доходит, — но ни один сайт не открывается. Похоже, режут именно HTTPS или сломан DNS.",
		EN: "There is connectivity — a plain HTTP request gets through — yet no site opens. It looks like HTTPS is being blocked or DNS is broken.",
	},
	"verdict.nothing_checked": {
		RU: "Проверять было нечего: на вкладке «Сервисы» не выбрано ни одной цели.",
		EN: "There was nothing to check: no targets are selected on the “Services” tab.",
	},
	"verdict.services_skipped": {
		RU: "Проверка сервисов пропущена: пока не открывается ни один сайт, её результат ничего бы не значил.",
		EN: "The per-service checks were skipped: while no site opens at all, their result would mean nothing.",
	},
	"dns.spoof": {
		RU: "Резолвер вернул адрес, которого у этого домена быть не может — DNS-ответы подменяются (провайдером, роутером или локальным фильтром).",
		EN: "The resolver returned an address this domain cannot have — DNS answers are being spoofed (by the ISP, the router or a local filter).",
	},
	"dns.down": {
		RU: "Системный DNS не отвечает — имена сайтов не превращаются в адреса. Обычно помогает смена DNS-сервера в настройках адаптера.",
		EN: "The system DNS is not answering — host names don't resolve to addresses. Switching the DNS server in the adapter settings usually helps.",
	},
	"svc.dns_unreachable": {
		RU: "Причину по каждому сервису установить не удалось: имена не резолвятся, спрашивать было нечем.",
		EN: "The per-service cause couldn't be established: names don't resolve, so there was nothing to ask.",
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
		RU: "%s: резолверы отвечают, что такого имени нет — возможно, домен больше не существует",
		EN: "%s: the resolvers answer that no such name exists — the domain may no longer exist",
	},
	"svc.blocked.dns_silent": {
		RU: "%s: имя не удалось выяснить — резолверы не ответили, спрашивать было нечем",
		EN: "%s: the name couldn't be resolved — the resolvers stayed silent, there was nothing to ask",
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
