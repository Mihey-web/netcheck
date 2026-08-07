package i18n

// messages — единственное место с пользовательским текстом.
// %s в svc.* — перечисление сервисов через запятую.
var messages = map[string]map[Lang]string{
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
		RU: "Проверка остановлена: пока не отвечает роутер, остальные проверки всё равно покажут «недоступно».",
		EN: "The run was stopped: while the router is unreachable, everything above would report \"unreachable\" anyway.",
	},
	// отменённый прогон — не диагноз: замеры неполные, вердикта по ним нет
	"verdict.canceled": {
		RU: "Проверка прервана — по неполным замерам вердикт не ставится.",
		EN: "The check was interrupted — no verdict is drawn from incomplete measurements.",
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
		EN: "The router didn't hand out an address: Windows fell back to a temporary 169.254.x.x. Wi-Fi is connected, but there is no network behind it — reconnect or restart the router.",
	},
	"verdict.no_route": {
		RU: "У соединения нет маршрута наружу: шлюз не задан. Сеть подключена, но не настроена.",
		EN: "The connection has no route out: no gateway is set. The network is connected but not configured.",
	},
	"verdict.captive": {
		RU: "Это сеть с входом через браузер — как Wi-Fi в кафе или гостинице: пока вы не войдёте через её страницу, она никуда не пускает. Откройте браузер и авторизуйтесь — до этого не заработает ничего.",
		EN: "This network requires signing in through a browser — like cafe or hotel Wi-Fi: until you log in on its page, it lets nothing through. Open a browser and sign in — nothing will work until you do.",
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
		RU: "На запрос имени пришёл адрес, которого у этого домена быть не может — DNS-ответы подменяются (провайдером, роутером или локальным фильтром).",
		EN: "A name lookup returned an address this domain cannot have — DNS answers are being spoofed (by the ISP, the router or a local filter).",
	},
	"dns.down": {
		RU: "Системный DNS не отвечает — имена сайтов не превращаются в адреса. Обычно помогает смена DNS-сервера в настройках адаптера.",
		EN: "The system DNS is not answering — host names don't resolve to addresses. Switching the DNS server in the adapter settings usually helps.",
	},
	"svc.dns_unreachable": {
		RU: "Причину по каждому сервису установить не удалось: имена сайтов не превратились в адреса — спросить было не у кого.",
		EN: "The per-service cause couldn't be established: site names didn't resolve to addresses — there was no one to ask.",
	},

	// блокировки по механизмам
	"svc.blocked.dpi_sni": {
		RU: "Провайдер обрывает соединения с %s, распознав имя сайта при подключении (SNI)",
		EN: "Your ISP drops connections to %s based on the site name (SNI)",
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
		EN: "%s is redirected to your ISP's block page",
	},
	"svc.blocked.geo_block": {
		RU: "%s сам не пускает из вашей страны (нужен VPN с выходом в подходящей стране)",
		EN: "%s itself blocks visitors from your country (you need a VPN exit in a suitable country)",
	},
	"svc.blocked.antibot": {
		RU: "%s отвечает защитой от роботов — это не блокировка, VPN тут не поможет (через другую страну ответ тот же)",
		EN: "%s answers with an anti-bot challenge — not a block; a VPN won't help (the same answer comes from other countries)",
	},
	"svc.blocked.service_down": {
		RU: "%s отвечает ошибкой сервера — проблема на их стороне, а не у вас",
		EN: "%s answers with a server error — the problem is on their side, not yours",
	},
	"svc.blocked.tls_mitm": {
		RU: "Вместо настоящего сертификата %s приходит чужой — соединение кто-то вскрывает по пути",
		EN: "Instead of the real certificate for %s, someone else's arrives — the connection is being intercepted along the way",
	},
	"svc.blocked.http_drop": {
		RU: "%s: защищённое соединение устанавливается, но ответ не приходит — блокируют не подключение, а передачу данных внутри него",
		EN: "%s: the encrypted connection is established, but no answer comes back — it's the data inside it that gets blocked, not the connection",
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
		RU: "%s: имя не удалось превратить в адрес — ни один DNS-сервер не ответил",
		EN: "%s: the name couldn't be turned into an address — no DNS server answered",
	},
	"svc.blocked.unknown": {
		RU: "%s недоступен, причина не определена",
		EN: "%s is unreachable, cause undetermined",
	},
	"svc.via_proxy_ok": {
		RU: "— через VPN они доступны.",
		EN: "— they are reachable through the VPN.",
	},
	// Проверка «я не робот» — не диагноз, а честное «проверить не удалось».
	// Сервер ответил и путь до него чист; капчу решает браузер, и у него это
	// выходит. Раньше такой ответ записывался в блокировки, и программа
	// объявляла недоступным сайт, через который пользователь с ней и говорил.
	"svc.challenge": {
		RU: "%s отвечает проверкой «я не робот» — это не блокировка: сервер отвечает и путь до него чист. В браузере такие сайты открываются, а программой их проверить нельзя.",
		EN: "%s answers with an “I am not a robot” check — this is not a block: the server responds and the path to it is clean. Such sites open in a browser; this program cannot check them.",
	},
	// Счёт, а не флаг. Прежнее «через VPN они доступны» показывалось лишь
	// тогда, когда через VPN работало всё до единого, и любые три сервиса,
	// не работающие нигде, заставляли программу промолчать про остальные
	// двадцать. Человек видел длинный список блокировок и ни слова о том,
	// что через его собственный VPN почти всё это открывается.
	"svc.via_proxy_some": {
		RU: "— через VPN из них открывается %d из %d.",
		EN: "— %d of %d open through the VPN.",
	},
	"svc.proxy_fails": {
		RU: "%s не работает даже через VPN — похоже, проблема на стороне VPN-сервера.",
		EN: "%s doesn't work even through the VPN — the problem is likely on the VPN side.",
	},

	// заметки карты и трассировки. Аргументы приходят строками (номер шага
	// и миллисекунды уже отформатированы), поэтому всюду %s, а не %d:
	// []any после JSON-истории превращает числа в float64, и %d ломался бы.
	"map.note.no_reply": {
		RU: "не ответил ни один шаг маршрута",
		EN: "no hop of the route answered",
	},
	"map.note.opaque_start": {
		RU: "маршрут не прослеживается: ICMP режут с первого же шага, но сервис отвечает",
		EN: "the route can't be traced: ICMP is filtered from the very first hop, yet the service responds",
	},
	"map.note.blocked_at_target": {
		RU: "пакеты доходят до цели (шаг %s), но сервис не отвечает — режут не маршрут, а само соединение",
		EN: "packets reach the target (hop %s), but the service doesn't answer — it's the connection being cut, not the route",
	},
	"map.note.opaque": {
		RU: "сервис отвечает, но маршрут дальше шага %s не прослеживается — по пути режут ICMP",
		EN: "the service responds, but the route can't be traced past hop %s — ICMP is filtered along the way",
	},
	"map.note.closed": {
		RU: "маршрут закрыт на шаге %s: %s",
		EN: "the route is closed at hop %s: %s",
	},
	"map.note.silence": {
		RU: "дальше шага %s тишина, последним ответил %s",
		EN: "silence past hop %s, the last to answer was %s",
	},
	"map.note.far_country": {
		RU: "ответ за %s мс, хотя адрес числится за страной %s — отвечает ближайшая точка присутствия, а не сервер там",
		EN: "an answer in %s ms although the address is registered to %s — the nearest point of presence responds, not a server there",
	},
	"map.note.trace_failed": {
		RU: "трассировка не отработала: %s",
		EN: "the trace didn't run: %s",
	},

	// история прогонов: подпись перед списком упавших сервисов в однострочном
	// итоге. Итог хранится строкой, но при чтении истории пересобирается из
	// отчёта на текущем языке (history.LoadLocalized → Summarize).
	"hist.broken": {
		RU: "не открываются",
		EN: "down",
	},

	// предупреждения об окружении
	"warn.proxy_bypass": {
		RU: "Внимание: VPN-прокси запущен, но системный прокси выключен — браузер ходит мимо VPN.",
		EN: "Warning: a VPN proxy is running, but the system proxy is off — your browser bypasses the VPN.",
	},
}
