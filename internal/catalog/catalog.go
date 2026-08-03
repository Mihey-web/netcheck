// Package catalog — встроенный справочник проверяемых сервисов.
//
// Пользователь отмечает, что проверять; конфиг хранит только список включённых
// идентификаторов. Группа определяет, на какой слой влияет результат, а не
// приговор: действительный механизм блокировки определяет пакет analyze
// по замерам.
package catalog

// Группы целей. От группы зависит, на какой слой влияет результат.
const (
	GroupRunet  = "runet"   // местные сервисы: живы ли и не сломал ли их VPN
	GroupGlobal = "global"  // заведомо неблокируемое: базовая связность
	GroupBlock  = "blocked" // то, что режет провайдер
	GroupGeo    = "geo"     // сервис сам не пускает по стране
)

// Groups — порядок групп в интерфейсе.
var Groups = []string{GroupRunet, GroupGlobal, GroupBlock, GroupGeo}

type Service struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Group string `json:"group"`
	// Name/NameEN — как сервис называется для человека.
	Name   string `json:"name"`
	NameEN string `json:"nameEn"`
	// Note/NoteEN — зачем эта цель в списке. Пусто — пояснять нечего.
	Note   string `json:"note"`
	NoteEN string `json:"noteEn"`
}

// Services — справочник. Порядок внутри группы = порядок в интерфейсе.
// Колонки: ID, хост, группа, имя RU, имя EN, пояснение RU, пояснение EN.
var Services = []Service{
	// ── местные (СНГ) ────────────────────────────────────────────
	{"ya", "ya.ru", GroupRunet, "Яндекс", "Yandex", "поиск №1 в рунете", "the #1 search engine in RuNet"},
	{"vk", "vk.com", GroupRunet, "ВКонтакте", "VK", "соцсеть №1", "the #1 social network here"},
	{"dzen", "dzen.ru", GroupRunet, "Дзен", "Dzen", "", ""},
	{"mail", "mail.ru", GroupRunet, "Mail.ru", "Mail.ru", "", ""},
	{"gosuslugi", "gosuslugi.ru", GroupRunet, "Госуслуги", "Gosuslugi", "часто ломается при включённом VPN", "often breaks while a VPN is on"},
	{"sber", "sberbank.ru", GroupRunet, "Сбербанк", "Sberbank", "антифрод режет иностранные IP", "anti-fraud rejects foreign IPs"},
	{"tbank", "tbank.ru", GroupRunet, "Т-Банк", "T-Bank", "антифрод режет иностранные IP", "anti-fraud rejects foreign IPs"},
	{"wildberries", "wildberries.ru", GroupRunet, "Wildberries", "Wildberries", "", ""},
	{"ozon", "ozon.ru", GroupRunet, "Ozon", "Ozon", "", ""},
	{"avito", "avito.ru", GroupRunet, "Авито", "Avito", "", ""},
	{"kinopoisk", "kinopoisk.ru", GroupRunet, "Кинопоиск", "Kinopoisk", "", ""},
	{"rutube", "rutube.ru", GroupRunet, "RuTube", "RuTube", "", ""},
	{"hh", "hh.ru", GroupRunet, "hh.ru", "hh.ru", "", ""},
	{"2gis", "2gis.ru", GroupRunet, "2ГИС", "2GIS", "", ""},
	{"kaspi", "kaspi.kz", GroupRunet, "Kaspi", "Kaspi", "Казахстан", "Kazakhstan"},
	{"onliner", "onliner.by", GroupRunet, "Onliner", "Onliner", "Беларусь", "Belarus"},

	// ── заграница, которую никто не режет ────────────────────────
	{"cloudflare", "cloudflare.com", GroupGlobal, "Cloudflare", "Cloudflare", "эталон связности", "the connectivity yardstick"},
	{"wikipedia", "wikipedia.org", GroupGlobal, "Wikipedia", "Wikipedia", "", ""},
	{"github", "github.com", GroupGlobal, "GitHub", "GitHub", "", ""},
	{"google", "google.com", GroupGlobal, "Google", "Google", "", ""},
	{"microsoft", "microsoft.com", GroupGlobal, "Microsoft", "Microsoft", "", ""},
	{"apple", "apple.com", GroupGlobal, "Apple", "Apple", "", ""},
	{"amazon", "amazon.com", GroupGlobal, "Amazon", "Amazon", "", ""},
	{"stackoverflow", "stackoverflow.com", GroupGlobal, "Stack Overflow", "Stack Overflow", "", ""},
	{"steam", "store.steampowered.com", GroupGlobal, "Steam", "Steam", "", ""},
	{"reddit", "reddit.com", GroupGlobal, "Reddit", "Reddit", "", ""},

	// ── блокируется провайдером ──────────────────────────────────
	{"youtube", "youtube.com", GroupBlock, "YouTube", "YouTube", "замедляется ТСПУ", "throttled by DPI boxes"},
	{"discord", "discord.com", GroupBlock, "Discord", "Discord", "заблокирован в РФ", "blocked in Russia"},
	{"instagram", "instagram.com", GroupBlock, "Instagram", "Instagram", "Meta, заблокирован", "Meta, blocked"},
	{"facebook", "facebook.com", GroupBlock, "Facebook", "Facebook", "Meta, заблокирован", "Meta, blocked"},
	{"x", "x.com", GroupBlock, "X (Twitter)", "X (Twitter)", "блокировка и замедление", "blocked and throttled"},
	{"signal", "signal.org", GroupBlock, "Signal", "Signal", "в реестре запрещённых", "on the blocklist register"},
	{"linkedin", "linkedin.com", GroupBlock, "LinkedIn", "LinkedIn", "заблокирован с 2016", "blocked since 2016"},
	{"telegram", "web.telegram.org", GroupBlock, "Telegram Web", "Telegram Web", "ограничения с 2026", "restricted since 2026"},
	{"whatsapp", "web.whatsapp.com", GroupBlock, "WhatsApp Web", "WhatsApp Web", "ограничения звонков", "calls restricted"},
	{"viber", "viber.com", GroupBlock, "Viber", "Viber", "заблокирован в РФ", "blocked in Russia"},
	{"tiktok", "tiktok.com", GroupBlock, "TikTok", "TikTok", "ограничения в РФ", "restricted in Russia"},
	{"twitch", "twitch.tv", GroupBlock, "Twitch", "Twitch", "", ""},
	{"rutracker", "rutracker.org", GroupBlock, "RuTracker", "RuTracker", "классика блокировок", "a blocking classic"},
	{"soundcloud", "soundcloud.com", GroupBlock, "SoundCloud", "SoundCloud", "", ""},

	// ── сервис сам не пускает по стране ──────────────────────────
	{"chatgpt", "chatgpt.com", GroupGeo, "ChatGPT", "ChatGPT", "не пускает российские IP", "refuses Russian IPs"},
	{"claude", "claude.ai", GroupGeo, "Claude", "Claude", "не пускает российские IP", "refuses Russian IPs"},
	{"gemini", "gemini.google.com", GroupGeo, "Gemini", "Gemini", "", ""},
	{"netflix", "netflix.com", GroupGeo, "Netflix", "Netflix", "ушёл из РФ", "left the Russian market"},
	{"spotify", "spotify.com", GroupGeo, "Spotify", "Spotify", "ушёл из РФ", "left the Russian market"},
	{"figma", "figma.com", GroupGeo, "Figma", "Figma", "ушла из РФ", "left the Russian market"},
	{"canva", "canva.com", GroupGeo, "Canva", "Canva", "ушла из РФ", "left the Russian market"},
	{"adobe", "adobe.com", GroupGeo, "Adobe", "Adobe", "ушёл из РФ", "left the Russian market"},
	{"paypal", "paypal.com", GroupGeo, "PayPal", "PayPal", "ушёл из РФ", "left the Russian market"},
	{"notion", "notion.so", GroupGeo, "Notion", "Notion", "", ""},
}

// byID — быстрый доступ к сервису.
var byID = func() map[string]Service {
	m := make(map[string]Service, len(Services))
	for _, s := range Services {
		m[s.ID] = s
	}
	return m
}()

// Get возвращает сервис по идентификатору.
func Get(id string) (Service, bool) {
	s, ok := byID[id]
	return s, ok
}

// Item — запись справочника на одном языке: ровно то, что рисует интерфейс.
type Item struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Group string `json:"group"`
	Name  string `json:"name"`
	Note  string `json:"note"`
}

// Localized отдаёт справочник на выбранном языке ("en" — английский,
// всё остальное — русский).
func Localized(lang string) []Item {
	out := make([]Item, 0, len(Services))
	for _, s := range Services {
		it := Item{ID: s.ID, Host: s.Host, Group: s.Group, Name: s.Name, Note: s.Note}
		if lang == "en" {
			it.Name, it.Note = s.NameEN, s.NoteEN
		}
		out = append(out, it)
	}
	return out
}

// Presets — готовые наборы. Прогон растёт линейно по числу целей,
// поэтому «полный» набор — осознанный выбор, а не значение по умолчанию.
var Presets = map[string][]string{
	// самое частое «почему не работает» — за несколько секунд
	"quick": {"ya", "cloudflare", "youtube", "discord", "chatgpt"},
	// разумный набор по умолчанию
	"standard": {
		"ya", "vk", "gosuslugi", "wildberries", "tbank",
		"cloudflare", "wikipedia", "github",
		"youtube", "discord", "instagram", "x", "signal",
		"chatgpt", "netflix", "spotify",
	},
	// только то, что режут
	"blocked": {"youtube", "discord", "instagram", "facebook", "x", "signal",
		"linkedin", "telegram", "whatsapp", "viber", "tiktok", "twitch", "rutracker"},
}

// All — идентификаторы всех сервисов справочника.
func All() []string {
	ids := make([]string, 0, len(Services))
	for _, s := range Services {
		ids = append(ids, s.ID)
	}
	return ids
}

// Custom — цель, добавленная пользователем вручную.
type Custom struct {
	Host  string `yaml:"host" json:"host"`
	Group string `yaml:"group" json:"group"`
}

// Resolve раскладывает выбранные идентификаторы и пользовательские цели
// по группам. Неизвестные идентификаторы молча пропускаются: справочник
// меняется между версиями, и старый конфиг не должен ронять прогон.
func Resolve(enabled []string, custom []Custom) (runet, global, blocked, geo []string) {
	add := func(group, host string) {
		switch group {
		case GroupRunet:
			runet = append(runet, host)
		case GroupGlobal:
			global = append(global, host)
		case GroupGeo:
			geo = append(geo, host)
		default:
			blocked = append(blocked, host)
		}
	}
	for _, id := range enabled {
		if s, ok := byID[id]; ok {
			add(s.Group, s.Host)
		}
	}
	for _, c := range custom {
		if c.Host != "" {
			add(c.Group, c.Host)
		}
	}
	return
}

// IDForHost — обратный поиск: по какому идентификатору живёт этот хост.
// Нужен, чтобы перенести старый конфиг со списком хостов на выбор сервисов.
func IDForHost(host string) (string, bool) {
	for _, s := range Services {
		if s.Host == host {
			return s.ID, true
		}
	}
	return "", false
}
