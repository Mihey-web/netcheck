package geo

import (
	"math"
	"strings"
)

// Здесь решается главная беда карты: где роутер стоит на самом деле.
//
// Бесплатная геобаза знает не это, а в какой стране ЗАРЕГИСТРИРОВАН блок
// адресов. Внутри магистралей и CDN это сплошь и рядом другой континент:
// у Facebook маршрут «Испания → США → Эквадор → Германия» с неизменными
// 60 мс на всех четырёх шагах оказался четырьмя роутерами в одном
// Франкфурте, а у Telia «Германия → Британия» — тоже Франкфуртом дважды.
//
// Настоящий источник — имя роутера. Операторы зашивают в него код города,
// потому что сами по нему ориентируются, и поддерживают эту разметку
// годами: ffm-bb1-link.ip.twelve99.net, usw04.fra5.tfbnw.net,
// ae-1.edge3.Frankfurt1.Level3.net. Чаще всего это код аэропорта IATA,
// реже — собственное сокращение сети.

// LatLon — точка на земле.
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// Place — город, распознанный по имени роутера.
type Place struct {
	Name string `json:"name"`
	At   LatLon `json:"at"`
}

func at(name string, lat, lon float64) Place { return Place{Name: name, At: LatLon{lat, lon}} }

// cityCodes — метки городов в именах роутеров. Ключи только в нижнем
// регистре и не короче трёх букв: двухбуквенные совпадали бы со служебными
// кусками имён вроде «ae» или «bb».
var cityCodes = map[string]Place{}

func addCodes(p Place, codes ...string) {
	for _, c := range codes {
		cityCodes[c] = p
	}
}

func init() {
	// ── Европа ───────────────────────────────────────────────────
	addCodes(at("Frankfurt", 50.11, 8.68), "fra", "ffm", "frnkge", "frankfurt")
	addCodes(at("Amsterdam", 52.37, 4.90), "ams", "amst", "amstnl", "amsterdam")
	addCodes(at("London", 51.51, -0.13), "lon", "ldn", "lhr", "londen", "london")
	addCodes(at("Paris", 48.86, 2.35), "par", "prs", "cdg", "pariwq", "parifr", "paris")
	addCodes(at("Stockholm", 59.33, 18.07), "sto", "arn", "stockholm")
	addCodes(at("Copenhagen", 55.68, 12.57), "cph", "kbn", "copenhagen")
	addCodes(at("Oslo", 59.91, 10.75), "osl", "oslo")
	addCodes(at("Helsinki", 60.17, 24.94), "hel", "hls", "helsinki")
	addCodes(at("Warsaw", 52.23, 21.01), "waw", "warsaw")
	addCodes(at("Prague", 50.08, 14.44), "prg", "prague", "praha")
	addCodes(at("Vienna", 48.21, 16.37), "vie", "vienna", "wien")
	addCodes(at("Milan", 45.46, 9.19), "mil", "mlan", "mxp", "milan", "milano")
	addCodes(at("Rome", 41.90, 12.50), "fco", "rome", "roma")
	addCodes(at("Madrid", 40.42, -3.70), "mad", "madrid")
	addCodes(at("Barcelona", 41.39, 2.17), "bcn", "barcelona")
	addCodes(at("Lisbon", 38.72, -9.14), "lis", "lisbon", "lisboa")
	addCodes(at("Zurich", 47.38, 8.54), "zrh", "zurich")
	addCodes(at("Geneva", 46.20, 6.14), "gva", "geneva")
	addCodes(at("Munich", 48.14, 11.58), "muc", "munich", "muenchen")
	addCodes(at("Dusseldorf", 51.23, 6.78), "dus", "dusseldorf")
	addCodes(at("Berlin", 52.52, 13.40), "ber", "berlin")
	addCodes(at("Hamburg", 53.55, 9.99), "ham", "hamburg")
	addCodes(at("Brussels", 50.85, 4.35), "bru", "brussels")
	addCodes(at("Dublin", 53.35, -6.26), "dub", "dublin")
	addCodes(at("Manchester", 53.48, -2.24), "manchester")
	addCodes(at("Bucharest", 44.43, 26.10), "otp", "bucharest")
	addCodes(at("Sofia", 42.70, 23.32), "sof", "sofia")
	addCodes(at("Budapest", 47.50, 19.04), "bud", "budapest")
	addCodes(at("Istanbul", 41.01, 28.98), "ist", "istanbul")
	addCodes(at("Athens", 37.98, 23.73), "ath", "athens")
	addCodes(at("Riga", 56.95, 24.11), "rix", "riga")
	addCodes(at("Vilnius", 54.69, 25.28), "vno", "vilnius")
	addCodes(at("Tallinn", 59.44, 24.75), "tll", "tallinn")
	addCodes(at("Belgrade", 44.79, 20.45), "beg", "belgrade")

	// ── Россия и соседи ──────────────────────────────────────────
	addCodes(at("Москва", 55.75, 37.62), "msk", "mow", "dme", "svo", "moscow", "moskva")
	addCodes(at("Санкт-Петербург", 59.94, 30.31), "spb", "led", "piter", "petersburg")
	addCodes(at("Екатеринбург", 56.84, 60.61), "ekb", "svx", "ekaterinburg")
	addCodes(at("Новосибирск", 55.03, 82.92), "nsk", "ovb", "novosibirsk")
	addCodes(at("Ростов-на-Дону", 47.23, 39.72), "rnd", "rov", "rostov")
	addCodes(at("Краснодар", 45.04, 38.98), "krd", "krr", "krasnodar")
	addCodes(at("Самара", 53.20, 50.15), "kuf", "samara")
	addCodes(at("Казань", 55.79, 49.11), "kzn", "kazan")
	addCodes(at("Владивосток", 43.12, 131.89), "vvo", "vladivostok")
	addCodes(at("Нижний Новгород", 56.33, 44.00), "goj", "nnov")
	addCodes(at("Симферополь", 44.95, 34.10), "sip", "simferopol")
	addCodes(at("Киев", 50.45, 30.52), "iev", "kbp", "kiev", "kyiv")
	addCodes(at("Минск", 53.90, 27.57), "msq", "minsk")
	addCodes(at("Алматы", 43.24, 76.89), "ala", "almaty")

	// ── Северная Америка ─────────────────────────────────────────
	addCodes(at("New York", 40.71, -74.01), "nyc", "nyk", "jfk", "ewr", "nycmny", "newyork")
	addCodes(at("Ashburn", 39.04, -77.49), "iad", "ash", "ashbvi", "ashburn", "washington")
	addCodes(at("Chicago", 41.88, -87.63), "chi", "ord", "chcgil", "chicago")
	addCodes(at("Dallas", 32.78, -96.80), "dfw", "dls", "dllstx", "dallas")
	addCodes(at("Los Angeles", 34.05, -118.24), "lax", "lsanca", "losangeles")
	addCodes(at("San Jose", 37.34, -121.89), "sjc", "sanjca", "sanjose")
	addCodes(at("San Francisco", 37.77, -122.42), "sfo", "sanfrancisco")
	addCodes(at("Seattle", 47.61, -122.33), "sea", "sttlwa", "seattle")
	addCodes(at("Atlanta", 33.75, -84.39), "atl", "atlanta")
	addCodes(at("Miami", 25.76, -80.19), "mia", "miami")
	addCodes(at("Denver", 39.74, -104.99), "den", "denver")
	addCodes(at("Phoenix", 33.45, -112.07), "phx", "phoenix")
	addCodes(at("Toronto", 43.65, -79.38), "yyz", "toronto")
	addCodes(at("Montreal", 45.50, -73.57), "yul", "montreal")

	// ── Остальной мир ────────────────────────────────────────────
	addCodes(at("Tokyo", 35.68, 139.69), "nrt", "hnd", "tky", "tokyjp", "tokyo")
	addCodes(at("Hong Kong", 22.32, 114.17), "hkg", "hkngcn", "hongkong")
	addCodes(at("Singapore", 1.35, 103.82), "sin", "sng", "sngpsi", "singapore")
	addCodes(at("Sydney", -33.87, 151.21), "syd", "sydney")
	addCodes(at("Seoul", 37.57, 126.98), "icn", "seoul")
	addCodes(at("Mumbai", 19.08, 72.88), "bom", "mumbai")
	addCodes(at("Delhi", 28.61, 77.21), "del", "delhi")
	addCodes(at("Dubai", 25.20, 55.27), "dxb", "dubai")
	addCodes(at("Tel Aviv", 32.08, 34.78), "tlv", "telaviv")
	addCodes(at("Sao Paulo", -23.55, -46.63), "gru", "saopaulo")
	addCodes(at("Johannesburg", -26.20, 28.05), "jnb", "johannesburg")
}

// PlaceFromHost вытаскивает город из имени роутера.
//
// Имя режется на куски по точкам и дефисам, у каждого куска отбрасывается
// цифровой хвост (fra5 → fra, edge3 → edge), и то, что нашлось в словаре,
// и есть ответ. Сравниваются куски целиком, а не подстроки: иначе «border»
// подарил бы нам Чикаго через код ord, а «denver» нашёлся бы в чём угодно.
func PlaceFromHost(host string) (Place, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return Place{}, false
	}
	tokens := strings.FieldsFunc(host, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	for _, tok := range tokens {
		if p, ok := cityCodes[tok]; ok {
			return p, true
		}
		if trimmed := strings.TrimRight(tok, "0123456789"); len(trimmed) >= 3 {
			if p, ok := cityCodes[trimmed]; ok {
				return p, true
			}
		}
	}
	return Place{}, false
}

// KmBetween — расстояние по большому кругу, километры.
func KmBetween(a, b LatLon) float64 {
	const earthKm = 6371
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := rad(b.Lat-a.Lat), rad(b.Lon-a.Lon)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(a.Lat))*math.Cos(rad(b.Lat))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthKm * math.Asin(math.Min(1, math.Sqrt(h)))
}

// ReachableKm — насколько далеко физически может стоять машина, ответившая
// за rtt миллисекунд. В волокне свет идёт около 200 км/мс, ответ проходит
// путь дважды, поэтому радиус — половина.
//
// Оценка заведомо щедрая: она считает, что кабель лежит по прямой (на деле
// он длиннее раза в полтора) и что ни один коммутатор по пути не думает
// ни микросекунды. То есть «не уложился» здесь означает не «маловероятно»,
// а «невозможно ни при каких условиях».
//
// Это тот же довод, что и nearbyRTT, только выраженный в расстоянии,
// а не одним порогом на все случаи жизни.
func ReachableKm(rttMs int64) float64 {
	if rttMs <= 0 {
		return 0 // измерения нет — судить не о чем
	}
	return float64(rttMs) / 2 * 200
}
