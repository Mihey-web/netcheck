package geo

import "testing"

// Имена взяты из настоящего прогона — тех самых шагов, которые геобаза
// разбросала по четырём странам, а на деле они все во Франкфурте.
func TestPlaceFromHost(t *testing.T) {
	cases := []struct {
		host string
		want string // пусто — город определяться не должен
	}{
		// Facebook: база говорила «Испания» и «США», имя говорит Франкфурт
		{"po4002.asw02.fra2.tfbnw.net", "Frankfurt"},
		{"usw04.fra5.tfbnw.net", "Frankfurt"},
		// Telia: база говорила «Британия», имя говорит Франкфурт
		{"ffm-b17-link.ip.twelve99.net", "Frankfurt"},
		{"ffm-bb1-link.ip.twelve99.net", "Frankfurt"},
		// прочие принятые в отрасли записи
		{"ae-1.edge3.Frankfurt1.Level3.net", "Frankfurt"},
		{"be2345.ccr41.ams03.atlas.cogentco.com", "Amsterdam"},
		{"ae-9.r24.londen12.uk.bb.gin.ntt.net", "London"},
		{"100ge0-32.core1.sto1.he.net", "Stockholm"},
		{"msk-ix-gw.example.ru", "Москва"},
		// Из прогона после починки волн: тот же Facebook, но маршрут теперь
		// не рвётся и доходит до своей стокгольмской площадки. Заодно проверка,
		// что соседние куски имени (asw04, psw03, shv) города не выдумывают.
		{"po4005.asw04.arn2.tfbnw.net", "Stockholm"},
		{"psw03.arn2.tfbnw.net", "Stockholm"},
		{"edge-star-mini-shv-01-arn2.facebook.com", "Stockholm"},

		// Ничего не говорящие имена не должны рождать город из воздуха.
		{"81.27.252.175.rascom.as20764.net", ""},
		{"178.18.225.111.ix.dataix.eu", ""},
		{"ip-91-241-196-1.static.eastnet.online", ""},
		// Мусорная PTR-запись: провайдеры сплошь и рядом оставляют её
		// по умолчанию. Города из неё быть не должно.
		{"localhost", ""},
		{"", ""},
		// «border» не должен превратиться в Чикаго через код ord:
		// куски имени сравниваются целиком, а не как подстроки
		{"border1.example.net", ""},
		{"po1.agg2.example.com", ""},
	}

	for _, c := range cases {
		p, ok := PlaceFromHost(c.host)
		if c.want == "" {
			if ok {
				t.Errorf("%q: город выдуман — %s", c.host, p.Name)
			}
			continue
		}
		if !ok {
			t.Errorf("%q: город не распознан, ждали %s", c.host, c.want)
			continue
		}
		if p.Name != c.want {
			t.Errorf("%q: got %s, want %s", c.host, p.Name, c.want)
		}
	}
}

// Проверка физики: за 60 мс до Эквадора не успевает даже свет, а до
// Франкфурта успевает с большим запасом.
func TestMarkImplausible(t *testing.T) {
	donetsk := &LatLon{Lat: 48.0, Lon: 37.8}
	nodes := []Node{
		{N: 1, RTTms: 60, At: &LatLon{Lat: 50.11, Lon: 8.68}}, // Франкфурт ~2000 км
		{N: 2, RTTms: 60, At: &LatLon{Lat: -1.4, Lon: -78.5}}, // Эквадор ~11500 км
		{N: 3, RTTms: 45, At: &LatLon{Lat: 39.5, Lon: -99.0}}, // США ~9200 км
		{N: 4, RTTms: 0, At: &LatLon{Lat: -33.9, Lon: 151.2}}, // без замера — не судим
		{N: 5, RTTms: 10, Country: "NL"},                      // без координат — не судим
	}
	MarkImplausible(nodes, donetsk)

	want := []bool{false, true, true, false, false}
	for i, w := range want {
		if nodes[i].Implausible != w {
			t.Errorf("шаг %d: implausible=%v, ждали %v", nodes[i].N, nodes[i].Implausible, w)
		}
	}

	// Без точки отсчёта не выбрасываем ничего: отсутствие данных — не улика.
	clean := []Node{{N: 1, RTTms: 60, At: &LatLon{Lat: -1.4, Lon: -78.5}}}
	MarkImplausible(clean, nil)
	if clean[0].Implausible {
		t.Error("без якоря шаг помечен невозможным")
	}
}

// Догадка о городе и знание о городе опровергаются по-разному. Роутер
// собственного провайдера в четырёх миллисекундах от Донецка — настоящий шаг,
// и то, что узел связи страны стоит в Москве, говорит о негодности догадки,
// а не шага. Раньше разницы не было, и это выбрасывало первый же публичный
// шаг, а с ним и весь луч: из двенадцати маршрутов рисовалось пять.
func TestGuessedPointLosesPointNotHop(t *testing.T) {
	donetsk := &LatLon{Lat: 48.33, Lon: 39.95}
	msk := func() *LatLon { p, _ := HubOf("RU"); return &p.At }

	nodes := []Node{
		{N: 2, RTTms: 4, Country: "RU", At: msk(), Guessed: true},
		{N: 3, RTTms: 60, At: &LatLon{Lat: -1.4, Lon: -78.5}}, // Эквадор по имени
	}
	MarkImplausible(nodes, donetsk)

	if nodes[0].Implausible {
		t.Error("шаг провайдера выброшен из-за неудачной догадки о городе")
	}
	if nodes[0].At != nil || nodes[0].Guessed {
		t.Errorf("негодная догадка осталась точкой на карте: %+v", nodes[0].At)
	}
	if nodes[0].Country != "RU" {
		t.Error("вместе с точкой потеряна страна")
	}
	if !nodes[1].Implausible {
		t.Error("точка из имени роутера обязана опровергаться временем")
	}
}

// «Стокгольм → Дублин → Стокгольм» за одну миллисекунду: сходить в Ирландию
// и вернуться маршрут не успевал ни при каком раскладе. Шаг настоящий,
// но разместить его негде — на карте его быть не должно.
func TestGuessedPointNeedsReachableLeg(t *testing.T) {
	donetsk := &LatLon{Lat: 48.33, Lon: 39.95}
	sto := LatLon{Lat: 59.33, Lon: 18.07}
	dub, _ := HubOf("IE")

	nodes := []Node{
		{N: 10, RTTms: 54, City: "Stockholm", At: &sto},
		{N: 11, RTTms: 53, Country: "IE", At: &dub.At, Guessed: true},
		{N: 12, RTTms: 50, City: "Stockholm", At: &sto},
	}
	MarkImplausible(nodes, donetsk)

	if !nodes[1].Implausible || nodes[1].At != nil {
		t.Errorf("крюк, которого нет во времени, оставлен на карте: %+v", nodes[1])
	}
	if nodes[0].Implausible || nodes[2].Implausible {
		t.Error("настоящие шаги пострадали вместе с выдуманным")
	}
}

// Геометрический центр страны — плохая догадка: у России он в Сибири,
// у США в прериях Канзаса, а магистрали идут не там.
func TestHubOf(t *testing.T) {
	cases := map[string]string{"RU": "Москва", "US": "Ashburn", "DE": "Frankfurt", "SE": "Stockholm"}
	for code, want := range cases {
		p, ok := HubOf(code)
		if !ok || p.Name != want {
			t.Errorf("%s: got %q (ok=%v), want %s", code, p.Name, ok, want)
		}
	}
	if _, ok := HubOf("XX"); ok {
		t.Error("неизвестная страна не должна получать узел из воздуха")
	}
	if _, ok := HubOf(""); ok {
		t.Error("пустая страна не должна получать узел")
	}
}

func TestAnchorPrefersRealCoordinates(t *testing.T) {
	nodes := []Node{{N: 1, At: &LatLon{Lat: 50.11, Lon: 8.68}}}

	if a := Anchor(nodes, &Info{Lat: 55.75, Lon: 37.62}); a == nil || a.Lat != 55.75 {
		t.Errorf("координаты пользователя должны быть в приоритете, got %+v", a)
	}
	// Нулевые координаты — это «не определилось», а не остров у берегов Ганы.
	if a := Anchor(nodes, &Info{}); a == nil || a.Lat != 50.11 {
		t.Errorf("при пустой геолокации якорь берётся с первого размещённого шага, got %+v", a)
	}
	if a := Anchor(nil, nil); a != nil {
		t.Errorf("брать якорь неоткуда, got %+v", a)
	}
}

// Якорь в Guessed-точке — это Москва у жителя Владивостока: от неё
// MarkImplausible снимал честные точки. Догадка в точку отсчёта не годится,
// а без единой exact-точки якоря нет вовсе: отсутствие данных — не улика.
func TestAnchorSkipsGuessed(t *testing.T) {
	msk := func() *LatLon { p, _ := HubOf("RU"); return &p.At }

	nodes := []Node{
		{N: 2, Country: "RU", At: msk(), Guessed: true},
		{N: 3, City: "Владивосток", At: &LatLon{Lat: 43.12, Lon: 131.89}},
	}
	if a := Anchor(nodes, nil); a == nil || a.Lat != 43.12 {
		t.Errorf("якорь должен встать в точку из имени роутера, а не в догадку: %+v", a)
	}

	onlyGuessed := []Node{{N: 2, Country: "RU", At: msk(), Guessed: true}}
	if a := Anchor(onlyGuessed, nil); a != nil {
		t.Errorf("якорь поставлен по одной лишь догадке: %+v", a)
	}
}

// Каждая страна в hubs обязана указывать на существующий город: опечатка
// в коде города молча оставляла бы страну без точки на карте.
func TestHubsResolve(t *testing.T) {
	for country, code := range hubs {
		if _, ok := cityCodes[code]; !ok {
			t.Errorf("%s: код узла %q не найден среди городов", country, code)
		}
	}
	// Добитые страны из бэклога волны 5 — на месте.
	for _, c := range []string{
		"CN", "TW", "TH", "VN", "ID", "MY", "PH", "PK", "BD",
		"MX", "AR", "CL", "PE", "CO", "EG", "NG", "SA", "NZ", "GE", "AM",
	} {
		if _, ok := HubOf(c); !ok {
			t.Errorf("у страны %s нет узла связи", c)
		}
	}
}
