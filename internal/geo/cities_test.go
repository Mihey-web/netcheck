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

		// Ничего не говорящие имена не должны рождать город из воздуха.
		{"81.27.252.175.rascom.as20764.net", ""},
		{"178.18.225.111.ix.dataix.eu", ""},
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
