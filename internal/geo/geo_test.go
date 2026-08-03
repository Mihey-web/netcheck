package geo

import "testing"

func TestParseIpapi(t *testing.T) {
	raw := []byte(`{"ip":"203.0.113.7","city":"Frankfurt","country_name":"Germany","country_code":"DE","latitude":50.11,"longitude":8.68}`)
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != "203.0.113.7" || got.Code != "DE" || got.Country != "Germany" {
		t.Fatalf("ipapi.co разобран неверно: %+v", got)
	}
	if got.Lat == 0 || got.Lon == 0 {
		t.Errorf("координаты потеряны: %+v", got)
	}
}

func TestParseIfconfig(t *testing.T) {
	raw := []byte(`{"ip":"198.51.100.4","country":"Netherlands","country_iso":"NL","city":"Amsterdam","latitude":52.37,"longitude":4.89}`)
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != "NL" || got.Country != "Netherlands" || got.City != "Amsterdam" {
		t.Fatalf("ifconfig.co разобран неверно: %+v", got)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := parse([]byte(`{"error":true}`)); err == nil {
		t.Error("ответ без IP должен быть ошибкой, а не пустой меткой на карте")
	}
	if _, err := parse([]byte(`не json`)); err == nil {
		t.Error("мусор должен быть ошибкой")
	}
}
