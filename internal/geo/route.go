package geo

import (
	"fmt"
	"net/netip"

	"github.com/mihey/netcheck/internal/geo/ipdb"
	"github.com/mihey/netcheck/internal/probe"
)

// Node — шаг маршрута, размеченный по офлайн-базе.
type Node struct {
	N       int             `json:"n"`
	IP      string          `json:"ip"`
	RTTms   int64           `json:"rttMs"`
	Status  probe.HopStatus `json:"status"`
	Country string          `json:"country,omitempty"` // ISO alpha-2, пусто — не знаем
	ASN     uint32          `json:"asn,omitempty"`
	Org     string          `json:"org,omitempty"`
	// Private — адрес из домашней сети. Не «неизвестная страна», а «своя».
	Private bool `json:"private"`
	// Host/City/At — где роутер стоит на самом деле, по его имени.
	// Надёжнее страны из базы: имя ставит оператор для себя, а страну
	// в базе — регистратор блока адресов, и у магистралей это разные вещи.
	Host string  `json:"host,omitempty"`
	City string  `json:"city,omitempty"`
	At   *LatLon `json:"at,omitempty"`
	// Implausible — за измеренное время сюда не успел бы даже свет.
	// Значит, база ошиблась, и рисовать такой шаг на карте нельзя.
	Implausible bool `json:"implausible,omitempty"`
}

// Route — луч от пользователя до места, где путь кончился.
//
// Кончился — не обязательно оборвался: если цель ответила, луч доходит
// до неё целиком. Именно это и рисуется на карте вместо «страны сервиса»,
// которой у сервиса за CDN попросту нет.
type Route struct {
	Host     string `json:"host"`
	TargetIP string `json:"targetIP"`
	Nodes    []Node `json:"nodes"`
	Reached  bool   `json:"reached"`
	// Break — последний ответивший шаг. Для дошедшего маршрута это цель,
	// для оборвавшегося — тот, за кем начинается тишина.
	Break *Node `json:"break,omitempty"`
	// Home — страна, из которой смотрим. Берётся с первого публичного шага,
	// то есть у собственного провайдера, а не у внешнего сервиса.
	Home string `json:"home,omitempty"`
	// FarCountry — база числит цель за другой страной, но ответ пришёл
	// слишком быстро, чтобы это была правда.
	FarCountry bool `json:"farCountry"`
	// ServiceOK — сервис отвечает на самом деле, что бы ни показала
	// трассировка.
	ServiceOK bool `json:"serviceOK"`
	// Opaque — маршрут не прослеживается, хотя сервис работает: где-то
	// по пути режут ICMP. Это не обрыв, и рисовать крест здесь нельзя —
	// иначе карта противоречила бы отчёту на той же странице.
	Opaque bool   `json:"opaque"`
	Note   string `json:"note,omitempty"`
	// Anchor — точка, от которой считалась достижимость. Карта берёт её же,
	// когда судит шаги, размещённые лишь по стране: два разных критерия
	// одного и того же расходились бы, и отчёт спорил бы с картой.
	Anchor *LatLon `json:"anchor,omitempty"`
}

// nearbyRTT — порог «отвечающая машина стоит рядом». 40 мс туда-обратно —
// это около 4000 км по прямой: свет в волокне идёт примерно на треть
// медленнее, чем в вакууме, да ещё и не по прямой.
//
// Отсюда простое, но честное правило: если база числит адрес за далёкой
// страной, а ответ приходит за 32 мс, то отвечает ближайшая точка
// присутствия CDN, и красить ту далёкую страну — враньё.
const nearbyRTT = 40

// Annotate размечает шаги трассировки по базе.
func Annotate(hops []probe.Hop, db *ipdb.DB) []Node {
	nodes := make([]Node, 0, len(hops))
	for _, h := range hops {
		n := Node{N: h.N, IP: h.IP, RTTms: h.RTTms, Status: h.Status}
		if addr, err := netip.ParseAddr(h.IP); err == nil {
			n.Private = isLocal(addr)
			if db != nil && !n.Private {
				rec := db.Lookup(addr)
				n.Country, n.ASN, n.Org = rec.Country, rec.ASN, rec.Org
			}
		}
		// Имя роутера сильнее базы: оно даёт город, а не страну регистрации.
		n.Host = h.Host
		if p, ok := PlaceFromHost(h.Host); ok && !n.Private {
			n.City = p.Name
			at := p.At
			n.At = &at
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// cgnat — 100.64.0.0/10, адреса провайдерского NAT. Формально публичные,
// фактически внутренние: в базе их нет, и это не пробел в данных.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// isLocal — адрес из тех, которых в интернете не бывает. Первый шаг
// трассировки всегда такой, и подписывать его страной нельзя.
func isLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsUnspecified() || cgnat.Contains(a)
}

// Anchor — точка, от которой считается «успел бы свет или нет».
//
// Лучше всего — настоящие координаты пользователя (их даёт geo.Lookup).
// Если их нет, годится первый же роутер провайдера, чьё имя выдало город:
// он в паре десятков километров от нас. Центроид страны для этого не годится
// категорически — у России он в Сибири, и от него до Франкфурта «не успевает
// свет» даже тогда, когда пользователь сидит в Москве и Франкфурт у него
// в сорока миллисекундах.
func Anchor(nodes []Node, direct *Info) *LatLon {
	if direct != nil && !(direct.Lat == 0 && direct.Lon == 0) {
		return &LatLon{Lat: direct.Lat, Lon: direct.Lon}
	}
	for _, n := range nodes {
		if n.At != nil {
			at := *n.At
			return &at
		}
	}
	return nil
}

// MarkImplausible помечает шаги, до которых за измеренное время не успел бы
// даже свет. Такой шаг — не крюк трафика, а ошибка геобазы, и на карте его
// быть не должно.
//
// Без якоря и без измерения не помечается ничего: отсутствие данных — не повод
// выбрасывать шаг.
func MarkImplausible(nodes []Node, anchor *LatLon) {
	if anchor == nil {
		return
	}
	for i := range nodes {
		n := &nodes[i]
		if n.At == nil || n.RTTms <= 0 {
			continue // судим только то, что измерено и размещено
		}
		if KmBetween(*anchor, *n.At) > ReachableKm(n.RTTms) {
			n.Implausible = true
		}
	}
}

// HomeCountry — страна первого публичного шага. Это ответ на вопрос
// «откуда мы смотрим», полученный без единого запроса наружу: первый
// же роутер провайдера числится в той стране, где мы и находимся.
func HomeCountry(nodes []Node) string {
	for _, n := range nodes {
		if !n.Private && n.Country != "" {
			return n.Country
		}
	}
	return ""
}

// BuildRoute собирает луч по трассировке.
//
// serviceOK — ответил ли сервис на самом деле. Без этого карта врала бы:
// половина магистральных роутеров не отвечает на ICMP, и трассировка до
// живого сервиса регулярно не доходит. Крест в таком месте противоречил бы
// отчёту на соседней вкладке.
func BuildRoute(host, targetIP string, hops []probe.Hop, db *ipdb.DB, serviceOK bool, direct *Info) Route {
	r := Route{
		Host:      host,
		TargetIP:  targetIP,
		Nodes:     Annotate(hops, db),
		Reached:   probe.Reached(hops),
		ServiceOK: serviceOK,
	}
	r.Opaque = serviceOK && !r.Reached
	r.Home = HomeCountry(r.Nodes)
	r.Anchor = Anchor(r.Nodes, direct)
	MarkImplausible(r.Nodes, r.Anchor)

	for i := len(r.Nodes) - 1; i >= 0; i-- {
		if n := r.Nodes[i]; n.IP != "" && n.Status != probe.HopSilent {
			end := n
			r.Break = &end
			break
		}
	}

	if r.Break == nil {
		r.Note = "не ответил ни один шаг маршрута"
		if r.Opaque {
			r.Note = "маршрут не прослеживается: ICMP режут с первого же шага, но сервис отвечает"
		}
		return r
	}
	r.FarCountry, r.Note = judgeEnd(*r.Break, r.Home, r.Reached, r.Opaque, serviceOK)
	return r
}

// judgeEnd объясняет словами, что означает конец луча.
func judgeEnd(end Node, home string, reached, opaque, serviceOK bool) (far bool, note string) {
	switch {
	case reached && !serviceOK:
		// Пакеты доходят, а сервис не открывается — так и выглядит блокировка
		// по имени или по содержимому. Раньше карта в этом случае рисовала
		// зелёный луч «всё дошло» и прямо спорила с отчётом на соседней вкладке.
		return false, fmt.Sprintf(
			"пакеты доходят до цели (шаг %d), но сервис не отвечает — режут не маршрут, а само соединение", end.N)
	case opaque:
		return false, fmt.Sprintf(
			"сервис отвечает, но маршрут дальше шага %d не прослеживается — по пути режут ICMP", end.N)
	case !reached && end.Status == probe.HopUnreach:
		return false, fmt.Sprintf("маршрут закрыт на шаге %d: %s", end.N, describe(end))
	case !reached:
		return false, fmt.Sprintf("дальше шага %d тишина, последним ответил %s", end.N, describe(end))
	case end.Country != "" && home != "" && end.Country != home && end.RTTms > 0 && end.RTTms < nearbyRTT:
		// Дошли, но не туда, где цель числится. Так выглядит CDN.
		return true, fmt.Sprintf(
			"ответ за %d мс, хотя адрес числится за страной %s — отвечает ближайшая точка присутствия, а не сервер там",
			end.RTTms, end.Country)
	default:
		return false, ""
	}
}

// describe — как назвать узел человеку: имя автономной системы говорит
// больше, чем адрес, но при его отсутствии адрес лучше, чем ничего.
func describe(n Node) string {
	switch {
	case n.Org != "" && n.ASN != 0:
		return fmt.Sprintf("%s (AS%d, %s)", n.IP, n.ASN, n.Org)
	case n.Country != "":
		return fmt.Sprintf("%s (%s)", n.IP, n.Country)
	default:
		return n.IP
	}
}
