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
	// Guessed — координата взята не из имени роутера, а по стране: главный
	// узел связи и есть догадка. Разница принципиальная. Знание о городе
	// можно опровергнуть замером времени; догадку — тоже, но опровергается
	// тогда сама догадка, а не шаг, и выбрасывать надо точку, а не шаг.
	Guessed bool `json:"guessed,omitempty"`
	// Implausible — за измеренное время сюда не успел бы даже свет.
	// Значит, база ошиблась, и рисовать такой шаг на карте нельзя.
	Implausible bool `json:"implausible,omitempty"`
	// Ambiguous — на этом шаге путь разветвляется: повторный вопрос пришёл
	// с другого адреса. Одной точкой такой шаг не описывается, и координаты
	// ему не ставятся вовсе.
	Ambiguous bool `json:"ambiguous,omitempty"`
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
	Opaque bool `json:"opaque"`
	// Note — готовая подпись на языке пользователя. Сам пакет geo языка
	// не знает: он ставит только NoteID+NoteArgs, а строку из них собирает
	// сборщик отчёта — и пересобирает при смене языка (как verdict).
	Note string `json:"note,omitempty"`
	// NoteID — код причины (ключ i18n), NoteArgs — его аргументы. Аргументы
	// хранятся строками нарочно: []any после прогулки через JSON (история)
	// превращает числа в float64, и «%d» ломался бы на старых отчётах.
	NoteID   string   `json:"noteId,omitempty"`
	NoteArgs []string `json:"noteArgs,omitempty"`
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
		n.Ambiguous = h.Ambiguous
		switch {
		case n.Ambiguous:
			// Шаг ответил с двух разных адресов — это два роутера, а не один.
			// Любая точка здесь была бы выдумкой: в списке шаг остаётся,
			// на карте его нет.
		case n.Private:
			// свой адрес — страны у него нет и быть не может
		default:
			placeNode(&n, h.Host)
		}
		nodes = append(nodes, n)
	}
	return nodes
}

// placeNode ставит шагу координату: сперва по имени роутера, затем — по
// главному узлу связи его страны.
func placeNode(n *Node, host string) {
	if p, ok := PlaceFromHost(host); ok {
		n.City = p.Name
		at := p.At
		n.At = &at
		return
	}
	if p, ok := HubOf(n.Country); ok {
		// Имя ничего не сказало — ставим точку в главный узел связи страны.
		// City не заполняем: это догадка о стране, а не знание о городе,
		// и подписывать её городом было бы враньём.
		at := p.At
		n.At = &at
		n.Guessed = true
	}
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
//
// Guessed-точки в якоря не годятся тоже: узел связи страны — догадка,
// и якорь в Москве у жителя Владивостока заставлял MarkImplausible снимать
// честные точки. Нет ни геолокации, ни точки из имени роутера — якоря нет:
// отсутствие данных — не улика, и судить шаги в этом случае нечем.
func Anchor(nodes []Node, direct *Info) *LatLon {
	if direct != nil && !(direct.Lat == 0 && direct.Lon == 0) {
		return &LatLon{Lat: direct.Lat, Lon: direct.Lon}
	}
	for _, n := range nodes {
		if n.At != nil && !n.Guessed {
			at := *n.At
			return &at
		}
	}
	return nil
}

// legFloorMs — запас на соседний шаг. Разница времён между соседними шагами
// мала и шумна: 53 и 54 мс дают «минус миллисекунду», из которой нельзя
// заключить, что роутеры стоят в одной комнате. Восьми миллисекунд хватает
// на восемьсот километров — больше, чем расстояние между соседними узлами
// связи в Европе, и заметно меньше любого настоящего океанского перегона.
const legFloorMs = 8

// MarkImplausible разбирается, каким точкам верить.
//
// Проверок две, и обе — про скорость света: за rtt/2 миллисекунд свет
// в волокне проходит около 200 км/мс, дальше машина стоять не может.
//
// Первая: успел бы свет от пользователя. Вторая: успел бы он от предыдущего
// размещённого шага за разницу времён — она ловит крюки, которых не было.
//
// Что делать с провалом, зависит от того, откуда взялась точка:
//
//   - точка из имени роутера — это знание. Провал означает, что база или имя
//     врут, и шаг с карты снимается (Implausible);
//   - точка по стране — это догадка. Провал означает, что неверна догадка,
//     а не шаг: роутер провайдера в четырёх миллисекундах от Донецка
//     совершенно нормален, неверна только отметка в Москве. Точка снимается,
//     шаг остаётся — карта разместит его по стране, с поправкой на её размер.
//
// Раньше разницы не было, и первое же правило выбрасывало собственного
// провайдера пользователя, а вместе с ним и весь маршрут: из двенадцати лучей
// рисовались пять.
//
// Без якоря и без измерения не трогается ничего: отсутствие данных — не улика.
func MarkImplausible(nodes []Node, anchor *LatLon) {
	if anchor == nil {
		return
	}
	var prev *Node // последний шаг, за точкой которого осталась сила
	for i := range nodes {
		n := &nodes[i]
		if n.At == nil || n.RTTms <= 0 {
			continue // судим только то, что измерено и размещено
		}
		switch {
		case KmBetween(*anchor, *n.At) > ReachableKm(n.RTTms):
			// свет от пользователя не успел
		case prev != nil && n.Guessed &&
			KmBetween(*prev.At, *n.At) > ReachableKm(max(abs(n.RTTms-prev.RTTms), legFloorMs)):
			// Догаданная точка требует перегона, которого нет во времени.
			// Так и выглядел «Стокгольм → Дублин → Стокгольм» на 53 мс:
			// база числит роутер за Ирландией, а сходить туда и вернуться
			// маршрут не успевал ни при каком раскладе. Шаг настоящий,
			// но разместить его негде — на карте его быть не должно.
			n.Implausible = true
			n.At, n.Guessed = nil, false
			continue
		default:
			prev = n
			continue
		}
		if n.Guessed {
			n.At, n.Guessed = nil, false
			continue
		}
		n.Implausible = true
	}
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
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
		r.NoteID = "map.note.no_reply"
		if r.Opaque {
			r.NoteID = "map.note.opaque_start"
		}
		return r
	}
	r.FarCountry, r.NoteID, r.NoteArgs = judgeEnd(*r.Break, r.Home, r.Reached, r.Opaque, serviceOK, baseRTT(r.Nodes, r.Break.N))
	return r
}

// baseRTT — время до первого публичного шага, не считая самой цели.
//
// Это цена «выхода в интернет»: у VPN в TUN-режиме первый публичный шаг —
// сам выход VPN, и его 60 мс — это туннель, а не расстояние до цели.
// Сравнивать с порогом «рядом» надо время сверх этой базы, иначе всё,
// что видно через туннель, казалось далёким. Сама цель за базу не годится:
// когда, кроме неё, не ответил никто, вычитание давало бы ноль и любую цель
// объявляло бы соседней.
func baseRTT(nodes []Node, endN int) int64 {
	for _, n := range nodes {
		if !n.Private && n.RTTms > 0 && n.N != endN {
			return n.RTTms
		}
	}
	return 0
}

// judgeEnd объясняет, что означает конец луча: кодом причины и аргументами,
// строку из которых соберёт i18n на языке пользователя.
func judgeEnd(end Node, home string, reached, opaque, serviceOK bool, base int64) (far bool, noteID string, args []string) {
	step := fmt.Sprint(end.N)
	switch {
	case reached && !serviceOK:
		// Пакеты доходят, а сервис не открывается — так и выглядит блокировка
		// по имени или по содержимому. Раньше карта в этом случае рисовала
		// зелёный луч «всё дошло» и прямо спорила с отчётом на соседней вкладке.
		return false, "map.note.blocked_at_target", []string{step}
	case opaque:
		return false, "map.note.opaque", []string{step}
	case !reached && end.Status == probe.HopUnreach:
		return false, "map.note.closed", []string{step, describe(end)}
	case !reached:
		return false, "map.note.silence", []string{step, describe(end)}
	case end.Country != "" && home != "" && end.Country != home && end.RTTms > 0 && end.RTTms-base < nearbyRTT:
		// Дошли, но не туда, где цель числится. Так выглядит CDN.
		// Порог сравнивается со временем сверх базы: см. baseRTT.
		return true, "map.note.far_country", []string{fmt.Sprint(end.RTTms), end.Country}
	default:
		return false, "", nil
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
