package probe

import "time"

// HopStatus — чем кончился шаг трассировки. Различать эти четыре исхода
// важнее, чем знать RTT: молчание и явный отказ выглядят на карте
// по-разному и означают разное.
type HopStatus string

const (
	// HopOK — роутер ответил «время жизни истекло», путь идёт дальше.
	HopOK HopStatus = "ok"
	// HopSilent — не ответил никто. Либо роутер не отвечает на ICMP
	// (обычное дело), либо дальше пакеты не идут. Отличить нельзя.
	HopSilent HopStatus = "silent"
	// HopUnreach — роутер явно сказал «дальше не пройти».
	HopUnreach HopStatus = "unreachable"
	// HopFinal — ответила сама цель, маршрут пройден целиком.
	HopFinal HopStatus = "final"
)

// Hop — один шаг трассировки.
type Hop struct {
	N      int       `json:"n"` // номер шага, с единицы
	IP     string    `json:"ip"`
	RTTms  int64     `json:"rttMs"`
	Status HopStatus `json:"status"`
	Detail string    `json:"detail,omitempty"`
}

// Responded — ответил ли кто-нибудь на этом шаге.
func (h Hop) Responded() bool { return h.IP != "" && h.Status != HopSilent }

// maxTTL — дальше идти незачем: до любой достижимой точки интернета
// добираются за полтора десятка шагов, а каждый лишний стоит времени.
const maxTTL = 20

// hopTimeout — сколько ждать ответа на один шаг. Шаги опрашиваются
// параллельно, поэтому это же и весь бюджет трассировки.
const hopTimeout = 1500 * time.Millisecond

// TrimHops убирает то, что не несёт смысла: всё после достигнутой цели
// и хвост молчания в конце.
//
// Хвост молчания обрезается не для красоты. Если путь оборвался на седьмом
// шаге, то шаги с восьмого по двадцатый — это одно и то же событие,
// показанное тринадцать раз, и на карте они превратились бы в тринадцать
// одинаковых пустых отметок вместо одной точки обрыва.
func TrimHops(hops []Hop) []Hop {
	for i, h := range hops {
		if h.Status == HopFinal {
			return hops[:i+1]
		}
	}
	end := len(hops)
	for end > 0 && !hops[end-1].Responded() {
		end--
	}
	return hops[:end]
}

// LastResponding — последний шаг, с которого пришёл ответ. Это и есть точка,
// до которой пакеты дошли: дальше начинается неизвестность.
//
// Второе значение — false, если не ответил вообще никто; тогда рисовать
// нечего, и карта обязана сказать это словами, а не показать пустой луч.
func LastResponding(hops []Hop) (Hop, bool) {
	for i := len(hops) - 1; i >= 0; i-- {
		if hops[i].Responded() {
			return hops[i], true
		}
	}
	return Hop{}, false
}

// Reached — дошла ли трассировка до самой цели.
func Reached(hops []Hop) bool {
	for _, h := range hops {
		if h.Status == HopFinal {
			return true
		}
	}
	return false
}
