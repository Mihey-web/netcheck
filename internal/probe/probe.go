// Package probe содержит атомарные сетевые тесты netcheck.
// Каждая функция самодостаточна, уважает контекст и возвращает Result.
package probe

import (
	"net"
	"time"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	// StatusSkip — слой не проверялся: прогон оборвали раньше, потому что
	// без нижнего слоя результат верхних не значил бы ничего.
	StatusSkip Status = "skip"
)

type Path string

const (
	PathDirect Path = "direct"
	PathProxy  Path = "proxy"
)

// Outcome — КАК именно проба кончилась. Status{ok,warn,fail} теряет класс
// ошибки, а различает DPI и честный отказ сервера именно он: молчание до
// исчерпания бюджета — это вмешательство, быстрый RST или TLS-alert — это
// сам сервер.
type Outcome string

const (
	OutOK       Outcome = "ok"
	OutTimeout  Outcome = "timeout"  // молчание до конца бюджета
	OutReset    Outcome = "reset"    // RST
	OutRefused  Outcome = "refused"  // ICMP port unreachable
	OutTLSAlert Outcome = "tlsalert" // сервер ответил отказом на уровне TLS
	OutEOF      Outcome = "eof"      // соединение закрыто без ответа
	OutDNSFail  Outcome = "dnsfail"
	OutOther    Outcome = "other"
)

// CertInfo — предъявленный сертификат как улика. Пустой Subject значит,
// что до рукопожатия дело не дошло.
type CertInfo struct {
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NameMatch bool   `json:"nameMatch"`
	// ChainValid — цепочка строится до корня из системного хранилища.
	ChainValid bool   `json:"chainValid"`
	ChainErr   string `json:"chainErr,omitempty"`
}

type Result struct {
	Target  string        `json:"target"`
	Method  string        `json:"method"`
	Path    Path          `json:"path"`
	Latency time.Duration `json:"latency"`
	Status  Status        `json:"status"`
	Outcome Outcome       `json:"outcome,omitempty"`
	Detail  string        `json:"detail,omitempty"`
	IPs     []string      `json:"ips,omitempty"`
	// поля HTTP-пробы: нужны analyze, чтобы отличить геоблок от антибота
	Code        int    `json:"code,omitempty"`
	Location    string `json:"location,omitempty"`
	Server      string `json:"server,omitempty"`
	CFMitigated string `json:"cfMitigated,omitempty"`
	Body        string `json:"body,omitempty"` // первые 256 байт
	// SNI — какое имя предъявляли в рукопожатии (для лестницы нейтральных).
	SNI  string    `json:"sni,omitempty"`
	Cert *CertInfo `json:"cert,omitempty"`
}

// SameIPSet — пересекаются ли множества A-записей.
// Пустое множество ни с чем не совпадает: «нет ответа» не равно «тот же ответ».
func SameIPSet(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

func onlyIPv4(in []string) []string {
	var out []string
	for _, s := range in {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			out = append(out, s)
		}
	}
	return out
}
