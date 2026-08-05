package probe

import (
	"errors"
	"syscall"
)

// Коды ошибок сокетов Windows. Разбирать вместо них текст сообщения нельзя:
// Go просит его у системы на английском, и если английских MUI-ресурсов
// в системе нет — а на русской Windows их обычно нет, — приходит русский
// текст. «Конечный компьютер отверг запрос на подключение» не содержит
// ни одной подстроки, которую искал прежний разбор, класс отказа терялся,
// и главный диагноз программы — DPI по имени — переставал ставиться вовсе.
const (
	wsaeNetUnreach   = 10051
	wsaeConnAborted  = 10053
	wsaeConnReset    = 10054
	wsaeTimedOut     = 10060
	wsaeConnRefused  = 10061
	wsaeHostDown     = 10064
	wsaeHostUnreach  = 10065
	wsaeHostNotFound = 11001
	wsaeTryAgain     = 11002 // резолвер: временный отказ
	wsaeNoRecovery   = 11003 // резолвер: неустранимая ошибка
)

// platformOutcome — класс отказа по коду ошибки сокета.
// Второе значение false означает «это не системная ошибка сокета».
func platformOutcome(err error) (Outcome, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "", false
	}
	switch errno {
	case wsaeConnRefused:
		return OutRefused, true
	case wsaeConnReset, wsaeConnAborted:
		return OutReset, true
	case wsaeTimedOut:
		return OutTimeout, true
	case wsaeNetUnreach, wsaeHostUnreach, wsaeHostDown:
		return OutUnreach, true
	case wsaeHostNotFound, wsaeNoRecovery, wsaeTryAgain:
		return OutDNSFail, true
	}
	return "", false
}
