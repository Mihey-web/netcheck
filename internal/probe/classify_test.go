package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

// Класс отказа — фундамент всей диагностики: по нему различаются DPI
// и честный отказ сервера. Раньше он вычислялся разбором ТЕКСТА системной
// ошибки по английским подстрокам, а Windows на русской локали выдаёт
// «конечный компьютер отверг запрос на подключение» — ни одна подстрока
// не совпадала, и главный диагноз программы переставал ставиться.
//
// Тест построен на числовых кодах, поэтому не зависит от языка машины,
// на которой его гоняют.
func TestClassifyErrByErrno(t *testing.T) {
	wsa := func(code int) error {
		return &net.OpError{Op: "dial", Net: "tcp",
			Err: &os.SyscallError{Syscall: "connectex", Err: syscall.Errno(code)}}
	}

	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"соединение отвергнуто", wsa(10061), OutRefused},
		{"соединение сброшено", wsa(10054), OutReset},
		{"соединение прервано", wsa(10053), OutReset},
		{"таймаут стека", wsa(10060), OutTimeout},
		{"сеть недостижима", wsa(10051), OutUnreach},
		{"узел недостижим", wsa(10065), OutUnreach},
		{"имя не найдено", wsa(11001), OutDNSFail},

		{"истёк наш бюджет", context.DeadlineExceeded, OutTimeout},
		// Отмена — факт о нас, а не о сети: OutOther здесь портил бы
		// вердикт, как будто проба честно кончилась неудачей.
		{"прогон отменили", context.Canceled, OutCanceled},
		{"конец потока", io.EOF, OutEOF},
		{"нет ошибки", nil, OutOK},
	}
	for _, c := range cases {
		if got := classifyErr(c.err); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Адрес цели попадает в текст ошибки целиком, и поиск подстроки «eof»
// находил её в любом theoffice.com.
func TestClassifyErrDoesNotMatchHostnames(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://theoffice.com",
		Err: errors.New("proxy CONNECT: 502 Bad Gateway")}
	if got := classifyErr(err); got == OutEOF {
		t.Errorf("имя хоста принято за конец потока: %q", got)
	}
}
