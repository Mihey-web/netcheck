//go:build !windows

package probe

// platformOutcome — на не-Windows кодов ошибок сокетов не разбираем:
// netcheck — программа под Windows, и сборка под другие системы нужна
// лишь для того, чтобы гонять тесты чистой логики.
func platformOutcome(error) (Outcome, bool) { return "", false }
