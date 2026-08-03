//go:build !windows

package probe

import (
	"context"
	"errors"
)

// Trace на не-Windows не реализована: netcheck — программа под Windows,
// а сборка под другие системы нужна лишь для того, чтобы гонять тесты
// чистой логики. Молча возвращать пустой маршрут нельзя — карта приняла бы
// это за «никто не ответил».
func Trace(ctx context.Context, ip string) ([]Hop, error) {
	return nil, errors.New("trace: поддерживается только на Windows")
}
