//go:build !windows

package fonts

// List на не-Windows платформах не перечисляет шрифты: пользователь может
// вписать семейство вручную или указать файл.
func List() []string { return nil }
