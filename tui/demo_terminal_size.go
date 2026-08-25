package tui

import "strconv"

func demoTerminalDimension(value string, fallback int) int {
	dimension, err := strconv.Atoi(value)
	if err != nil || dimension <= 0 {
		return fallback
	}
	return dimension
}
