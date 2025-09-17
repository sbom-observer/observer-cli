package files

const (
	windowsSeparator = '\\' // OS-specific path separator
)

func isPathSeparator(c uint8) bool {
	return c == windowsSeparator
}

// WindowsBase returns the base name of a Windows path
func WindowsBasePath(path string) string {
	// strip trailing Separator(s)
	i := len(path) - 1
	for i >= 0 && isPathSeparator(path[i]) {
		i--
	}

	// if the path was only separators, return a single separator
	if i < 0 {
		return string(windowsSeparator)
	}

	// find the position of the last separator
	j := i
	for j >= 0 && !isPathSeparator(path[j]) {
		j--
	}

	// return everything after last Separator
	return path[j+1 : i+1]
}
