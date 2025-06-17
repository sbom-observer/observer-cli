package types

func SeverityToString(severity float64) string {
	if severity > 8.9 {
		return "CRITICAL"
	}

	if severity > 6.9 {
		return "HIGH"
	}

	if severity > 3.9 {
		return "MEDIUM"
	}

	if severity > 0 {
		return "LOW"
	}

	return "UNKNOWN"
}
