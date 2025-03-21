package scanner

import "sbom.observer/cli/pkg/log"

type withFallbackScanner struct {
	SelectedScanner RepoScanner
}

type MissingScannerInstructions interface {
	LogInstructions()
}

func NewWithFallbackScanner(primaryScanner, fallbackScanner RepoScanner) *withFallbackScanner {
	selectedScanner := primaryScanner

	if !primaryScanner.IsAvailable() {
		log.Warnf("preferred scanner '%s' not available, falling back to '%s'", primaryScanner.Id(), fallbackScanner.Id())
		if missingScannerInstructions, ok := primaryScanner.(MissingScannerInstructions); ok {
			missingScannerInstructions.LogInstructions()
		}
		selectedScanner = fallbackScanner
	}

	return &withFallbackScanner{
		SelectedScanner: selectedScanner,
	}
}

func (s *withFallbackScanner) Id() string {
	return s.SelectedScanner.Id()
}

func (s *withFallbackScanner) IsAvailable() bool {
	return s.SelectedScanner.IsAvailable()
}

func (s *withFallbackScanner) Priority() int {
	return s.SelectedScanner.Priority()
}

func (s *withFallbackScanner) Scan(target *ScanTarget) error {
	return s.SelectedScanner.Scan(target)
}
