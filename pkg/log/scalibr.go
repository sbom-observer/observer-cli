package log

import "github.com/charmbracelet/log"

type ScalibrAdapter struct {
	logger *log.Logger
}

func (s *ScalibrAdapter) Errorf(format string, args ...any) {
	s.logger.Errorf(format, args...)
}

func (s *ScalibrAdapter) Error(args ...any) {
	if len(args) > 1 {
		s.logger.Error(args[0], args[1:]...)
	} else {
		s.logger.Error(args[0])
	}
}

func (s *ScalibrAdapter) Warnf(format string, args ...any) {
	s.logger.Warnf(format, args...)
}

func (s *ScalibrAdapter) Warn(args ...any) {
	if len(args) > 1 {
		s.logger.Warn(args[0], args[1:]...)
	} else {
		s.logger.Warn(args[0])
	}
}

func (s *ScalibrAdapter) Infof(format string, args ...any) {
	s.logger.Debugf(format, args...)
}

func (s *ScalibrAdapter) Info(args ...any) {
	if len(args) > 1 {
		s.logger.Debug(args[0], args[1:]...)
	} else {
		s.logger.Debug(args[0])
	}
}

func (s *ScalibrAdapter) Debugf(format string, args ...any) {
	s.logger.Debugf(format, args...)
}

func (s *ScalibrAdapter) Debug(args ...any) {
	if len(args) > 1 {
		s.logger.Debug(args[0], args[1:]...)
	} else {
		s.logger.Debug(args[0])
	}
}
