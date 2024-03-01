package log

import (
	"github.com/schollz/progressbar/v3"
	"os"
	"time"
)

func NewProgressBar(total int64, description string, silent bool) *progressbar.ProgressBar {
	// disable when debugging
	if silent {
		return progressbar.DefaultSilent(total, description)
	}

	//return progressbar.Default(total, description)

	return progressbar.NewOptions(int(total),
		progressbar.OptionSetWriter(os.Stderr), //you should install "github.com/k0kubun/go-ansi"
		progressbar.OptionSetDescription(description),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetWidth(25),
		//progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
}
