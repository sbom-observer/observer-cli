package ospkgs

import (
	"os"
	"strings"
)

func DetectOSFamily() (OSFamily, error) {
	files := []string{"/etc/redhat-release", "/etc/os-release", "/etc/debian_version"}
	for _, filename := range files {
		if _, err := os.Stat(filename); err == nil {
			contents, err := os.ReadFile(filename)
			if err != nil {
				return OSFamily{Name: OSFamilyUnknown, Release: OSReleaseUnknown}, err
			}

			switch filename {
			//case "/etc/redhat-release":
			//	return &OSFamily{Name: "RedHat", Release: "unknown"}, nil
			//case "/etc/os-release":
			//	return &OSFamily{Name: "Ubuntu", Release: "unknown"}, nil
			case "/etc/debian_version":
				return OSFamily{Name: "Debian", Release: strings.TrimSpace(string(contents))}, nil
			}
		}
	}

	return OSFamily{Name: OSFamilyUnknown, Release: OSReleaseUnknown}, nil
}
