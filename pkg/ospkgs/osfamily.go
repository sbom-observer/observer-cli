package ospkgs

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

func DetectOSFamily() (OSFamily, error) {
	files := []string{"/etc/redhat-release", "/etc/os-release", "/usr/lib/os-release", "/etc/debian_version"}
	for _, filename := range files {
		if _, err := os.Stat(filename); err == nil {
			contents, err := os.ReadFile(filename)
			if err != nil {
				return OSFamily{Name: OSFamilyUnknown, Distro: OSFamilyUnknown, Release: OSReleaseUnknown}, err
			}

			switch filename {
			//case "/etc/redhat-release":
			//	return &OSFamily{Name: "RedHat", Release: "unknown"}, nil
			case "/etc/debian_version":
				return OSFamily{Name: "debian", Distro: "debian", Release: strings.TrimSpace(string(contents))}, nil
			case "/etc/os-release", "/usr/lib/os-release":
				fields := parseOsReleaseFile(contents)
				name := fields["ID"]

				// if ID_LIKE use this instead as a least common denominator
				if fields["ID_LIKE"] != "" {
					like := strings.Split(fields["ID_LIKE"], " ")
					if len(like) > 0 {
						name = like[0]
					}
				}

				return OSFamily{Name: name, Distro: fields["ID"], Release: fields["VERSION_ID"]}, nil
			}
		}
	}

	return OSFamily{Name: OSFamilyUnknown, Release: OSReleaseUnknown}, nil
}

/*
 Amazon Linux 2023

NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.6.20250218"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/"
DOCUMENTATION_URL="https://docs.aws.amazon.com/linux/"
SUPPORT_URL="https://aws.amazon.com/premiumsupport/"
BUG_REPORT_URL="https://github.com/amazonlinux/amazon-linux-2023"
VENDOR_NAME="AWS"
VENDOR_URL="https://aws.amazon.com/"
SUPPORT_END="2029-06-30"
*/

// parse the os-release(5) file.
func parseOsReleaseFile(bs []byte) map[string]string {
	s := bufio.NewScanner(bytes.NewReader(bs))

	m := map[string]string{}
	for s.Scan() {
		line := strings.TrimSpace(s.Text())

		if !strings.Contains(line, "=") || strings.HasPrefix(line, "#") {
			continue
		}

		kv := strings.SplitN(line, "=", 2)
		m[kv[0]] = resolveString(kv[1])
	}
	return m
}

// resolveString parses the right side of an environment-like shell-compatible variable assignment.
// Currently it just removes double quotes. See `man os-release 5` for more details.
func resolveString(s string) string {
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = s[1 : len(s)-1]
	}
	return s
}
