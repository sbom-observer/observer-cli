package files

import (
	"testing"
)



func TestWindowsPaths(t *testing.T) {
	t1 := "packages\\Patch\\x86\\Windows8.1-KB2999226-x86.msu"
	b := WindowsBasePath(t1)
	if b != "Windows8.1-KB2999226-x86.msu" {
		t.Errorf("%s is not Windows8.1-KB2999226-x86.msu", b)
	}
}

func TestWindowsBasePath_MoreCases(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{`C:\\Program Files\\App\\app.exe`, `app.exe`},
		{`C:\\Windows\\System32\\`, `System32`},
		{`C:\\Windows\\System32\\\\`, `System32`},
		{`\\\\server\\share\\folder\\file.txt`, `file.txt`},
		{`setup.msi`, `setup.msi`},
		// Unix-style paths: should return the same string unmodified
		{`/usr/bin/bash`, `/usr/bin/bash`},
		{`foo/bar/baz`, `foo/bar/baz`},
		{`C:/Windows/System32/notepad.exe`, `C:/Windows/System32/notepad.exe`},
	}

	for _, c := range cases {
		got := WindowsBasePath(c.in)
		if got != c.out {
			t.Errorf("WindowsBasePath(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}
