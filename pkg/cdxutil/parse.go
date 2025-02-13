package cdxutil

import (
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"os"
)

func ParseCycloneDX(filename string) (*cdx.BOM, error) {
	var bom cdx.BOM

	bomFormat := cdx.BOMFileFormatJSON

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := cdx.NewBOMDecoder(f, bomFormat)
	err = decoder.Decode(&bom)
	if err != nil {
		return nil, fmt.Errorf("cdx.Decode: %w", err)
	}

	return &bom, nil
}
