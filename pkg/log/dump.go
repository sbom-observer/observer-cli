package log

import (
	"encoding/json"
	"fmt"
)

// Dump prints contents as JSON, used in development
func Dump(something any) {
	jsonData, err := json.MarshalIndent(something, "", "  ")
	if err != nil {
		fmt.Printf("Dump error: %v\n", err)
		return
	}
	fmt.Printf("%s\n", jsonData)
}
