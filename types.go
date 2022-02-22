package govulners

import (
	"strings"
	"time"
)

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(data []byte) error {
	value := strings.TrimPrefix(strings.TrimSuffix(string(data), `"`), `"`)
	parsed, err := time.Parse("2006-01-02T15:04:05", value)
	if err != nil {
		return err
	}
	*t = Time{parsed}

	return nil
}

type FloatString string

func (t *FloatString) UnmarshalJSON(data []byte) error {
	value := strings.TrimPrefix(strings.TrimSuffix(string(data), `"`), `"`)

	*t = FloatString(value)
	return nil
}
