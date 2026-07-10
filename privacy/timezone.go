package privacy

import (
	"net/http"
	"time"
)

type TimezoneParser struct {
	headerName string
}

func NewTimezoneParser(headerName string) *TimezoneParser {
	return &TimezoneParser{headerName: headerName}
}

func (p *TimezoneParser) Parse(h http.Header) *time.Location {
	tzStr := h.Get(p.headerName)
	if tzStr == "" {
		return time.UTC
	}

	loc, err := time.LoadLocation(tzStr)
	if err != nil {
		return time.UTC
	}

	return loc
}
