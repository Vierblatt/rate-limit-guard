package guard

import (
	"net/http"
	"time"
)

type timezoneParser struct {
	headerName string
}

func newTimezoneParser(headerName string) *timezoneParser {
	return &timezoneParser{headerName: headerName}
}

func (p *timezoneParser) Parse(h http.Header) *time.Location {
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
