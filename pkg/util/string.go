package util

import (
	"strings"
	"time"
)

// TrimAll strips all leading and trailing whitespaces and replaces multiple subsequent whitespaces
// in the string with single ones.
func TrimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// FormatDateTime formats the given time using the ISO 8601 date time format.
func FormatDateTime(t time.Time) string {
	return t.Format(TimeFormatISO8601DateTime)
}

// FormatDate formats the given time using the ISO 8601 date format.
func FormatDate(t time.Time) string {
	return t.Format(TimeFormatISO8601Date)
}

// ParseDateTime parses the provided string using the ISO 8601 date time format.
func ParseDateTime(s string) (time.Time, error) {
	return time.Parse(TimeFormatISO8601DateTime, s)
}

// ParseDate parses the provided string using the ISO 8601 date format.
func ParseDate(s string) (time.Time, error) {
	return time.Parse(TimeFormatISO8601Date, s)
}
