package util

import (
	"strings"
	"time"
)

func TrimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func FormatDateTime(t time.Time) string {
	return t.Format(TimeFormatISO8601DateTime)
}

func FormatDate(t time.Time) string {
	return t.Format(TimeFormatISO8601Date)
}

func ParseDateTime(s string) (time.Time, error) {
	return time.Parse(TimeFormatISO8601DateTime, s)
}

func ParseDate(s string) (time.Time, error) {
	return time.Parse(TimeFormatISO8601Date, s)
}