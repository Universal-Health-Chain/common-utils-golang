package joseUtils

import "time"

// CheckNotExpiredDateISO returns true if the date is not expired or false if expired or error
func CheckNotExpiredDateISO(datetime string) bool {
	currentTime := time.Now()
	layout := "2000-12-30T12:00:00Z"
	endTime, err := time.Parse(layout, datetime)
	if err != nil {
		return false
	}
	return currentTime.Before(endTime)
}

// CheckNotExpiredDateEpochUNIX returns true if the date is not expired or false if expired
func CheckNotExpiredDateEpochUNIX(timeUNIX int64) bool {
	currentTime := time.Now().Unix() // seconds
	if timeUNIX <= currentTime {
		return false // expired, current time was reached
	} else {
		return true // all right, current time was not reached
	}
}
