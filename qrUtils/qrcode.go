package qrUtils

import (
	"github.com/aaronarduino/goqrsvg"
	svg "github.com/ajstarks/svgo"
	"github.com/boombuler/barcode/qr"
	"github.com/skip2/go-qrcode"
	"net/http"
)

func QrPng(content string, version int) ([]byte, error) {
	qrContent, err := qrcode.NewWithForcedVersion(content, version, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	return qrContent.PNG(512)
}

// from https://github.com/aaronarduino/goqrsvg
func QrSvg(content string, version int) (ioWriter http.ResponseWriter) {
	// creates svg
	s := svg.New(ioWriter)

	// Create the barcode
	qrCode, _ := qr.Encode(content, qr.M, qr.Auto)

	// Write QR code to SVG
	qrSvg := goqrsvg.NewQrSVG(qrCode, 5)
	qrSvg.StartQrSVG(s)
	qrSvg.WriteQrSVG(s)

	s.End()
	return ioWriter
}
