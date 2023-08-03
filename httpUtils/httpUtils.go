package httpUtils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	// HeaderEnumAccept is a HeaderEnum enum value
	HeaderEnumAccept = "Accept"

	// HeaderEnumAcceptCharset is a HeaderEnum enum value
	HeaderEnumAcceptCharset = "Accept-Charset"

	// HeaderEnumAcceptDatetime is a HeaderEnum enum value
	HeaderEnumAcceptDatetime = "Accept-Datetime"

	// HeaderEnumAcceptEncoding is a HeaderEnum enum value
	HeaderEnumAcceptEncoding = "Accept-Encoding"

	// HeaderEnumAcceptLanguage is a HeaderEnum enum value
	HeaderEnumAcceptLanguage = "Accept-Language"

	// HeaderEnumAuthorization is a HeaderEnum enum value
	HeaderEnumAuthorization = "Authorization"

	// HeaderEnumHost is a HeaderEnum enum value
	HeaderEnumHost = "Host"

	// HeaderEnumOrigin is a HeaderEnum enum value
	HeaderEnumOrigin = "Origin"

	// HeaderEnumReferer is a HeaderEnum enum value
	HeaderEnumReferer = "Referer"
)

const (
	MimeTypeJSON = "application/json"
	MimeTypeForm = "application/x-www-form-urlencoded"
)

func HttpResponseJSON(w http.ResponseWriter, httpCode int, responseJSON *map[string]interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(*responseJSON)
}
func HttpResponseBytes(w http.ResponseWriter, httpCode int, contentType string, responseBytes []byte) {
	w.Header().Add("Content-Type", contentType)
	w.WriteHeader(httpCode)
	w.Write(responseBytes)
}

// SendInternalHttpRequest sends an internal HttpRequestHeaders request to an internal endpoint with JSON or form data encoded
// by using optional middleware and access token when defined and returns the bytes of the response or error.
// gorilla/mux implements a request router and dispatcher for matching incoming requests to their respective handler.
func SendInternalHttpRequest(
	dataJSON *map[string]interface{},
	dataFormEncoded *string,
	httpMethod string,
	requestUrl string,
	contentType *string, // "application/x-www-form-urlencoded"
	acceptResponseFormat *string,
	controllerFunc func(http.ResponseWriter, *http.Request), // only for testing controllers
	middleWareFunc *mux.MiddlewareFunc,
	accessToken *string) (*[]byte, error) {

	// TODO: check controllerFunc is not nil

	// creating the request with data as JSON or Form-Url encoded
	var dataBuffer *bytes.Buffer
	if dataJSON != nil {
		dataBytes, _ := json.Marshal(*dataJSON)
		dataBuffer = bytes.NewBuffer(dataBytes)
	} else if dataFormEncoded != nil {
		dataReader := strings.NewReader(*dataFormEncoded)
		var dataBytes []byte
		_, _ = dataReader.Read(dataBytes)
		dataBuffer = bytes.NewBuffer(dataBytes)
	}
	httpRequest, _ := http.NewRequest(httpMethod, requestUrl, dataBuffer) // "POST", "GET" ...

	// ParseForm populates r.Form and r.PostForm.
	// - For all requests, it parses the raw query from the URL and updates r.Form.
	// - For POST, PUT, and PATCH requests, it also reads the request body, parses it as a form and puts the results into both r.PostForm and r.Form.
	httpRequest.ParseForm()

	// only for testing:
	// for key, value := range httpRequest.Form { fmt.Printf("Key:%s, Value:%s\n", key, value)}

	if accessToken != nil {
		httpRequest.Header.Set("Authorization", "Bearer "+*accessToken)
	}

	if contentType != nil {
		httpRequest.Header.Set("Content-Type", *contentType)
	}

	if acceptResponseFormat != nil {
		httpRequest.Header.Set("Accept", *acceptResponseFormat)
	}

	// this is to create the router to an internal function with httptest instead of using httpClient
	router := mux.NewRouter()
	router.HandleFunc(requestUrl, controllerFunc).Methods(httpMethod)
	if middleWareFunc != nil {
		router.Use(*middleWareFunc)
	}

	// fmt.Print(httpRequest)
	server := httptest.NewServer(router)
	defer server.Close()

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httpRequest)
	responseBytes, err := ioutil.ReadAll(response.Body)
	return &responseBytes, err
}

// url.Values maps a string key to a list of values. It is typically used for query parameters and form values.
// url.Values.Encode() encodes the values into "URL encoded" form sorted by key ("bar=abc&foo=xyz").
func SendExternalHttpRequest(urlPath, httpMethod string, contentType string, dataForm url.Values, dataJSON *map[string]interface{}) (*http.Response, error) {
	switch contentType {
	case MimeTypeForm:
		return SendExternalHttpRequestFormEncoded(urlPath, httpMethod, dataForm)
	case MimeTypeJSON:
		return SendExternalHttpRequestJSON(urlPath, httpMethod, dataJSON)
	}
	return nil, errors.New("the content type specified is not supported")
}

// url.Values maps a string key to a list of values. It is typically used for query parameters and form values.
// url.Values.Encode() encodes the values into "URL encoded" form sorted by key ("bar=abc&foo=xyz").
func SendExternalHttpRequestFormEncoded(urlPath, httpMethod string, formData url.Values) (*http.Response, error) {
	httpClient := &http.Client{Timeout: time.Second * 10} // given as parameter
	// TODO: check httpClient and formData are not nil

	// Encode encodes the values into "URL encoded" form ("bar=abc&foo=xyz") sorted by key.
	encodedFormData := formData.Encode()
	// fmt.Printf("formData encoded URL = %s\n", encodedFormData)

	// preparing the HttpRequestHeaders request
	httpRequest, err := http.NewRequest(httpMethod, urlPath, strings.NewReader(encodedFormData))
	if err != nil {
		fmt.Errorf("http.NewRequest error = %v\n", err.Error())
		return nil, fmt.Errorf("Got error %s", err.Error())
	}
	httpRequest.Header.Add("Content-Type", MimeTypeForm)
	httpRequest.Header.Add("Content-Length", strconv.Itoa(len(encodedFormData)))

	// doing the http request
	return httpClient.Do(httpRequest)
}

func SendExternalHttpRequestJSON(urlPath, httpMethod string, dataJSON *map[string]interface{}) (*http.Response, error) {
	httpClient := &http.Client{Timeout: time.Second * 10} // given as parameter
	// TODO: check httpClient and formData are not nil

	var dataBuffer *bytes.Buffer
	dataBytes, _ := json.Marshal(*dataJSON)
	dataBuffer = bytes.NewBuffer(dataBytes)
	// preparing the HttpRequestHeaders request
	httpRequest, _ := http.NewRequest(httpMethod, urlPath, dataBuffer) // "POST", "GET" ...
	httpRequest.Header.Add("Content-Type", MimeTypeJSON)
	httpRequest.Header.Add("Content-Length", strconv.Itoa(len(dataBytes)))

	// doing the http request
	return httpClient.Do(httpRequest)
}

// GetHttpHeaders returns the OpenID HTTP headers
// TODO: return all the headers
// Headers are case insensitive as per RFC2616 (RFC 7230 does not modify this)
// https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.2
var GetHttpHeaders = func(r *http.Request) *HttpPrivateHeadersOpenid {
	privateHeaders := HttpPrivateHeadersOpenid{
		Authorization: r.Header.Get("Authorization"),
		ContentType:   r.Header.Get("Content-Type"),
		DPoP:          r.Header.Get("DPoP"),
		Accept:        r.Header.Get("Accept"),
		// IDToken:       r.Header.Get("IdToken"),
	}

	return &privateHeaders
}

func ReturnDIDCommPayloadJSON(w http.ResponseWriter, data []byte, errMsg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")

	w.Write(data)
}
