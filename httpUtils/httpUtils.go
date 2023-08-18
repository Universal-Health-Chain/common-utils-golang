package httpUtils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
		_ = fmt.Errorf("http.NewRequest error = %v\n", err.Error())
		return nil, fmt.Errorf("got error %s", err.Error())
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

func ReturnDIDCommPayloadJSON(w http.ResponseWriter, data []byte, errMsg string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")

	w.Write(data)
}

/*
func SendInternalHttpRequest(
	dataJSON *map[string]interface{},
	dataFormEncoded *string,
	httpMethod string,
	requestUrl string,
	contentType *string, // "application/x-www-form-urlencoded"
	acceptResponseFormat *string,
	controllerFunc func(http.ResponseWriter, *http.Request), // only for testing controllers
	middleWareFunc *interface{},
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
*/