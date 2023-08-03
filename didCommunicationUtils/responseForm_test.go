package didCommunicationUtils

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Universal-Health-Chain/common-utils-golang/openidUtils"

	"github.com/joncalhoun/form"
)

var inputFormTemplate = `
	<label {{with .ID}}for="{{.}}"{{end}}>
		{{.Label}}
	</label>
	<input {{with .ID}}id="{{.}}"{{end}} 
		type="{{.Type}}" 
		name="{{.Name}}" 
		placeholder="{{.Placeholder}}" 
		{{with .Value}}value="{{.}}"{{end}}>
		{{with .Footer}}<p>{{.}}</p>{{end}}
`

type Address struct {
	Street1 string `form:"label=Street;placeholder=123 Sample St"`
	Street2 string `form:"label=Street (cont);placeholder=Apt 123"`
	City    string
	State   string `form:"footer=Or your Province"`
	Zip     string `form:"label=Postal Code"`
	Country string
}

func TestTemplate(t *testing.T) {
	formTemplate := template.Must(template.New("").Parse(inputFormTemplate))
	formBuilder := form.Builder{
		InputTemplate: formTemplate,
	}

	pageTemplate := template.Must(template.New("").Funcs(formBuilder.FuncMap()).Parse(`
		<html>
		<body>
			<form>
				{{inputs_for .}}
			</form>
		</body>
		</html>`))

	// testing the HTML response
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		pageTemplate.Execute(w, Address{
			Street1: "123 Known St",
			Country: "United States",
		})

		// io.WriteString(w, "<html><body>Hello World!</body></html>")
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	_, _ = io.ReadAll(resp.Body)

	// fmt.Println(resp.StatusCode)
	// fmt.Println(resp.Header.Get("Content-Type"))
	// fmt.Println(string(body))

}

// httptest examples: https://go.dev/src/net/http/httptest/example_test.go

func TestExampleResponseRecorder(t *testing.T) {
	// creating the HTML with the form data
	formTemplate := template.Must(template.New("").Parse(openidUtils.TemplateResponseFormOauth2))
	formBuilder := form.Builder{InputTemplate: formTemplate}
	pageTemplate := template.Must(template.New("").Funcs(formBuilder.FuncMap()).Parse(openidUtils.TemplateResponsePageJARM))

	// testing the HTML response
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		pageTemplate.Execute(w, openidUtils.ResponseFormJARM{
			Response: "compactJWT",
		})
		// io.WriteString(w, "<html><body>Hello World!</body></html>")
	}

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	_, _ = io.ReadAll(resp.Body)

	// fmt.Println(resp.StatusCode)
	// fmt.Println(resp.Header.Get("Content-Type"))
	// fmt.Println(string(body))

	// Output:
	// 200
	// text/html; charset=utf-8
	// <html><body>Hello World!</body></html>
}
