package openidUtils

import (
	"github.com/joncalhoun/form"
	"html/template"
	"net/http"
)

// https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
// https://github.com/joncalhoun/form
var TemplateResponseFormOauth2 = `
	<input {{with .ID}}id="{{.}}"{{end}} 
		type="{{.Type}}" 
		name="{{.Name}}" 
		{{with .Value}}value="{{.}}"{{end}}>
`

// https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html#FormPostResponseExample
// https://github.com/joncalhoun/form
var TemplateResponsePageJARM = `
	<html>
	<head><title>JARM form_post.jwt</title></head>
	<body onload="javascript:document.forms[0].submit()">
		<form>
			{{inputs_for .}}
		</form>
	</body>
	</html>`

type ResponseFormJARM struct {
	Response string `json:"response" form:"type=hidden;name=response"`
	// State: not for JARM (it is in the JWT)
}

// ReturnWebPageFormData returns a Web page which contains the form data (with automatic form post when loading the body)
// and HTTP Status 200 (OK).
func (formData *ResponseFormJARM) ReturnWebPageFormData(w http.ResponseWriter) {
	// creating the HTML with the form data
	formTemplate := template.Must(template.New("").Parse(TemplateResponseFormOauth2))
	formBuilder := form.Builder{InputTemplate: formTemplate}
	pageTemplate := template.Must(template.New("").Funcs(formBuilder.FuncMap()).Parse(TemplateResponsePageJARM))

	// writing the HTML response
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html")
	pageTemplate.Execute(w, formData)
}
