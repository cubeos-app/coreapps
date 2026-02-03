package handlers

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed openapi.yaml
var openapiSpec []byte

// ServeOpenAPISpec serves the OpenAPI specification.
// @Summary Get OpenAPI spec
// @Description Returns the OpenAPI 3.0 specification in YAML format
// @Tags Documentation
// @Produce text/yaml
// @Success 200 {string} string "OpenAPI YAML specification"
// @Router /docs/openapi.yaml [get]
func (h *HALHandler) ServeOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(openapiSpec)
}

// ServeSwaggerUI serves the Swagger UI.
// @Summary Swagger UI
// @Description Interactive API documentation
// @Tags Documentation
// @Produce text/html
// @Success 200 {string} string "Swagger UI HTML"
// @Router /docs [get]
func (h *HALHandler) ServeSwaggerUI(w http.ResponseWriter, r *http.Request) {
	// Determine base path from request
	basePath := "/hal"
	if strings.HasPrefix(r.URL.Path, "/hal") {
		basePath = "/hal"
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CubeOS HAL API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        html { box-sizing: border-box; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui .info { margin: 20px 0; }
        .swagger-ui .info .title { font-size: 2em; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "` + basePath + `/docs/openapi.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                displayRequestDuration: true,
                filter: true,
                showExtensions: true,
                showCommonExtensions: true,
                tryItOutEnabled: true
            });
        };
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// HealthCheck returns health status.
// @Summary Health check
// @Description Returns HAL service health status
// @Tags System
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /health [get]
func (h *HALHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"service": "cubeos-hal",
		"version": "1.1.0",
	})
}
