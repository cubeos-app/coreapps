package handlers

import (
	_ "embed"
	"net/http"
)

// OpenAPI spec embedded at compile time
// To update: edit api/openapi.yaml and rebuild
//
//go:embed openapi.yaml
var openAPISpec []byte

// ServeOpenAPISpec serves the raw OpenAPI YAML specification
// @Summary Get OpenAPI specification
// @Description Returns the OpenAPI 3.0 specification for the HAL API
// @Tags Documentation
// @Produce text/yaml
// @Success 200 {string} string "OpenAPI YAML specification"
// @Router /openapi.yaml [get]
func (h *HALHandler) ServeOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(openAPISpec)
}

// ServeSwaggerUI serves the Swagger UI documentation page
// @Summary Swagger UI documentation
// @Description Interactive API documentation using Swagger UI
// @Tags Documentation
// @Produce text/html
// @Success 200 {string} string "Swagger UI HTML page"
// @Router /docs [get]
func (h *HALHandler) ServeSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerUIHTML))
}

// Swagger UI HTML template - loads spec from /hal/openapi.yaml
const swaggerUIHTML = `<!DOCTYPE html>
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
        .topbar { display: none; }
        .swagger-ui .info { margin: 30px 0; }
        .swagger-ui .info .title { color: #3b4151; }
        .swagger-ui .scheme-container { background: #fff; box-shadow: 0 1px 2px 0 rgba(0,0,0,.15); }
        /* CubeOS branding */
        .swagger-ui .info hgroup.main a { display: none; }
        .swagger-ui .info .title small { background: #7c3aed; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: "/hal/openapi.yaml",
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
                docExpansion: "list",
                filter: true,
                showExtensions: true,
                showCommonExtensions: true,
                tryItOutEnabled: true
            });
            window.ui = ui;
        };
    </script>
</body>
</html>`
