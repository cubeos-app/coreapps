// CubeOS HAL (Hardware Abstraction Layer) Service
//
// @title CubeOS HAL API
// @version 1.1.0
// @description Hardware Abstraction Layer for Raspberry Pi and ARM64 SBCs
//
// @host cubeos.cube:6005
// @BasePath /hal
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"

	"cubeos-hal/internal/handlers"
)

func main() {
	// Get configuration from environment
	host := os.Getenv("HAL_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := os.Getenv("HAL_PORT")
	if port == "" {
		port = "6005"
	}

	// Create router
	r := chi.NewRouter()

	// Create handler
	h := handlers.NewHALHandler()

	// Health check at root
	r.Get("/health", h.HealthCheck)

	// Mount all HAL routes under /hal
	r.Route("/hal", func(r chi.Router) {
		handlers.SetupRoutes(r, h)
	})

	// Start server
	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("CubeOS HAL starting on %s", addr)
	log.Printf("Health: http://%s/health", addr)
	log.Printf("API: http://%s/hal/...", addr)
	log.Printf("Docs: http://%s/hal/docs", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
