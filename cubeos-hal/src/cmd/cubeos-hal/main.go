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
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Health check at root (outside timeout wrapper — must always respond fast)
	r.Get("/health", h.HealthCheck)

	// Mount all HAL routes under /hal with request timeout middleware
	r.Route("/hal", func(r chi.Router) {
		handlers.SetupRoutes(r, h)
	})

	// Wrap entire router with request timeout (60s default)
	requestTimeout := 60 * time.Second
	if v := os.Getenv("HAL_REQUEST_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			requestTimeout = d
		}
	}
	handler := http.TimeoutHandler(r, requestTimeout, `{"error":"request timeout","code":504}`)

	// Configure HTTP server with timeouts
	addr := fmt.Sprintf("%s:%s", host, port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second, // Must be > request timeout
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("CubeOS HAL starting on %s", addr)
		log.Printf("Health: http://%s/health", addr)
		log.Printf("API: http://%s/hal/...", addr)
		log.Printf("Docs: http://%s/hal/docs", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal %s, shutting down gracefully...", sig)

	// Give 15 seconds for graceful shutdown (aligned with Pi watchdog timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("CubeOS HAL stopped")
}
