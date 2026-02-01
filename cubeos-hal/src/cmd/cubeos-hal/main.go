// CubeOS Hardware Abstraction Layer (HAL)
// Tiny privileged service providing hardware access to unprivileged containers
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"cubeos-hal/internal/handlers"
)

const (
	defaultPort = "6005"
	defaultHost = "0.0.0.0"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("CubeOS HAL starting...")

	// Get port from environment or use default
	port := os.Getenv("HAL_PORT")
	if port == "" {
		port = defaultPort
	}

	host := os.Getenv("HAL_HOST")
	if host == "" {
		host = defaultHost
	}

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"cubeos-hal"}`))
	})

	// HAL handlers
	h := handlers.NewHALHandler()

	// Network endpoints
	r.Route("/hal/network", func(r chi.Router) {
		// Interface control
		r.Get("/interfaces", h.ListInterfaces)
		r.Get("/interface/{name}", h.GetInterface)
		r.Post("/interface/{name}/up", h.BringInterfaceUp)
		r.Post("/interface/{name}/down", h.BringInterfaceDown)

		// WiFi operations
		r.Get("/wifi/scan/{iface}", h.ScanWiFi)
		r.Post("/wifi/connect", h.ConnectWiFi)
		r.Post("/wifi/disconnect/{iface}", h.DisconnectWiFi)

		// Status
		r.Get("/status", h.GetNetworkStatus)
	})

	// Firewall endpoints
	r.Route("/hal/firewall", func(r chi.Router) {
		r.Get("/rules", h.GetFirewallRules)
		r.Post("/nat/enable", h.EnableNAT)
		r.Post("/nat/disable", h.DisableNAT)
		r.Post("/rule", h.AddFirewallRule)
		r.Delete("/rule", h.DeleteFirewallRule)
		r.Post("/forward/enable", h.EnableIPForward)
		r.Post("/forward/disable", h.DisableIPForward)
	})

	// VPN endpoints
	r.Route("/hal/vpn", func(r chi.Router) {
		r.Get("/status", h.GetVPNStatus)
		r.Post("/wireguard/up/{name}", h.WireGuardUp)
		r.Post("/wireguard/down/{name}", h.WireGuardDown)
		r.Post("/openvpn/up/{name}", h.OpenVPNUp)
		r.Post("/openvpn/down/{name}", h.OpenVPNDown)
	})

	// USB endpoints
	r.Route("/hal/usb", func(r chi.Router) {
		r.Get("/devices", h.ListUSBDevices)
		r.Post("/mount/{device}", h.MountUSB)
		r.Post("/unmount/{device}", h.UnmountUSB)
	})

	// Bluetooth endpoints (future)
	r.Route("/hal/bluetooth", func(r chi.Router) {
		r.Get("/status", h.GetBluetoothStatus)
		r.Get("/devices", h.ListBluetoothDevices)
		r.Post("/scan", h.ScanBluetooth)
		r.Post("/pair/{mac}", h.PairBluetooth)
	})

	// System endpoints
	r.Route("/hal/system", func(r chi.Router) {
		r.Post("/reboot", h.Reboot)
		r.Post("/shutdown", h.Shutdown)
		r.Post("/service/{name}/restart", h.RestartService)
		r.Post("/service/{name}/start", h.StartService)
		r.Post("/service/{name}/stop", h.StopService)
		r.Get("/service/{name}/status", h.ServiceStatus)
	})

	// Create server
	addr := host + ":" + port
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("HAL listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down HAL...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("HAL stopped")
}
// Build trigger zo  1 feb 2026 11:06:12 CET
