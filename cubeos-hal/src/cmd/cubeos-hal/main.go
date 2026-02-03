package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"cubeos-hal/internal/handlers"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	// Get configuration from environment
	port := os.Getenv("HAL_PORT")
	if port == "" {
		port = "6005"
	}
	host := os.Getenv("HAL_HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	// Create handler
	h := handlers.NewHALHandler()

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"cubeos-hal","version":"1.0.0"}`))
	})

	// HAL routes
	r.Route("/hal", func(r chi.Router) {
		// Network interfaces
		r.Get("/network/interfaces", h.ListInterfaces)
		r.Get("/network/interface/{name}", h.GetInterface)
		r.Get("/network/interface/{name}/traffic", h.GetInterfaceTraffic)
		r.Post("/network/interface/{name}/up", h.BringInterfaceUp)
		r.Post("/network/interface/{name}/down", h.BringInterfaceDown)
		r.Get("/network/status", h.GetNetworkStatus)

		// WiFi operations
		r.Get("/network/wifi/scan/{iface}", h.ScanWiFi)
		r.Post("/network/wifi/connect", h.ConnectWiFi)
		r.Post("/network/wifi/disconnect/{iface}", h.DisconnectWiFi)

		// AP (Access Point) operations
		r.Get("/network/ap/clients", h.GetAPClients)
		r.Post("/network/ap/disconnect", h.DisconnectAPClient)
		r.Post("/network/ap/block", h.BlockAPClient)

		// Firewall operations
		r.Get("/firewall/rules", h.GetFirewallRules)
		r.Post("/firewall/nat/enable", h.EnableNAT)
		r.Post("/firewall/nat/disable", h.DisableNAT)
		r.Post("/firewall/forward/enable", h.EnableIPForward)
		r.Post("/firewall/forward/disable", h.DisableIPForward)
		r.Post("/firewall/rule", h.AddFirewallRule)
		r.Delete("/firewall/rule", h.DeleteFirewallRule)

		// VPN operations
		r.Get("/vpn/status", h.GetVPNStatus)
		r.Post("/vpn/wireguard/up/{name}", h.WireGuardUp)
		r.Post("/vpn/wireguard/down/{name}", h.WireGuardDown)
		r.Post("/vpn/openvpn/up/{name}", h.OpenVPNUp)
		r.Post("/vpn/openvpn/down/{name}", h.OpenVPNDown)

		// USB operations
		r.Get("/usb/devices", h.ListUSBDevices)
		r.Post("/usb/mount/{device}", h.MountUSB)
		r.Post("/usb/unmount/{device}", h.UnmountUSB)

		// Bluetooth operations (stubs)
		r.Get("/bluetooth/status", h.GetBluetoothStatus)
		r.Get("/bluetooth/devices", h.ListBluetoothDevices)
		r.Post("/bluetooth/scan", h.ScanBluetooth)
		r.Post("/bluetooth/pair", h.PairBluetooth)

		// System operations
		r.Post("/system/reboot", h.Reboot)
		r.Post("/system/shutdown", h.Shutdown)
		r.Post("/system/service/{name}/restart", h.RestartService)
		r.Post("/system/service/{name}/start", h.StartService)
		r.Post("/system/service/{name}/stop", h.StopService)
		r.Get("/system/service/{name}/status", h.ServiceStatus)
		r.Get("/system/throttle", h.GetThrottleStatus)
		r.Get("/system/temperature", h.GetCPUTemp)
		r.Get("/system/eeprom", h.GetEEPROMInfo)
		r.Get("/system/bootconfig", h.GetBootConfig)

		// Storage operations
		r.Get("/storage/devices", h.GetStorageDevices)
		r.Get("/storage/device/{device}", h.GetStorageDevice)
		r.Get("/storage/smart/{device}", h.GetSmartInfo)
		r.Get("/storage/usage", h.GetStorageUsage)

		// Mount operations
		r.Post("/mounts/smb", h.MountSMB)
		r.Post("/mounts/nfs", h.MountNFS)
		r.Post("/mounts/unmount", h.UnmountPath)
		r.Post("/mounts/test", h.TestMountConnection)
		r.Get("/mounts/list", h.ListMounts)
		r.Get("/mounts/check", h.CheckMounted)

		// Power management (UPS/Battery)
		r.Get("/power/status", h.GetPowerStatus)
		r.Get("/power/battery", h.GetBatteryStatus)
		r.Get("/power/ups", h.GetUPSInfo)
		r.Post("/power/charging", h.SetChargingEnabled)
		r.Post("/power/battery/quickstart", h.QuickStartBattery)
		r.Post("/power/monitor/start", h.StartPowerMonitor)
		r.Post("/power/monitor/stop", h.StopPowerMonitor)

		// System info
		r.Get("/system/uptime", h.GetUptime)

		// RTC (Real-Time Clock)
		r.Get("/rtc/status", h.GetRTCStatus)
		r.Post("/rtc/sync-to-rtc", h.SetRTCTime)
		r.Post("/rtc/sync-from-rtc", h.SyncTimeFromRTC)
		r.Post("/rtc/wakealarm", h.SetWakeAlarm)
		r.Delete("/rtc/wakealarm", h.ClearWakeAlarm)

		// Watchdog
		r.Get("/watchdog/status", h.GetWatchdogStatus)
		r.Post("/watchdog/pet", h.PetWatchdog)
		r.Post("/watchdog/enable", h.EnableWatchdog)

		// I2C bus operations
		r.Get("/i2c/buses", h.ListI2CBuses)
		r.Get("/i2c/scan", h.ScanI2CBus)
	})

	// Start server
	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("Starting CubeOS HAL service on %s", addr)
	log.Printf("Health: http://%s/health", addr)
	log.Printf("API: http://%s/hal/...", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
