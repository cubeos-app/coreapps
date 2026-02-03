package handlers

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// SetupRoutes configures all HAL API routes.
func SetupRoutes(r chi.Router, h *HALHandler) {
	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// Health check
	r.Get("/health", h.HealthCheck)

	// Documentation
	r.Get("/docs", h.ServeSwaggerUI)
	r.Get("/docs/", h.ServeSwaggerUI)
	r.Get("/docs/openapi.yaml", h.ServeOpenAPISpec)

	// System
	r.Route("/system", func(r chi.Router) {
		r.Get("/temperature", h.GetCPUTemp)
		r.Get("/throttle", h.GetThrottleStatus)
		r.Get("/eeprom", h.GetEEPROMInfo)
		r.Get("/bootconfig", h.GetBootConfig)
		r.Get("/uptime", h.GetUptime)
		r.Post("/reboot", h.Reboot)
		r.Post("/shutdown", h.Shutdown)

		// Service management
		r.Get("/service/{name}/status", h.ServiceStatus)
		r.Post("/service/{name}/start", h.StartService)
		r.Post("/service/{name}/stop", h.StopService)
		r.Post("/service/{name}/restart", h.RestartService)
	})

	// Power (Battery, UPS, RTC, Watchdog)
	r.Route("/power", func(r chi.Router) {
		r.Get("/status", h.GetPowerStatus)
		r.Get("/battery", h.GetBatteryStatus)
		r.Get("/ups", h.GetUPSInfo)
		r.Post("/charging", h.SetChargingEnabled)
		r.Post("/battery/quickstart", h.QuickStartBattery)
		r.Post("/monitor/start", h.StartPowerMonitor)
		r.Post("/monitor/stop", h.StopPowerMonitor)
	})

	// RTC
	r.Route("/rtc", func(r chi.Router) {
		r.Get("/status", h.GetRTCStatus)
		r.Post("/sync-to-rtc", h.SetRTCTime)
		r.Post("/sync-from-rtc", h.SyncTimeFromRTC)
		r.Post("/wakealarm", h.SetWakeAlarm)
		r.Delete("/wakealarm", h.ClearWakeAlarm)
	})

	// Watchdog
	r.Route("/watchdog", func(r chi.Router) {
		r.Get("/status", h.GetWatchdogStatus)
		r.Post("/pet", h.PetWatchdog)
		r.Post("/enable", h.EnableWatchdog)
	})

	// Network
	r.Route("/network", func(r chi.Router) {
		r.Get("/interfaces", h.ListInterfaces)
		r.Get("/interface/{name}", h.GetInterface)
		r.Get("/interface/{name}/traffic", h.GetInterfaceTraffic)
		r.Post("/interface/{name}/up", h.BringInterfaceUp)
		r.Post("/interface/{name}/down", h.BringInterfaceDown)
		r.Get("/status", h.GetNetworkStatus)

		// WiFi
		r.Get("/wifi/scan/{iface}", h.ScanWiFi)
		r.Post("/wifi/connect", h.ConnectWiFi)
		r.Post("/wifi/disconnect/{iface}", h.DisconnectWiFi)

		// Access Point
		r.Get("/ap/status", h.GetAPStatus)
		r.Get("/ap/clients", h.GetAPClients)
		r.Post("/ap/disconnect", h.DisconnectAPClient)
		r.Post("/ap/block", h.BlockAPClient)
	})

	// Firewall
	r.Route("/firewall", func(r chi.Router) {
		r.Get("/rules", h.GetFirewallRules)
		r.Post("/rule", h.AddFirewallRule)
		r.Delete("/rule", h.DeleteFirewallRule)
		r.Post("/nat/enable", h.EnableNAT)
		r.Post("/nat/disable", h.DisableNAT)
		r.Post("/forward/enable", h.EnableIPForward)
		r.Post("/forward/disable", h.DisableIPForward)
	})

	// VPN
	r.Route("/vpn", func(r chi.Router) {
		r.Get("/status", h.GetVPNStatus)

		// WireGuard
		r.Post("/wireguard/up/{name}", h.WireGuardUp)
		r.Post("/wireguard/down/{name}", h.WireGuardDown)

		// OpenVPN
		r.Post("/openvpn/up/{name}", h.OpenVPNUp)
		r.Post("/openvpn/down/{name}", h.OpenVPNDown)

		// Tor
		r.Get("/tor/status", h.GetTorStatus)
		r.Get("/tor/config", h.GetTorConfig)
		r.Post("/tor/start", h.StartTor)
		r.Post("/tor/stop", h.StopTor)
		r.Post("/tor/newcircuit", h.NewTorCircuit)
	})

	// Storage
	r.Route("/storage", func(r chi.Router) {
		r.Get("/devices", h.GetStorageDevices)
		r.Get("/device/{device}", h.GetStorageDevice)
		r.Get("/smart/{device}", h.GetSmartInfo)
		r.Get("/usage", h.GetStorageUsage)

		// USB Storage
		r.Get("/usb", h.GetUSBStorageDevices)
		r.Post("/usb/mount", h.MountUSBStorage)
		r.Post("/usb/unmount", h.UnmountUSBStorage)
		r.Post("/usb/eject", h.EjectUSBStorage)
	})

	// Logs
	r.Route("/logs", func(r chi.Router) {
		r.Get("/kernel", h.GetKernelLogs)
		r.Get("/journal", h.GetJournalLogs)
		r.Get("/hardware", h.GetHardwareLogs)
	})

	// Support bundle
	r.Get("/support/bundle.zip", h.GetSupportBundle)

	// GPS
	r.Route("/gps", func(r chi.Router) {
		r.Get("/devices", h.GetGPSDevices)
		r.Get("/status", h.GetGPSStatus)
		r.Get("/position", h.GetGPSPosition)
	})

	// Cellular
	r.Route("/cellular", func(r chi.Router) {
		r.Get("/modems", h.GetCellularModems)
		r.Get("/status", h.GetCellularStatus)
		r.Get("/signal", h.GetCellularSignal)
		r.Post("/connect/{modem}", h.ConnectCellular)
		r.Post("/disconnect/{modem}", h.DisconnectCellular)

		// Android tethering
		r.Get("/android/status", h.GetAndroidTetheringStatus)
		r.Post("/android/enable", h.EnableAndroidTethering)
		r.Post("/android/disable", h.DisableAndroidTethering)
	})

	// Meshtastic
	r.Route("/meshtastic", func(r chi.Router) {
		r.Get("/status", h.GetMeshtasticStatus)
		r.Get("/nodes", h.GetMeshtasticNodes)
		r.Post("/send", h.SendMeshtasticMessage)
		r.Post("/channel", h.SetMeshtasticChannel)
	})

	// Iridium
	r.Route("/iridium", func(r chi.Router) {
		r.Get("/status", h.GetIridiumStatus)
		r.Get("/signal", h.GetIridiumSignal)
		r.Post("/send", h.SendIridiumSBD)
		r.Get("/messages", h.GetIridiumMessages)
		r.Post("/check", h.CheckIridiumMailbox)
	})

	// Camera
	r.Route("/camera", func(r chi.Router) {
		r.Get("/devices", h.GetCameras)
		r.Get("/info", h.GetCameraInfo)
		r.Post("/capture", h.CaptureImage)
		r.Get("/image", h.GetCapturedImage)
		r.Get("/stream/status", h.GetStreamInfo)
		r.Post("/stream/start", h.StartStream)
		r.Post("/stream/stop", h.StopStream)
	})

	// Sensors
	r.Route("/sensors", func(r chi.Router) {
		r.Get("/all", h.GetAllSensorReadings)

		// 1-Wire
		r.Get("/1wire/devices", h.Get1WireDevices)
		r.Get("/1wire/device/{id}", h.Read1WireDevice)
		r.Get("/1wire/temperatures", h.Read1WireTemperatures)

		// BME280
		r.Get("/bme280", h.ReadBME280)
		r.Get("/bme280/detect", h.DetectBME280)
	})

	// Audio
	r.Route("/audio", func(r chi.Router) {
		r.Get("/devices", h.GetAudioDevices)
		r.Get("/playback", h.GetPlaybackDevices)
		r.Get("/capture", h.GetCaptureDevices)
		r.Get("/volume", h.GetVolume)
		r.Post("/volume", h.SetVolume)
		r.Post("/mute", h.SetMute)
		r.Post("/test", h.PlayTestTone)
	})

	// GPIO
	r.Route("/gpio", func(r chi.Router) {
		r.Get("/pins", h.GetGPIOStatus)
		r.Get("/pin/{pin}", h.GetGPIOPin)
		r.Post("/pin", h.SetGPIOPin)
		r.Post("/mode", h.SetGPIOMode)
		r.Post("/export/{pin}", h.ExportGPIOPin)
		r.Post("/unexport/{pin}", h.UnexportGPIOPin)
	})

	// I2C
	r.Route("/i2c", func(r chi.Router) {
		r.Get("/buses", h.ListI2CBuses)
		r.Get("/scan", h.ScanI2CBus)
		r.Get("/bus/{bus}/device/{address}", h.GetI2CDevice)
		r.Get("/read", h.ReadI2CRegister)
		r.Post("/write", h.WriteI2CRegister)
	})

	// USB
	r.Route("/usb", func(r chi.Router) {
		r.Get("/devices", h.GetUSBDevices)
		r.Get("/tree", h.GetUSBDevicesTree)
		r.Get("/class", h.GetUSBDevicesByClass)
		r.Post("/reset", h.ResetUSBDevice)
		r.Post("/rescan", h.RescanUSB)
	})

	// Bluetooth
	r.Route("/bluetooth", func(r chi.Router) {
		r.Get("/status", h.GetBluetoothStatus)
		r.Post("/power/on", h.PowerOnBluetooth)
		r.Post("/power/off", h.PowerOffBluetooth)
		r.Get("/devices", h.GetBluetoothDevices)
		r.Post("/scan", h.ScanBluetoothDevices)
		r.Post("/pair", h.PairBluetoothDevice)
		r.Post("/connect/{address}", h.ConnectBluetoothDevice)
		r.Post("/disconnect/{address}", h.DisconnectBluetoothDevice)
		r.Delete("/remove/{address}", h.RemoveBluetoothDevice)
	})

	// Network Mounts
	r.Route("/mounts", func(r chi.Router) {
		r.Get("/", h.GetNetworkMounts)
		r.Post("/smb", h.MountSMB)
		r.Post("/nfs", h.MountNFS)
		r.Post("/unmount", h.UnmountNetwork)
		r.Get("/smb/check", h.CheckSMBServer)
		r.Get("/nfs/check", h.CheckNFSServer)
	})
}
