# Build stage
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download
# Copy source code
COPY . .
# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o cubeos-hal ./cmd/cubeos-hal
# Runtime stage - use full alpine for tools (iw, ip, iptables, etc.)
FROM alpine:3.19
# Install required tools for hardware control
RUN apk add --no-cache \
    iproute2 \
    iptables \
    wireless-tools \
    iw \
    wpa_supplicant \
    hostapd \
    dhclient \
    wireguard-tools \
    openvpn \
    util-linux \
    procps \
    usbutils \
    i2c-tools \
    libgpiod
WORKDIR /app
# Copy binary from builder
COPY --from=builder /app/cubeos-hal .
# Expose HAL port
EXPOSE 6005
# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1:6005/health || exit 1
# Run HAL
CMD ["./cubeos-hal"]
