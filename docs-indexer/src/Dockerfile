# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o docs-indexer .

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/docs-indexer .

# Create docs directory
RUN mkdir -p /cubeos/docs

ENTRYPOINT ["/app/docs-indexer"]
