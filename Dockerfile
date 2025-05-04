# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o dcm ./cmd/dcm.go

# Final image
FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/dcm /usr/local/bin/dcm
ENTRYPOINT ["dcm"]
