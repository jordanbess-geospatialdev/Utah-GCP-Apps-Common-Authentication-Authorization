# ============================================================================
# Stage 1: Build the Go binary
# ============================================================================
FROM golang:1.23-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/authz-server ./cmd/authz-server

# ============================================================================
# Stage 2: Minimal Distroless Runtime for GCP Cloud Run
# ============================================================================
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/authz-server /authz-server
COPY --from=builder /src/migrations /migrations

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/authz-server"]
