# build stage
FROM golang:1.24-alpine AS builder
WORKDIR /app

RUN apk add --no-cache gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM builder AS builder_sso
RUN CGO_ENABLED=1 GOOS=linux go build -o /sso ./cmd/sso

FROM builder AS builder_migrator
RUN CGO_ENABLED=1 GOOS=linux go build -o /sso-migrator ./cmd/migrator

# runtime stage
FROM alpine:3.20 AS sso
WORKDIR /app
COPY --from=builder_sso /sso /app/sso
EXPOSE 8080
ENTRYPOINT ["/app/sso"]

FROM alpine:3.20 AS migrate
WORKDIR /app
COPY --from=builder_migrator /sso-migrator /app/sso-migrator
ENTRYPOINT ["/app/sso-migrator"]
