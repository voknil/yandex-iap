# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/yandex-iap \
    .

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/voknil/yandex-iap"
LABEL org.opencontainers.image.description="Forward-auth IAP for Yandex ID"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=build /out/yandex-iap /yandex-iap

EXPOSE 9090
USER nonroot:nonroot
ENTRYPOINT ["/yandex-iap"]
