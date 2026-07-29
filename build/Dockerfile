# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.2 AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -buildid=" -o /out/procrustes ./cmd/procrustes

FROM gcr.io/distroless/static-debian12
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="procrustes"
LABEL org.opencontainers.image.version=$VERSION
LABEL org.opencontainers.image.revision=$COMMIT
LABEL org.opencontainers.image.created=$BUILD_DATE
COPY --from=builder /out/procrustes /usr/local/bin/procrustes
ENTRYPOINT ["/usr/local/bin/procrustes"]
