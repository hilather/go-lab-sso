# LabSSO production image: ghcr.io/hilather/labsso
#
# Multi-stage, static binary, numeric non-root UID, no shell.
# Run with a read-only root filesystem, cap_drop ALL, and no-new-privileges.
# Host port 443 maps to container 10443. Management is :8080 (never 443).

FROM golang:1.26-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
	-ldflags="-s -w \
	-X github.com/hilather/go-lab-sso/internal/buildinfo.Version=${VERSION} \
	-X github.com/hilather/go-lab-sso/internal/buildinfo.Commit=${COMMIT} \
	-X github.com/hilather/go-lab-sso/internal/buildinfo.Date=${BUILD_TIME}" \
	-o /out/labsso ./cmd/labsso \
	&& printf 'labsso:x:65532:65532:labsso:/:/sbin/nologin\n' > /out/passwd \
	&& printf 'labsso:x:65532:\n' > /out/group \
	&& cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt \
	&& cp LICENSE /out/LICENSE

FROM scratch

LABEL org.opencontainers.image.title="labsso" \
	org.opencontainers.image.description="Laboratory SSO Identity Provider" \
	org.opencontainers.image.source="https://github.com/hilather/go-lab-sso" \
	org.opencontainers.image.url="https://github.com/hilather/go-lab-sso" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.vendor="hilather" \
	org.opencontainers.image.documentation="https://github.com/hilather/go-lab-sso/blob/main/docs/11-deployment.md"

COPY --from=build /out/passwd /etc/passwd
COPY --from=build /out/group /etc/group
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/labsso /labsso
COPY --from=build /out/LICENSE /LICENSE

USER 65532:65532
EXPOSE 10443/tcp 8080/tcp
WORKDIR /

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
	CMD ["/labsso", "healthcheck", "--url=http://127.0.0.1:8080/v1/health/ready"]

ENTRYPOINT ["/labsso"]
CMD ["serve", "--config=/etc/labsso/config.yaml"]
