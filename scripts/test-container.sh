#!/usr/bin/env bash
# Container contract for FND-001 / Wave 5. Requires Docker. Fail closed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${LABSSO_TEST_IMAGE:-ghcr.io/hilather/labsso:test}"
NAME="labsso-container-test-$$"
CFG="${ROOT}/testdata/config/valid/minimal.yaml"
SECRETS="${ROOT}/testdata/secrets"
COMPOSE="${ROOT}/examples/compose.yaml"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required for make test-container" >&2
	exit 1
fi
if ! docker info >/dev/null 2>&1; then
	echo "docker daemon is not available for make test-container" >&2
	exit 1
fi

if ! grep -q '443:10443' "${COMPOSE}"; then
	echo "examples/compose.yaml must still publish 443:10443" >&2
	exit 1
fi
if grep -q '443:443' "${COMPOSE}"; then
	echo "management or HTTPS must not bind host 443 as a container 443" >&2
	exit 1
fi

cleanup() {
	docker rm -f "${NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "building ${IMAGE}"
docker build -t "${IMAGE}" "${ROOT}"

inspect_user="$(docker image inspect --format '{{.Config.User}}' "${IMAGE}")"
if [ "${inspect_user}" != "65532:65532" ]; then
	echo "image User=${inspect_user}, want 65532:65532" >&2
	exit 1
fi

licenses="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}' "${IMAGE}")"
if [ "${licenses}" != "Apache-2.0" ]; then
	echo "image license label=${licenses}, want Apache-2.0" >&2
	exit 1
fi

# Ephemeral host port -> container :10443. Do not occupy host 443 in this test.
docker run -d --name "${NAME}" \
	--read-only \
	--cap-drop=ALL \
	--security-opt=no-new-privileges:true \
	--tmpfs /tmp:rw,noexec,nosuid,size=16m \
	-v "${CFG}:/etc/labsso/config.yaml:ro" \
	-v "${SECRETS}:/testdata/secrets:ro" \
	-p 127.0.0.1::10443/tcp \
	-p 127.0.0.1::8080/tcp \
	"${IMAGE}"

pid="$(docker inspect --format '{{.State.Pid}}' "${NAME}")"
if [ ! -r "/proc/${pid}/status" ]; then
	echo "cannot read /proc/${pid}/status to verify non-root/no-caps" >&2
	exit 1
fi
uid="$(awk '/^Uid:/{print $2}' "/proc/${pid}/status")"
if [ "${uid}" != "65532" ]; then
	echo "runtime Uid=${uid}, want 65532" >&2
	exit 1
fi
capeff="$(awk '/^CapEff:/{print $2}' "/proc/${pid}/status")"
if [ "${capeff}" != "0000000000000000" ]; then
	echo "CapEff=${capeff}, want 0000000000000000 (no capabilities)" >&2
	exit 1
fi

https_port="$(docker port "${NAME}" 10443/tcp | head -n1 | awk -F: '{print $NF}')"
mgmt_port="$(docker port "${NAME}" 8080/tcp | head -n1 | awk -F: '{print $NF}')"

ok=0
for _ in $(seq 1 40); do
	if curl -fsS "http://127.0.0.1:${mgmt_port}/v1/health/ready" >/dev/null 2>&1; then
		ok=1
		break
	fi
	sleep 0.25
done
if [ "${ok}" -ne 1 ]; then
	echo "management ready check failed on 127.0.0.1:${mgmt_port}" >&2
	docker logs "${NAME}" >&2 || true
	exit 1
fi

code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${https_port}/")"
if [ "${code}" != "404" ]; then
	echo "HTTPS dest-443 mapping (ephemeral host port -> :10443) expected 404 until OIDC, got ${code}" >&2
	docker logs "${NAME}" >&2 || true
	exit 1
fi

echo "container contract ok user=65532 read-only cap_drop=ALL https=127.0.0.1:${https_port}->10443 ready=ok compose=443:10443"
