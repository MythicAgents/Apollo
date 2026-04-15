package sentinel.gateway

default allow = false

allow {
  input.identity.spiffe_id == "spiffe://sentinel.nnsec.io/device/approved"
  input.request.destination in {"github.com:443", "console.sentinel.nnsec.io:443"}
}
