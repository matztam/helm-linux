# Helm pairing & authentication — reverse-engineered map

Reconstructed from `libgmm.so` (native VCM subsystem) and the decompiled
protobuf/Java. This is what stands between "connect to the plotter" and
"actually view/control it", and what `helm/credential.py` reimplements.

## The gate: a VCM auth JWT

The GMN 2.0 control channel (port 51200) and the RTSP video are authorized by a
**VCM auth JWT**, presented as `Authorization: Bearer <jwt>`. Native evidence:
`msl/vcm/Auth/{SeedJwt,GenerateJwt,RefreshJwt,JwtManager,JwtMiddleware}.cpp`,
`"Cannot seed VCM auth JWT"`, `application/jwt`, `Authorization: Bearer %s`.

So everything hinges on obtaining that JWT. There are two issuers:

* **Local (what we want):** the plotter itself, via its on-board credential
  service, when you're on the plotter's WiFi with no internet.
* **Cloud:** `profile*.marine.garmin.com/Authentication/{generate,refresh}-token`
  — account-bound, needs a myGarmin login/OAuth. We avoid this path.

## Local flow (reimplemented in helm/credential.py)

### 1. Discover the credential service
mDNS `_garmin-mrn-cred._tcp` — the "marine credential service". TXT carries
`tag` and `version`. Gives host:port.

### 2. Pair (authorize this device)  ← the one binary piece left
A **BCM network pair request** is sent (`bcm_net_send_pair_request`,
`bcm_pair_request_serialize`). The plotter shows a confirm / pass-key prompt on
its screen; the user accepts. Result is one of `CONFIRMED` / `REJECTED` /
`NO_ACTION` (native: `bcm_pair_reply_deserialize`, `"Handling network pair
reply"`). This marks the client as a known/registered device (the local
`devices` SQLite table: `unit_id, product_nmbr, vcm_role, registration_status`).

The pair request/reply are binary-serialized Garmin "DDF" messages. Their exact
layout is the remaining unknown; see "Next" below.

### 3. Get the token
`POST /Authentication/generate-token` to the credential service. Request fields
(from the binary): `client_id`, `device_id`, `unit_id`, `role`, `clientTime`.
Response JSON: `{"credentials", "device_id", "role", "token"/"jwtToken",
"expires"}`. `token` is the JWT. `/Authentication/refresh-token` renews it.
`GET /garmin/credentials/` reports status.

### 4. Use it
Send the JWT as `Authorization: Bearer` when opening the GMN 2.0 session
(helm.gmn2) and the RTSP stream (helm.video). The stream URL itself is then
delivered over the authorized GMN 2.0 session (HelmDevice.streamUrl).

## What's implemented vs. open

| Step | State |
|---|---|
| 1 discover mrn-cred | ✅ `helm/credential.py:discover_credential_service` |
| 3 generate/refresh token, status | ✅ implemented from RE'd field names — testable now |
| 4 Bearer on GMN2/RTSP | ✅ wiring ready (needs a token) |
| 2 BCM pair request/reply framing | 🚧 binary; confirm from device error responses or one capture |

## Next: let the plotter tell us

Run `python3 helm-cli.py pair` on the plotter's WiFi. It probes
`/garmin/credentials/` and `/Authentication/generate-token` and prints the
plotter's exact responses. Those responses reveal:

* whether generate-token works pre-pairing or demands the pair/confirm step,
* the exact required fields / error shape,
* whether the token is issued locally or bounced to the cloud.

That turns step 2 from guesswork into a precise target. The alternative to
reversing the BCM pair serialization byte-by-byte is a single capture of the
phone's *first* pairing (when the plotter shows the prompt) — but the probe
comes first because it's free and may show pairing isn't even required for a
`helm`/view role.

## Honest risk

If the plotter refuses to issue a local token without a cloud/account round-trip
(the refresh endpoint is cloud-hosted), a fully standalone laptop client may
still need a myGarmin OAuth token. The `pair` probe is what tells us which world
we're in.
