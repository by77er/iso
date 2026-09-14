#!/usr/bin/env bash
# End-to-end check of a deployed rig, through the fleet API only. Uses the
# exports deploy.sh prints (ISO_SERVER, ISO_CREDS, ISO_CLIENT) and the test
# secrets (a fake header for postman-echo.com), so no real credential is
# involved. Creates two VMs and destroys them.
set -euo pipefail
: "${ISO_SERVER:?}" "${ISO_CREDS:?}" "${ISO_CLIENT:?}"
ISOCTL="${ISOCTL:-isoctl}"
TEMPLATE="${TEMPLATE:-debian}"
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ok   $*"; }
bad()  { fail=$((fail+1)); echo "  FAIL $*"; }
api()  { curl -sS --cert "$ISO_CREDS/$ISO_CLIENT.crt" --key "$ISO_CREDS/$ISO_CLIENT.key" --cacert "$ISO_CREDS/ca.crt" "$@"; }
py()   { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
vmexec() { "$ISOCTL" vm exec "$1" -- sh -c "$2" 2>/dev/null; }

echo "== fleet"
hosts=$(api "$ISO_SERVER/hosts")
echo "$hosts" | py "print('  hosts:', [(h['name'], h['healthy'], h['slots_free'], h['templates']) for h in d])"
healthy=$(echo "$hosts" | py "print(sum(1 for h in d if h['healthy'] and '$TEMPLATE' in h['templates']))")
[ "$healthy" = 2 ] && ok "two healthy hosts with template $TEMPLATE" || bad "expected two healthy hosts with $TEMPLATE, got $healthy"

echo "== create, placed by the fleet"
id=$("$ISOCTL" vm create --template "$TEMPLATE" --egress proxy --principal alice \
  --allow postman-echo.com --allow echo.websocket.org \
  --rule 'deny https://postman-echo.com/status/**' --quiet)
vm=$(api "$ISO_SERVER/vms/$id")
host=$(echo "$vm" | py "print(d['host'])")
echo "$vm" | py "print('  vm', d['id'][:8], 'on', d['host'], '·', d['fleet_state'], '·', d['state'], '· gen', d['policy_gen'])"
[ -n "$host" ] && ok "placed on $host" || bad "no host recorded"

echo "== guest agent up"
for _ in $(seq 1 60); do "$ISOCTL" vm agent "$id" >/dev/null 2>&1 && break; sleep 2; done
"$ISOCTL" vm agent "$id" >/dev/null 2>&1 && ok "agent answers through the fleet" || bad "agent never answered"
for _ in $(seq 1 30); do vmexec "$id" 'getent hosts postman-echo.com >/dev/null' && break; sleep 2; done

echo "== guest clock: stepped to the host's after the snapshot resume"
guest_now=$(vmexec "$id" 'date +%s' || echo 0); here_now=$(date +%s)
skew=$(( here_now - guest_now )); [ "$skew" -lt 0 ] && skew=$(( -skew ))
[ "$skew" -le 5 ] && ok "guest clock within ${skew}s of ours" || bad "guest clock is ${skew}s off (template bake time?)"

echo "== allowed request: terminated on the control host, header injected there"
out=$(vmexec "$id" 'curl -sS --max-time 20 https://postman-echo.com/get' || true)
echo "$out" | grep -q '"x-iso-injected": *"hello-from-the-control-host"' && ok "global header injected" || bad "no injected header: $(echo "$out" | head -c 300)"
echo "$out" | grep -q '"x-iso-principal": *"alice"' && ok "per-principal header injected" || bad "no principal header"

echo "== URI rule: deny beats allow, 403 names the rule"
code=$(vmexec "$id" 'curl -s -o /tmp/deny.json -w "%{http_code}" --max-time 20 https://postman-echo.com/status/200; cat /tmp/deny.json' || true)
echo "$code" | grep -q '^403' && ok "403 for a denied path" || bad "expected 403, got: $(echo "$code" | head -c 200)"
echo "$code" | grep -q 'deny https://postman-echo.com/status/\*\*' && ok "the rule is named in the body" || bad "rule missing from body"

echo "== host no rule names: dropped at SNI time"
if vmexec "$id" 'curl -s --max-time 10 https://example.com/ >/dev/null'; then bad "example.com was reachable"; else ok "example.com refused"; fi

echo "== WebSocket upgrade through the tunnel"
# A WebSocket client speaks HTTP/1.1 (h2 has no Upgrade); curl must be told.
ws=$(vmexec "$id" 'curl -si --http1.1 --max-time 15 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" https://echo.websocket.org/ | head -1' || true)
echo "$ws" | grep -q ' 101 ' && ok "101 Switching Protocols" || bad "no 101: $ws"

echo "== policy change: new connections see it"
api -X PATCH -H 'content-type: application/json' -d '{"allow":["echo.websocket.org"]}' "$ISO_SERVER/vms/$id/policy" -o /dev/null
gen=$(api "$ISO_SERVER/vms/$id" | py "print(d['policy_gen'])")
[ "$gen" = 2 ] && ok "generation bumped to 2" || bad "generation is $gen"
if vmexec "$id" 'curl -s --max-time 10 https://postman-echo.com/get >/dev/null'; then bad "postman-echo.com still reachable after the change"; else ok "postman-echo.com refused after the change"; fi

echo "== a second VM lands on the other host"
id2=$("$ISOCTL" vm create --template "$TEMPLATE" --egress deny --quiet)
host2=$(api "$ISO_SERVER/vms/$id2" | py "print(d['host'])")
[ "$host2" != "$host" ] && ok "second VM on $host2" || bad "both VMs on $host"
api "$ISO_SERVER/stats" | py "print('  stats:', {k: d[k] for k in ('hosts_healthy','slots_used','slots_total','vms')})"

echo "== destroy"
"$ISOCTL" vm rm "$id"; "$ISOCTL" vm rm "$id2"
left=$(api "$ISO_SERVER/vms" | py "print(len(d))")
[ "$left" = 0 ] && ok "no VMs left" || bad "$left VMs left"

echo; echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
