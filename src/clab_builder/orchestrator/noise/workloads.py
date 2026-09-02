"""Local-only benign workload clients for noise experiments.

The generated client uses only Python's standard library and receives an
allow-listed JSON target set from the assembler. It never discovers hosts,
scans a subnet, follows redirects outside the set, or contacts the public
network.
"""

from __future__ import annotations

import json
import ipaddress
import shlex
from typing import Any, Mapping

from clab_builder.shared.models.artifact_contracts import (
    NoiseActivityConfigV1,
    normalize_noise_activity_config,
)


NOISE_ACTIVITY_VERSION = "activity-v3"


def workload_command(
    targets: list[dict[str, Any]],
    *,
    allowed_subnets: list[str],
    expected_source_ip: str,
    seed: int,
    active: bool | None = None,
    activity_config: NoiseActivityConfigV1 | Mapping[str, Any] | None = None,
) -> str:
    """Return the command for one isolated benign workload client."""
    requested_mode = None if active is None else ("normal" if active else "off")
    config = normalize_noise_activity_config(
        activity_config,
        mode=requested_mode,
        seed=seed,
    )
    if config.mode != "normal":
        return "sleep infinity"

    networks = [ipaddress.ip_network(value, strict=False) for value in allowed_subnets]
    if not networks:
        raise ValueError("active noise workload requires at least one allowed subnet")
    if not targets:
        raise ValueError("active noise workload requires at least one target")
    source_address = ipaddress.ip_address(expected_source_ip)
    if not any(source_address in network for network in networks):
        raise ValueError(
            f"noise client source address {source_address} is outside the allowed Range subnets"
        )
    for target in targets:
        address = ipaddress.ip_address(str(target.get("ip", "")))
        if not any(address in network for network in networks):
            raise ValueError(f"noise target {address} is outside the allowed Range subnets")
        port = int(target.get("port", 0))
        if not 1 <= port <= 65535:
            raise ValueError(f"noise target port is invalid: {port}")

    target_json = json.dumps(targets, sort_keys=True, separators=(",", ":"))
    subnet_json = json.dumps(allowed_subnets, sort_keys=True, separators=(",", ":"))
    config_json = json.dumps(
        config.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    code = r'''
import fcntl,ipaddress,json,random,socket,struct,time
targets=json.loads(__import__("os").environ["NOISE_TARGETS"])
allowed=[ipaddress.ip_network(value,strict=False) for value in json.loads(__import__("os").environ["NOISE_ALLOWED_SUBNETS"])]
expected_source_ip=__import__("os").environ["NOISE_EXPECTED_SOURCE_IP"]
rng=random.Random(int(__import__("os").environ.get("NOISE_SEED","0")))
activity=json.loads(__import__("os").environ["NOISE_ACTIVITY_CONFIG"])
interval_min=float(activity["interval_min_seconds"])
interval_max=float(activity["interval_max_seconds"])
duration=float(activity["duration_seconds"])
require_data_plane=bool(activity["require_data_plane_ready"])
operation_mix=activity["operation_mix"]

for target in targets:
    address=ipaddress.ip_address(str(target.get("ip","")))
    if not any(address in network for network in allowed):
        raise SystemExit("noise target outside allowed Range subnets: "+str(address))

def emit(t,operation,ok=True):
    print(json.dumps({"event":"business_request","operation":operation,
                      "ip":t.get("ip",""),"port":int(t.get("port",0)),
                      "ok":bool(ok),"emitted_at":time.time()},
                     separators=(",",":")),flush=True)

def emit_status(status):
    print(json.dumps({"event":"noise_client_status","status":status,
                      "expected_source_ip":expected_source_ip,
                      "emitted_at":time.time()},separators=(",",":")),flush=True)

def interface_ipv4(interface):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        request=struct.pack("256s",interface.encode()[:15])
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(),0x8915,request)[20:24])
    except OSError:
        return ""
    finally:
        sock.close()

# Containerlab creates the link before Ansible assigns the data-plane address.
# Wait for that address so startup never emits management-network timeouts as
# fake business-request failures.
wait_cycles=0
while require_data_plane and interface_ipv4("eth1") != expected_source_ip:
    if wait_cycles % 30 == 0:
        emit_status("waiting_for_data_plane")
    wait_cycles+=1
    time.sleep(1)
emit_status("data_plane_ready")

def require_operation(kind, operation):
    if operation not in operation_mix.get(kind, []):
        raise ValueError("operation is disabled by NoiseActivityConfigV1: "+operation)

def http_once(t):
    require_operation("http", "http_get")
    host,port=t["ip"],int(t["port"])
    family=t.get("family","")
    if family in ("elasticsearch","elasticsearch-http"):
        paths=["/","/_cluster/health","/_cat/indices"]
    elif family in ("solr","solr-http"):
        paths=["/solr/","/solr/select?q=*%3A*&rows=0"]
    else:
        paths=["/","/health","/robots.txt"]
    path=rng.choice(paths)
    with socket.create_connection((host,port),timeout=3) as s:
        request=("GET "+path+" HTTP/1.1\r\nHost: "+host+
                 "\r\nUser-Agent: CVELab-BusinessClient/1\r\nConnection: close\r\n\r\n").encode()
        s.sendall(request)
        response=s.recv(4096)
    if not response.startswith(b"HTTP/"):
        raise ValueError("invalid HTTP response")
    emit(t,"http_get",True)

def redis_once(t):
    require_operation("redis", "redis_ping_set_get")
    with socket.create_connection((t["ip"],int(t["port"])),timeout=3) as s:
        key=("cvelab:noise:"+str(t.get("zone","default"))).encode()
        def cmd(*parts):
            payload=b"*"+str(len(parts)).encode()+b"\r\n"
            for part in parts:
                value=part if isinstance(part,bytes) else str(part).encode()
                payload+=b"$"+str(len(value)).encode()+b"\r\n"+value+b"\r\n"
            s.sendall(payload)
            return s.recv(512)
        if not cmd(b"PING").startswith(b"+PONG"):
            raise ValueError("invalid Redis PING response")
        if not cmd(b"SET",key,b"ok").startswith(b"+OK"):
            raise ValueError("invalid Redis SET response")
        if b"ok" not in cmd(b"GET",key):
            raise ValueError("invalid Redis GET response")
    emit(t,"redis_ping_set_get",True)

def postgres_handshake(t):
    require_operation("postgres", "postgres_startup")
    # Normal startup/SSL negotiation without credentials or target mutation.
    with socket.create_connection((t["ip"],int(t["port"])),timeout=3) as s:
        s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        response=s.recv(64)
    if response not in (b"S",b"N"):
        raise ValueError("invalid PostgreSQL SSL response")
    emit(t,"postgres_startup",True)

def tcp_health(t):
    require_operation("tcp", "tcp_connect")
    s=socket.create_connection((t["ip"],int(t["port"])),timeout=3)
    s.close()
    emit(t,"tcp_connect",True)

started_at=time.monotonic()
while duration == 0 or time.monotonic()-started_at < duration:
    for target in targets:
        try:
            family=str(target.get("family","")).lower()
            if family in (
                "http-web",
                "elasticsearch",
                "elasticsearch-http",
                "solr",
                "solr-http",
            ) or target.get("protocol") in ("http", "https"):
                http_once(target)
            elif family in ("redis","redis-http") or int(target["port"])==6379:
                redis_once(target)
            elif family in ("postgresql","postgres") or int(target["port"])==5432:
                postgres_handshake(target)
            else:
                tcp_health(target)
        except (OSError,ValueError,TimeoutError) as exc:
            emit(target,"request_failed:"+type(exc).__name__,False)
    remaining=duration-(time.monotonic()-started_at) if duration else 0
    if duration and remaining <= 0:
        break
    delay=rng.uniform(interval_min,interval_max)
    time.sleep(min(delay,remaining) if duration else delay)
if duration:
    emit_status("duration_elapsed")
'''
    env = {
        "NOISE_TARGETS": target_json,
        "NOISE_ALLOWED_SUBNETS": subnet_json,
        "NOISE_EXPECTED_SOURCE_IP": expected_source_ip,
        "NOISE_SEED": str(seed),
        "NOISE_ACTIVITY_CONFIG": config_json,
    }
    env_assignments = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in env.items()
    )
    return f"sh -c {shlex.quote(env_assignments + ' python -c ' + shlex.quote(code))}"
