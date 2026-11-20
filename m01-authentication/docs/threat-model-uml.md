@startuml m01-threat-model
!theme plain
skinparam backgroundColor white
skinparam defaultFontSize 12
skinparam rectangle {
  BackgroundColor white
  BorderColor black
  ArrowColor black
}

' ===================================================================
' TITLE
' ===================================================================
title "Threat Model — m01-authentication\nSpring Vuln Range · Checklist Section 1\n\nScope: /vuln1/** (vulnerable) and /safe1/** (reference)\nPort: 8081 · Loopback only · Educational range"

' ===================================================================
' ACTORS
' ===================================================================
actor "Attacker\n(Agentic / LLM-driven)" as attacker
actor "Authenticated User\n(alice, bob, admin)" as user
actor "Browser\n(JavaScript / Cookies)" as browser

' ===================================================================
' TRUST BOUNDARIES
' ===================================================================
rectangle "TRUST BOUNDARY: Untrusted Network" {
  rectangle "HTTP Client\ncurl / browser / script" as client <<Actor>>
}

rectangle "TRUST BOUNDARY: Application (m01-authentication)" as app {
  rectangle "VulnerableAuthnController\n/vuln1/**" as vuln_ctrl
  rectangle "SafeAuthnController\n/safe1/**" as safe_ctrl
  rectangle "InsecureTokenService\nJWT / HMAC / remember-me" as token_svc
  rectangle "SafeTokenService\nJWT / HMAC / SecureRandom" as safe_token_svc
  rectangle "ConcurrentHashMap\nuser store (md5 hashes)" as user_store
  rectangle "ConcurrentHashMap\nuser store (bcrypt hashes)" as safe_user_store
  rectangle "SecurityConfig\npermitAll / csrf.disable" as sec_cfg
}

rectangle "TRUST BOUNDARY: External" {
  rectangle "application.yml\nvulnrange.m01.jwt-weak-secret" as config
  rectangle "Static Key\n\"remember-me-static-key\"" as static_key
}

' ===================================================================
' DATA FLOWS
' ===================================================================
client --> vuln_ctrl : POST /login\nPOST /register\nPOST /token/issue\nGET /session-id\nGET /admin/espd-summary\nGET /debug/users\nGET /token/predict
client --> safe_ctrl : POST /login\nPOST /register\nPOST /token/issue
client --> vuln_ctrl : GET /password-reset
client --> vuln_ctrl : POST /remember-me/login\nGET /remember-me/{username}

vuln_ctrl --> token_svc : issueHs256()\nverify()\nrememberMe()\
token_svc --> config : @Value jwt-weak-secret
token_svc --> static_key : HMAC key

safe_ctrl --> safe_token_svc : issue()\nverify()
safe_token_svc --> safe_user_store : passwordEncoder.matches()

vuln_ctrl --> user_store : users.get()\nusers.put()
safe_ctrl --> safe_user_store : users.get()\npasswordEncoder.encode()

vuln_ctrl --> sec_cfg : anyRequest().permitAll()

' ===================================================================
' THREATS — DREAD / STRIDE
' ===================================================================
rectangle "THREAT: Unsalted MD5 Password Hashes" as t1 {
  [CWE-328: Use of Weak Hash] as t1a
  [CWE-757: Selection of Hash Algorithm] as t1b
  [CVSS 9.8 — Credential Theft] as t1c
}
t1a -[hidden]down-> t1b
t1b -[hidden]down-> t1c

rectangle "THREAT: User Enumeration via Distinct Messages" as t2 {
  [CWE-204: Observable Response Discrepancy] as t2a
  [CWE-203: Observable Discrepancy] as t2b
}
t2a -[hidden]down-> t2b

rectangle "THREAT: Session Fixation" as t3 {
  [CWE-384: Session Fixation] as t3a
  [Pre-auth session ID reused after login] as t3b
}
t3a -[hidden]down-> t3b

rectangle "THREAT: JWT alg:none Acceptance" as t4 {
  [CWE-347: Improper Verification of Cryptographic Signature] as t4a
  [Attacker crafts unsigned token] as t4b
}
t4a -[hidden]down-> t4b

rectangle "THREAT: Weak JWT Secret (Dictionary)" as t5 {
  [CWE-521: Weak Password Requirements] as t5a
  [HMAC-SHA256 with \"s3cr3t\"] as t5b
  [Brute-force: 40 attempts/sec] as t5c
}
t5a -[hidden]down-> t5b
t5b -[hidden]down-> t5c

rectangle "THREAT: No JWT Expiry / iss / aud Enforcement" as t6 {
  [CWE-613: Insufficient Session Expiration] as t6a
  [Tokens valid forever] as t6b
}
t6a -[hidden]down-> t6b

rectangle "THREAT: Timing Side Channel (String.equals)" as t7 {
  [CWE-208: Observable Timing Discrepancy] as t7a
  [HMAC compared with .equals not isEqual] as t7b
}
t7a -[hidden]down-> t7b

rectangle "THREAT: Predictable Reset Codes" as t8 {
  [CWE-330: Use of Insufficiently Random Values] as t8a
  [java.util.Random seeded by System.currentTimeMillis()/60000] as t8b
  [Code computable from time seed] as t8c
}
t8a -[hidden]down-> t8b
t8b -[hidden]down-> t8c

rectangle "THREAT: Offline Remember-Me Token Minting" as t9 {
  [CWE-798: Use of Hardcoded Credentials] as t9a
  [\"remember-me-static-key\" in source] as t9b
  [Anyone with jar can forge cookies] as t9c
}
t9a -[hidden]down-> t9b
t9b -[hidden]down-> t9c

rectangle "THREAT: Cookie Flags Missing" as t10 {
  [CWE-1004: Sensitive Cookie Without 'Secure' Attribute] as t10a
  [HttpOnly=false, Secure=false] as t10b
  [Readable by JavaScript / sent over HTTP] as t10c
}
t10a -[hidden]down-> t10b
t10b -[hidden]down-> t10c

rectangle "THREAT: Unauthenticated User Hash Dump" as t11 {
  [CWE-200: Exposure of Sensitive Information] as t11a
  [GET /debug/users returns all MD5 hashes] as t11b
}
t11a -[hidden]down-> t11b

' ===================================================================
' MAPPING: THREAT -> VULNERABLE ENDPOINT
' ===================================================================
t1 ..> vuln_ctrl : register()\nlogin()\ndebug/users()
t2 ..> vuln_ctrl : login()\npasswordReset()
t3 ..> vuln_ctrl : login()\nsessionId()
t4 ..> token_svc : verify()
t5 ..> token_svc : issueHs256()\nverify()
t6 ..> token_svc : verify()
t7 ..> token_svc : verify()\nrememberMeMatches()
t8 ..> vuln_ctrl : passwordReset()\ntoken/predict()
t9 ..> token_svc : rememberMe()\nrememberMeMatches()
t10 ..> vuln_ctrl : setCookieDemo()
t11 ..> vuln_ctrl : debug/users()

' ===================================================================
' SAFE CONTROLS
' ===================================================================
rectangle "SAFE CONTROLS" as safe {
  [BCrypt cost=12, per-user salt] as sc1
  [Throttling: 5 attempts / 1 min] as sc2
  [Session rotation on login] as sc3
  [Constant alg=HS256, never from token] as sc4
  [256-bit key from SafeTokenKeyProvider] as sc5
  [exp/iss/aud/nbf enforced] as sc6
  [MessageDigest.isEqual() for HMAC] as sc7
  [SecureRandom (JEP 294) for codes] as sc8
  [SHA-256 digest for reset codes] as sc9
  [Audit log with masked identities] as sc10
  [Generic \"invalid credentials\" message] as sc11
  [Password policy: min 12 chars] as sc12
  [Decoy hash comparison (timing blind)] as sc13
}

sc1 ..> safe_user_store
sc2 ..> safe_ctrl
sc3 ..> safe_ctrl
sc4 ..> safe_token_svc
sc5 ..> safe_token_svc
sc6 ..> safe_token_svc
sc7 ..> safe_token_svc
sc8 ..> safe_token_svc
sc9 ..> safe_ctrl
sc10 ..> safe_ctrl
sc11 ..> safe_ctrl
sc12 ..> safe_ctrl
sc13 ..> safe_ctrl

' ===================================================================
' LEGEND
' ===================================================================
rectangle "Legend" as legend {
  [<<Actor>>] as a1
  [<<Data Store>>] as d1
  [Threat box] as tb
  -- [Data Flow]
  ..> [Threat Dependency]
}
legend : a1 : d1 : tb

@enduml
