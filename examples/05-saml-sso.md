# SAML 2.0 Single Sign-On (SSO)

This example demonstrates SAML 2.0 Identity Provider (IdP) functionality for **enterprise Single Sign-On**. SAML is widely used in enterprise environments for SSO between organizations.

## Use Case

Perfect for:
- Enterprise B2B integrations
- Corporate SSO solutions
- Legacy enterprise applications
- Organizations requiring SAML compliance
- Integration with services like Salesforce, Slack, AWS, etc.

## SAML vs OAuth2/OIDC

| Feature | SAML 2.0 | OAuth2/OIDC |
|---------|----------|-------------|
| Format | XML | JSON |
| Primary Use | Enterprise SSO | Modern web/mobile apps |
| User Experience | Browser redirects | Browser redirects |
| Token Format | XML assertions | JWT tokens |
| Complexity | High | Medium |
| Enterprise Adoption | Very high | Growing |

## Prerequisites

1. API is running on `http://localhost:3000`
2. SAML is configured for your tenant
3. You have X.509 certificates for signing
4. You have a Service Provider (SP) to integrate with

## SAML Flow Overview

```
┌──────────┐                                           ┌──────────────┐
│          │                                           │              │
│ Service  │                                           │   Identity   │
│ Provider │                                           │   Provider   │
│  (SP)    │                                           │   (IdP)      │
│          │                                           │   (This API) │
└────┬─────┘                                           └──────┬───────┘
     │                                                         │
     │  1. User accesses SP resource                          │
     ├────────►                                                │
     │                                                         │
     │  2. SP generates SAML AuthnRequest                     │
     ├─────────────────────────────────────────────────────────►
     │                                                         │
     │  3. IdP authenticates user (if needed)                 │
     │                                                         │
     │  4. IdP generates signed SAML Response + Assertion     │
     ◄─────────────────────────────────────────────────────────┤
     │                                                         │
     │  5. SP validates signature and grants access           │
     │                                                         │
```

## Step-by-Step Example

### Step 1: Get SAML Metadata

Retrieve the IdP metadata to configure your Service Provider:

```bash
curl -X GET http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata
```

**Expected Response (XML):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>MIICertificateDataHere==</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="http://localhost:3000/api/v1/tenant/test-tenant/saml/sso"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="http://localhost:3000/api/v1/tenant/test-tenant/saml/sso"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="http://localhost:3000/api/v1/tenant/test-tenant/saml/slo"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>
```

**Key Information:**
- `entityID` - Unique identifier for this IdP
- `SingleSignOnService` - SSO endpoint URL
- `SingleLogoutService` - SLO endpoint URL
- `X509Certificate` - Public certificate for signature verification

**Save this metadata** and import it into your Service Provider configuration.

### Step 2: Configure Service Provider

Most Service Providers can import IdP metadata automatically. For example:

#### Salesforce Configuration

1. Go to **Setup → Identity → Single Sign-On Settings**
2. Click **New from Metadata File**
3. Upload the metadata XML from Step 1
4. Configure attribute mappings

#### Generic SP Configuration

If manual configuration is needed:

- **SSO URL**: `http://localhost:3000/api/v1/tenant/test-tenant/saml/sso`
- **Entity ID**: `http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata`
- **Certificate**: Extract from metadata `<X509Certificate>` element
- **Name ID Format**: `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- **Binding**: HTTP-POST or HTTP-Redirect

### Step 3: Test SSO (HTTP-POST Binding)

Initiate SSO using HTTP-POST binding:

```bash
# Generate SAML AuthnRequest (simplified example)
SAML_REQUEST='<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_request_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z"
                    Destination="http://localhost:3000/api/v1/tenant/test-tenant/saml/sso"
                    AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>'

# Base64 encode
ENCODED=$(echo "$SAML_REQUEST" | base64 -w 0)

# Send to SSO endpoint
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/saml/sso \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLRequest=${ENCODED}&RelayState=optional-relay-state"
```

**Expected Response (HTML with auto-submit form):**
```html
<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="https://sp.example.com/saml/acs">
        <input type="hidden" name="SAMLResponse" value="PHNhbWxwOlJlc3Bvb..." />
        <noscript>
            <p>JavaScript is disabled. Click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>
```

This HTML will automatically post the SAML response back to your SP.

### Step 4: Test SSO (HTTP-Redirect Binding)

Initiate SSO using HTTP-Redirect binding (simpler for testing):

```bash
# Generate SAML AuthnRequest
SAML_REQUEST='<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_request_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>'

# Deflate compress + base64 encode
ENCODED=$(echo "$SAML_REQUEST" | gzip -c | base64 -w 0 | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g')

# Open in browser
open "http://localhost:3000/api/v1/tenant/test-tenant/saml/sso?SAMLRequest=${ENCODED}&RelayState=test-state"
```

**What happens:**
1. Browser opens the SSO URL
2. User authenticates (if not already logged in)
3. IdP generates SAML response
4. Browser is redirected back to SP with SAML response
5. SP validates and grants access

### Step 5: Decode SAML Response

Extract and decode the SAML response:

```bash
# Extract SAMLResponse from form
SAML_RESPONSE="PHNhbWxwOlJlc3Bvb..."

# Base64 decode
echo "$SAML_RESPONSE" | base64 -d
```

**SAML Response Structure:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response_id"
                Version="2.0"
                IssueInstant="2024-01-01T00:00:00Z"
                Destination="https://sp.example.com/saml/acs"
                InResponseTo="_request_id">
    <saml:Issuer>http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z">
        <saml:Issuer>http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="2024-01-01T00:05:00Z"
                                              Recipient="https://sp.example.com/saml/acs"
                                              InResponseTo="_request_id"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T00:05:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://sp.example.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionIndex="_session_id">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>user@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="uid">
                <saml:AttributeValue>user@example.com</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
```

**Key Elements:**
- `NameID` - User identifier (email address)
- `Conditions` - Validity time window
- `Audience` - Expected recipient (SP entity ID)
- `AttributeStatement` - User attributes
- `Signature` - XML digital signature (added by IdP)

### Step 6: Single Logout (SLO)

Initiate logout to terminate the SAML session:

```bash
# Generate SAML LogoutRequest
LOGOUT_REQUEST='<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     ID="_logout_request_id"
                     Version="2.0"
                     IssueInstant="2024-01-01T01:00:00Z">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                 Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    <samlp:SessionIndex>_session_id</samlp:SessionIndex>
</samlp:LogoutRequest>'

# Base64 encode
ENCODED=$(echo "$LOGOUT_REQUEST" | base64 -w 0)

# Send to SLO endpoint
curl -X POST http://localhost:3000/api/v1/tenant/test-tenant/saml/slo \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLRequest=${ENCODED}"
```

**Expected Response:**
```xml
<?xml version="1.0"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      ID="_response_id"
                      Version="2.0"
                      IssueInstant="2024-01-01T01:00:00Z">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>
```

## Testing with SAML Tools

### Using saml.tools (Online Validator)

1. Go to https://www.samltool.com/decode.php
2. Paste base64-encoded SAML response
3. View decoded XML and validate

### Using OneLogin SAML Tester

1. Go to https://www.samltool.com/sp_metadata.php
2. Generate test SP metadata
3. Configure with your IdP metadata
4. Test SSO flow

### Using SAML Tracer (Browser Extension)

```bash
# Install SAML Tracer for Firefox/Chrome
# Extension shows all SAML requests/responses in real-time
```

## Common Service Provider Integrations

### AWS IAM SAML

```bash
# 1. Get metadata
curl -o idp-metadata.xml http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata

# 2. Create IAM SAML provider
aws iam create-saml-provider \
  --name MyIdP \
  --saml-metadata-document file://idp-metadata.xml

# 3. Create IAM role with SAML trust policy
```

### Salesforce SAML

```bash
# 1. Salesforce Setup → Single Sign-On Settings
# 2. New from Metadata File → Upload metadata
# 3. Configure attribute mappings:
#    - User ID: email
#    - Email: email
#    - First Name: given_name
#    - Last Name: family_name
```

### Google Workspace

```bash
# 1. Admin Console → Security → Authentication → SSO with third-party IdP
# 2. Upload metadata file
# 3. Configure sign-in URL and certificate
```

### Slack

```bash
# Slack Workspace Settings → Authentication → SAML
# - SAML 2.0 Endpoint: http://localhost:3000/api/v1/tenant/test-tenant/saml/sso
# - Identity Provider Issuer: http://localhost:3000/api/v1/tenant/test-tenant/saml/metadata
# - Public Certificate: [from metadata]
```

## Complete SAML Test Script

```bash
#!/bin/bash

TENANT_ID="test-tenant"
BASE_URL="http://localhost:3000"
SP_ENTITY_ID="https://sp.example.com"
SP_ACS_URL="https://sp.example.com/saml/acs"

echo "==> Step 1: Retrieve IdP Metadata"
echo ""
curl -s "${BASE_URL}/api/v1/tenant/${TENANT_ID}/saml/metadata" > idp-metadata.xml
cat idp-metadata.xml | xmllint --format -
echo ""

echo "==> Step 2: Generate SAML AuthnRequest"
SAML_REQUEST=$(cat <<EOF
<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_$(uuidgen)"
                    Version="2.0"
                    IssueInstant="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                    Destination="${BASE_URL}/api/v1/tenant/${TENANT_ID}/saml/sso"
                    AssertionConsumerServiceURL="${SP_ACS_URL}">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${SP_ENTITY_ID}</saml:Issuer>
</samlp:AuthnRequest>
EOF
)

echo "$SAML_REQUEST" | xmllint --format -
echo ""

echo "==> Step 3: Encode SAML Request"
ENCODED=$(echo "$SAML_REQUEST" | base64 -w 0)
echo "Encoded: ${ENCODED:0:50}..."
echo ""

echo "==> Step 4: Send SAML Request (HTTP-POST)"
RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/tenant/${TENANT_ID}/saml/sso" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "SAMLRequest=${ENCODED}&RelayState=test-state")

echo "$RESPONSE" > saml-response.html
echo "Response saved to saml-response.html"
echo ""

echo "==> Step 5: Extract and decode SAML Response"
SAML_RESPONSE=$(echo "$RESPONSE" | grep -oP 'value="\K[^"]+' | head -1)
echo "$SAML_RESPONSE" | base64 -d | xmllint --format - > decoded-saml-response.xml
echo "Decoded response saved to decoded-saml-response.xml"
cat decoded-saml-response.xml
echo ""

echo "==> Done! Review the SAML response for user attributes"
```

## Security Considerations

### 1. Signature Validation

Service Providers **must validate** the XML signature:

```bash
# SP should verify:
# 1. Signature is present
# 2. Signature is valid using IdP's public certificate
# 3. Reference digest matches
# 4. Certificate is trusted
```

### 2. Replay Attack Prevention

Check `IssueInstant` and `NotOnOrAfter`:

```xml
<saml:Conditions NotBefore="2024-01-01T00:00:00Z"
                 NotOnOrAfter="2024-01-01T00:05:00Z">
```

Assertions should only be valid for a short time (5 minutes).

### 3. Audience Restriction

Verify the audience matches your SP:

```xml
<saml:AudienceRestriction>
    <saml:Audience>https://your-sp.example.com</saml:Audience>
</saml:AudienceRestriction>
```

### 4. InResponseTo Validation

Link responses to requests:

```xml
<!-- Request -->
<samlp:AuthnRequest ID="_request_123" .../>

<!-- Response must reference it -->
<samlp:Response InResponseTo="_request_123" .../>
```

## Troubleshooting

### Invalid Signature

**Error:** "SAML signature validation failed"

**Solution:**
- Ensure SP has correct certificate from IdP metadata
- Verify certificate hasn't expired
- Check that response hasn't been modified

### Time Sync Issues

**Error:** "SAML assertion expired"

**Solution:**
```bash
# Check time on both IdP and SP
date -u

# Sync NTP
sudo ntpdate pool.ntp.org
```

### Audience Mismatch

**Error:** "Audience restriction failed"

**Solution:**
- Verify SP entity ID matches `<saml:Audience>` in response
- Check SP configuration

## Next Steps

- Review [OAuth2 flows](01-oauth2-client-credentials.md) for modern alternatives
- Explore [OpenID Connect](03-openid-connect.md) for simpler SSO
- Try [API Key Management](04-api-key-management.md) for automated access
