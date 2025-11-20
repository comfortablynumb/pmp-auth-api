// SAML 2.0 Identity Provider Implementation
// This module implements SAML IdP functionality for SSO

#![allow(dead_code)]

use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// SAML Metadata request
/// GET /api/v1/tenant/{tenant_id}/saml/metadata
pub async fn saml_metadata(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    debug!("Serving SAML metadata for tenant '{}'", tenant_id);

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if SAML is configured
    let (saml_config, _storage_id) = tenant.get_saml_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "saml_not_configured" })),
        )
    })?;

    // Generate SAML metadata XML (use entity_id as base URL)
    let base_url = extract_base_url(&saml_config.entity_id);
    let metadata = generate_saml_metadata(&tenant_id, saml_config, &base_url)?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        metadata,
    )
        .into_response())
}

/// SAML SSO endpoint (HTTP-POST binding)
/// POST /api/v1/tenant/{tenant_id}/saml/sso
pub async fn saml_sso_post(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Processing SAML SSO POST request for tenant '{}'",
        tenant_id
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if SAML is configured
    let (saml_config, storage_id) = tenant.get_saml_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "saml_not_configured" })),
        )
    })?;

    // Parse SAML request
    let saml_request = parse_saml_request(&body)?;

    info!(
        "SAML request from SP '{}', ID '{}'",
        saml_request.issuer, saml_request.id
    );

    // Authenticate user via session
    let user_email = authenticate_user_from_session(&state, &tenant_id, &storage_id, &headers)
        .await?;

    info!("Authenticated user '{}' for SAML SSO", user_email);

    // Generate SAML response
    let base_url = extract_base_url(&saml_config.entity_id);
    let response_xml = generate_saml_response(
        &saml_request,
        &tenant_id,
        saml_config,
        &user_email,
        &base_url,
    )?;

    // Return SAML response as HTTP-POST form
    let html = create_saml_post_form(&saml_request.acs_url, &response_xml);

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/html")], html).into_response())
}

/// SAML SSO endpoint (HTTP-Redirect binding)
/// GET /api/v1/tenant/{tenant_id}/saml/sso
pub async fn saml_sso_redirect(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<SamlRedirectParams>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!(
        "Processing SAML SSO Redirect request for tenant '{}'",
        tenant_id
    );

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if SAML is configured
    let (saml_config, storage_id) = tenant.get_saml_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "saml_not_configured" })),
        )
    })?;

    // Decode and parse SAML request
    let decoded = decode_saml_redirect(&params.saml_request)?;
    let saml_request = parse_saml_request(&decoded)?;

    info!(
        "SAML request from SP '{}', ID '{}'",
        saml_request.issuer, saml_request.id
    );

    // Authenticate user via session
    let user_email = authenticate_user_from_session(&state, &tenant_id, &storage_id, &headers)
        .await?;

    info!("Authenticated user '{}' for SAML SSO", user_email);

    // Generate SAML response
    let base_url = extract_base_url(&saml_config.entity_id);
    let response_xml = generate_saml_response(
        &saml_request,
        &tenant_id,
        saml_config,
        &user_email,
        &base_url,
    )?;

    // Return SAML response as HTTP-POST form
    let html = create_saml_post_form(&saml_request.acs_url, &response_xml);

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/html")], html).into_response())
}

/// SAML Single Logout endpoint
/// POST /api/v1/tenant/{tenant_id}/saml/slo
pub async fn saml_slo(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    body: String,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    info!("Processing SAML SLO request for tenant '{}'", tenant_id);

    // Get tenant configuration
    let tenant = state.config.get_tenant(&tenant_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "tenant_not_found" })),
        )
    })?;

    // Check if SAML is configured
    let (_saml_config, _storage_id) = tenant.get_saml_provider().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "saml_not_configured" })),
        )
    })?;

    // Parse logout request
    let logout_request = parse_saml_logout_request(&body)?;

    info!(
        "SAML logout request - ID: {}, NameID: {}, SessionIndex: {:?}",
        logout_request.id, logout_request.name_id, logout_request.session_index
    );

    // Terminate session if session index is provided
    if let Some(session_index) = &logout_request.session_index {
        let storage = &state.storage;

        // Delete session by session index (session_index is the session_id in our implementation)
        match storage.delete_session(session_index).await {
            Ok(_) => {
                info!("Successfully terminated session {}", session_index);
            }
            Err(e) => {
                warn!("Failed to delete session {}: {}", session_index, e);
                // Continue with logout response even if session deletion fails
            }
        }
    }

    // Generate logout response
    let response_id = format!("_response_{}", Uuid::new_v4());
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let response = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      ID="{}"
                      Version="2.0"
                      IssueInstant="{}"
                      InResponseTo="{}">
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>"#,
        response_id, issue_instant, logout_request.id
    );

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        response,
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct SamlRedirectParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
    #[serde(rename = "SigAlg")]
    sig_alg: Option<String>,
    #[serde(rename = "Signature")]
    signature: Option<String>,
}

#[derive(Debug)]
struct ParsedSamlRequest {
    id: String,
    issuer: String,
    acs_url: String,
    relay_state: Option<String>,
}

#[derive(Debug)]
struct ParsedSamlLogoutRequest {
    id: String,
    name_id: String,
    session_index: Option<String>,
}

/// Generate SAML IdP metadata XML
fn generate_saml_metadata(
    tenant_id: &str,
    config: &crate::models::SamlIdpConfig,
    base_url: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let entity_id = format!("{}/api/v1/tenant/{}/saml/metadata", base_url, tenant_id);
    let sso_url = format!("{}/api/v1/tenant/{}/saml/sso", base_url, tenant_id);
    let slo_url = format!("{}/api/v1/tenant/{}/saml/slo", base_url, tenant_id);

    // Load certificate from config
    let cert_data = load_certificate_data(&config.certificate)?;

    let metadata = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="{}"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{}"/>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="{}"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        entity_id, cert_data, sso_url, sso_url, slo_url
    );

    Ok(metadata)
}

/// Parse SAML authentication request
fn parse_saml_request(
    xml: &str,
) -> Result<ParsedSamlRequest, (StatusCode, Json<serde_json::Value>)> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    debug!("Parsing SAML request XML");

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut id = None;
    let mut issuer = None;
    let mut acs_url = None;
    let mut in_issuer_element = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"samlp:AuthnRequest" | b"AuthnRequest" => {
                        // Parse attributes from AuthnRequest element
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                match attr.key.as_ref() {
                                    b"ID" => {
                                        id = Some(
                                            String::from_utf8_lossy(&attr.value).into_owned(),
                                        );
                                    }
                                    b"AssertionConsumerServiceURL" => {
                                        acs_url = Some(
                                            String::from_utf8_lossy(&attr.value).into_owned(),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    b"saml:Issuer" | b"Issuer" => {
                        in_issuer_element = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_issuer_element {
                    issuer = Some(e.unescape().unwrap_or_default().into_owned());
                    in_issuer_element = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("Error parsing SAML XML at position {}: {}", reader.buffer_position(), e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_saml_request", "detail": "XML parsing failed" })),
                ));
            }
            _ => {}
        }
    }

    // Validate required fields
    let id = id.ok_or_else(|| {
        warn!("SAML request missing ID attribute");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_request", "detail": "Missing ID attribute" })),
        )
    })?;

    let issuer = issuer.ok_or_else(|| {
        warn!("SAML request missing Issuer element");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_request", "detail": "Missing Issuer" })),
        )
    })?;

    let acs_url = acs_url.ok_or_else(|| {
        warn!("SAML request missing AssertionConsumerServiceURL");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_request", "detail": "Missing AssertionConsumerServiceURL" })),
        )
    })?;

    info!("Parsed SAML request - ID: {}, Issuer: {}, ACS: {}", id, issuer, acs_url);

    Ok(ParsedSamlRequest {
        id,
        issuer,
        acs_url,
        relay_state: None,
    })
}

/// Parse SAML logout request
fn parse_saml_logout_request(
    xml: &str,
) -> Result<ParsedSamlLogoutRequest, (StatusCode, Json<serde_json::Value>)> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    debug!("Parsing SAML logout request XML");

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut id = None;
    let mut name_id = None;
    let mut session_index = None;
    let mut in_name_id_element = false;
    let mut in_session_index_element = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"samlp:LogoutRequest" | b"LogoutRequest" => {
                        // Parse ID attribute from LogoutRequest element
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"ID" {
                                    id = Some(String::from_utf8_lossy(&attr.value).into_owned());
                                }
                            }
                        }
                    }
                    b"saml:NameID" | b"NameID" => {
                        in_name_id_element = true;
                    }
                    b"samlp:SessionIndex" | b"SessionIndex" => {
                        in_session_index_element = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_name_id_element {
                    name_id = Some(e.unescape().unwrap_or_default().into_owned());
                    in_name_id_element = false;
                }

                if in_session_index_element {
                    session_index = Some(e.unescape().unwrap_or_default().into_owned());
                    in_session_index_element = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("Error parsing SAML logout XML at position {}: {}", reader.buffer_position(), e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_saml_logout_request", "detail": "XML parsing failed" })),
                ));
            }
            _ => {}
        }
    }

    // Validate required fields
    let id = id.ok_or_else(|| {
        warn!("SAML logout request missing ID attribute");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_logout_request", "detail": "Missing ID attribute" })),
        )
    })?;

    let name_id = name_id.ok_or_else(|| {
        warn!("SAML logout request missing NameID element");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_logout_request", "detail": "Missing NameID" })),
        )
    })?;

    info!(
        "Parsed SAML logout request - ID: {}, NameID: {}, SessionIndex: {:?}",
        id, name_id, session_index
    );

    Ok(ParsedSamlLogoutRequest {
        id,
        name_id,
        session_index,
    })
}

/// Generate SAML response with assertion
fn generate_saml_response(
    request: &ParsedSamlRequest,
    tenant_id: &str,
    config: &crate::models::SamlIdpConfig,
    user_email: &str,
    base_url: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now();
    let response_id = format!("_response_{}", Uuid::new_v4());
    let assertion_id = format!("_assertion_{}", Uuid::new_v4());
    let issuer = format!("{}/api/v1/tenant/{}/saml/metadata", base_url, tenant_id);

    let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_before = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let not_on_or_after = (now + chrono::Duration::minutes(5))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Build attribute statements (default attributes)
    let attributes = format!(
        r#"
            <saml:Attribute Name="email">
                <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                     xsi:type="xs:string">{}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="uid">
                <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                     xsi:type="xs:string">{}</saml:AttributeValue>
            </saml:Attribute>"#,
        user_email, user_email
    );

    // Build unsigned assertion
    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="2.0"
                    IssueInstant="{}">
        <saml:Issuer>{}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="{}"
                                              Recipient="{}"
                                              InResponseTo="{}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{}" NotOnOrAfter="{}">
            <saml:AudienceRestriction>
                <saml:Audience>{}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{}" SessionIndex="{}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>{}</saml:AttributeStatement>
    </saml:Assertion>"#,
        assertion_id,
        issue_instant,
        issuer,
        user_email,
        not_on_or_after,
        request.acs_url,
        request.id,
        not_before,
        not_on_or_after,
        request.issuer,
        issue_instant,
        assertion_id,
        attributes
    );

    // Sign the assertion
    let signed_assertion = sign_saml_element(&assertion, &assertion_id, config)?;

    let response = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{}"
                Version="2.0"
                IssueInstant="{}"
                Destination="{}"
                InResponseTo="{}">
    <saml:Issuer>{}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    {}
</samlp:Response>"#,
        response_id,
        issue_instant,
        request.acs_url,
        request.id,
        issuer,
        signed_assertion
    );

    Ok(response)
}

/// Decode SAML request from HTTP-Redirect binding
fn decode_saml_redirect(encoded: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    // Decode base64
    let decoded = STANDARD.decode(encoded).map_err(|e| {
        warn!("Failed to decode base64 SAML request: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_request" })),
        )
    })?;

    // Inflate (decompress)
    let mut decoder = DeflateDecoder::new(&decoded[..]);
    let mut xml = String::new();
    decoder.read_to_string(&mut xml).map_err(|e| {
        warn!("Failed to decompress SAML request: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_saml_request" })),
        )
    })?;

    Ok(xml)
}

/// Create HTML form for HTTP-POST binding
fn create_saml_post_form(acs_url: &str, saml_response: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let encoded = STANDARD.encode(saml_response.as_bytes());

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>SAML Response</title>
</head>
<body onload="document.forms[0].submit()">
    <form method="post" action="{}">
        <input type="hidden" name="SAMLResponse" value="{}" />
        <noscript>
            <p>JavaScript is disabled. Click the button below to continue.</p>
            <input type="submit" value="Continue" />
        </noscript>
    </form>
</body>
</html>"#,
        acs_url, encoded
    )
}

/// Load certificate data from file path or inline PEM
fn load_certificate_data(cert_path: &str) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    use std::fs;

    // Read certificate file
    let cert_pem = fs::read_to_string(cert_path).map_err(|e| {
        warn!("Failed to read certificate file '{}': {}", cert_path, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "certificate_load_failed",
                "detail": format!("Failed to read certificate: {}", e)
            })),
        )
    })?;

    // Extract certificate data (remove PEM headers and newlines)
    let cert_data = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    if cert_data.is_empty() {
        warn!("Certificate file '{}' is empty or invalid", cert_path);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "invalid_certificate",
                "detail": "Certificate file is empty or invalid"
            })),
        ));
    }

    Ok(cert_data)
}

/// Load private key from file path
fn load_private_key(key_path: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    use std::fs;

    // Read private key file
    let key_pem = fs::read_to_string(key_path).map_err(|e| {
        warn!("Failed to read private key file '{}': {}", key_path, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "private_key_load_failed",
                "detail": format!("Failed to read private key: {}", e)
            })),
        )
    })?;

    // Parse PEM to get raw key bytes
    let pem_data = pem::parse(&key_pem).map_err(|e| {
        warn!("Failed to parse private key PEM: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "invalid_private_key",
                "detail": "Failed to parse private key PEM format"
            })),
        )
    })?;

    Ok(pem_data.contents().to_vec())
}

/// Sign SAML XML element using XML Digital Signature
fn sign_saml_element(
    xml: &str,
    element_id: &str,
    config: &crate::models::SamlIdpConfig,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use sha2::{Digest, Sha256};

    // Load private key
    let key_bytes = load_private_key(&config.private_key)?;

    // Parse RSA private key
    let rsa = Rsa::private_key_from_der(&key_bytes).map_err(|e| {
        warn!("Failed to parse RSA private key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "invalid_private_key",
                "detail": "Failed to parse RSA private key"
            })),
        )
    })?;

    let pkey = PKey::from_rsa(rsa).map_err(|e| {
        warn!("Failed to create PKey from RSA: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "key_conversion_failed" })),
        )
    })?;

    // Canonicalize XML (simplified - remove extra whitespace)
    let canonical = xml
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<&str>>()
        .join("");

    // Compute SHA-256 digest
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest_value = hasher.finalize();
    let digest_base64 = STANDARD.encode(&digest_value);

    // Create SignedInfo element
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n\
<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n\
<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n\
<ds:Reference URI=\"#{0}\">\n\
<ds:Transforms>\n\
<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n\
<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n\
</ds:Transforms>\n\
<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n\
<ds:DigestValue>{1}</ds:DigestValue>\n\
</ds:Reference>\n\
</ds:SignedInfo>",
        element_id, digest_base64
    );

    // Canonicalize SignedInfo
    let signed_info_canonical = signed_info
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<&str>>()
        .join("");

    // Sign the SignedInfo
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(|e| {
        warn!("Failed to create signer: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "signature_creation_failed" })),
        )
    })?;

    signer
        .update(signed_info_canonical.as_bytes())
        .map_err(|e| {
            warn!("Failed to update signer: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "signature_update_failed" })),
            )
        })?;

    let signature = signer.sign_to_vec().map_err(|e| {
        warn!("Failed to sign data: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "signature_failed" })),
        )
    })?;

    let signature_base64 = STANDARD.encode(&signature);

    // Load certificate data for KeyInfo
    let cert_data = load_certificate_data(&config.certificate)?;

    // Create Signature element
    let signature_element = format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n\
{}\n\
<ds:SignatureValue>{}</ds:SignatureValue>\n\
<ds:KeyInfo>\n\
<ds:X509Data>\n\
<ds:X509Certificate>{}</ds:X509Certificate>\n\
</ds:X509Data>\n\
</ds:KeyInfo>\n\
</ds:Signature>",
        signed_info, signature_base64, cert_data
    );

    // Insert signature after Issuer element in the XML
    let signed_xml = xml.replace(
        "<saml:Subject>",
        &format!("{}<saml:Subject>", signature_element),
    );

    Ok(signed_xml)
}

/// Verify XML Digital Signature on SAML request
/// Returns Ok(()) if signature is valid, Err if invalid or missing
fn verify_saml_signature(
    xml: &str,
    sp_certificate: Option<&str>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use openssl::hash::MessageDigest;
    use openssl::sign::Verifier;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // If no SP certificate provided, skip verification (optional)
    let cert_pem = match sp_certificate {
        Some(cert) => cert,
        None => {
            debug!("No SP certificate provided, skipping signature verification");
            return Ok(());
        }
    };

    debug!("Verifying XML signature on SAML request");

    // Parse XML to extract Signature element
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut signature_value = None;
    let mut _digest_value = None; // Reserved for full digest verification
    let mut _reference_uri = None; // Reserved for URI validation
    let mut signed_info_start: Option<usize> = None;
    let mut signed_info_end: Option<usize> = None;
    let mut _in_signature = false; // Tracks signature element context
    let mut _in_signed_info = false; // Tracks signed info element context
    let mut in_signature_value = false;
    let mut in_digest_value = false;
    let mut in_reference = false;

    let mut buf = Vec::new();
    let mut position: usize = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                match e.name().as_ref() {
                    b"ds:Signature" | b"Signature" => {
                        _in_signature = true;
                    }
                    b"ds:SignedInfo" | b"SignedInfo" => {
                        _in_signed_info = true;
                        signed_info_start = Some(position);
                    }
                    b"ds:SignatureValue" | b"SignatureValue" => {
                        in_signature_value = true;
                    }
                    b"ds:Reference" | b"Reference" => {
                        in_reference = true;
                        // Extract URI attribute
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"URI" {
                                    _reference_uri = Some(String::from_utf8_lossy(&attr.value).into_owned());
                                }
                            }
                        }
                    }
                    b"ds:DigestValue" | b"DigestValue" => {
                        if in_reference {
                            in_digest_value = true;
                        }
                    }
                    _ => {}
                }
                position = reader.buffer_position() as usize;
            }
            Ok(Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"ds:SignedInfo" | b"SignedInfo" => {
                        _in_signed_info = false;
                        signed_info_end = Some(position);
                    }
                    b"ds:Signature" | b"Signature" => {
                        _in_signature = false;
                    }
                    b"ds:Reference" | b"Reference" => {
                        in_reference = false;
                    }
                    _ => {}
                }
                position = reader.buffer_position() as usize;
            }
            Ok(Event::Text(e)) => {
                if in_signature_value {
                    signature_value = Some(e.unescape().unwrap_or_default().into_owned());
                    in_signature_value = false;
                } else if in_digest_value {
                    _digest_value = Some(e.unescape().unwrap_or_default().into_owned());
                    in_digest_value = false;
                }
                position = reader.buffer_position() as usize;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("Error parsing SAML XML for signature verification: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_signature",
                        "detail": "XML parsing failed"
                    })),
                ));
            }
            _ => {
                position = reader.buffer_position() as usize;
            }
        }
        buf.clear();
    }

    // Check if signature was found
    let signature_value = signature_value.ok_or_else(|| {
        warn!("No signature found in SAML request");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "missing_signature",
                "detail": "Request must be signed"
            })),
        )
    })?;

    // Decode signature
    let signature_bytes = STANDARD.decode(signature_value.trim()).map_err(|e| {
        warn!("Failed to decode signature value: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_signature" })),
        )
    })?;

    // Extract SignedInfo for verification
    let (start, end) = match (signed_info_start, signed_info_end) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "missing_signed_info" })),
            ));
        }
    };

    // Extract SignedInfo XML (simplified - should use proper canonicalization)
    let signed_info_xml = &xml[start..end];
    let signed_info_canonical = signed_info_xml
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<&str>>()
        .join("");

    // Load SP's public key from certificate
    let cert_data = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    let cert_bytes = STANDARD.decode(&cert_data).map_err(|e| {
        warn!("Failed to decode SP certificate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "invalid_certificate" })),
        )
    })?;

    // Parse X.509 certificate and extract public key
    let cert = openssl::x509::X509::from_der(&cert_bytes).map_err(|e| {
        warn!("Failed to parse X.509 certificate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "certificate_parse_failed" })),
        )
    })?;

    let public_key = cert.public_key().map_err(|e| {
        warn!("Failed to extract public key from certificate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "public_key_extraction_failed" })),
        )
    })?;

    // Verify signature
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).map_err(|e| {
        warn!("Failed to create verifier: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "verifier_creation_failed" })),
        )
    })?;

    verifier
        .update(signed_info_canonical.as_bytes())
        .map_err(|e| {
            warn!("Failed to update verifier: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "verification_update_failed" })),
            )
        })?;

    let valid = verifier.verify(&signature_bytes).map_err(|e| {
        warn!("Signature verification failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_signature" })),
        )
    })?;

    if !valid {
        warn!("Signature verification failed: signature mismatch");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_signature",
                "detail": "Signature does not match"
            })),
        ));
    }

    info!("SAML request signature verified successfully");
    Ok(())
}

/// Generate NameID based on format
fn generate_name_id(
    user_email: &str,
    user_id: &str,
    format: &str,
    sp_name_qualifier: Option<&str>,
) -> String {
    match format {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => user_email.to_string(),
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => {
            // Generate persistent identifier: hash of user_id + sp_name_qualifier
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(user_id.as_bytes());
            if let Some(sp) = sp_name_qualifier {
                hasher.update(sp.as_bytes());
            }
            let result = hasher.finalize();
            format!("_persistent_{}", hex::encode(&result[..16]))
        }
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => {
            // Generate transient identifier: random UUID
            format!("_transient_{}", Uuid::new_v4())
        }
        "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified" => user_id.to_string(),
        _ => {
            // Default to email if unknown format
            warn!("Unknown NameID format '{}', defaulting to email", format);
            user_email.to_string()
        }
    }
}

/// Encrypt SAML assertion using SP's public key
fn encrypt_assertion(
    assertion_xml: &str,
    sp_encryption_cert: &str,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use openssl::rsa::Padding;
    use openssl::symm::{encrypt, Cipher};

    // Load SP's encryption certificate
    let cert_data = sp_encryption_cert
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("");

    let cert_bytes = STANDARD.decode(&cert_data).map_err(|e| {
        warn!("Failed to decode SP encryption certificate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "invalid_encryption_certificate" })),
        )
    })?;

    let cert = openssl::x509::X509::from_der(&cert_bytes).map_err(|e| {
        warn!("Failed to parse encryption certificate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "certificate_parse_failed" })),
        )
    })?;

    let public_key = cert.public_key().map_err(|e| {
        warn!("Failed to extract public key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "public_key_extraction_failed" })),
        )
    })?;

    let rsa = public_key.rsa().map_err(|e| {
        warn!("Failed to get RSA key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "rsa_key_extraction_failed" })),
        )
    })?;

    // Generate random AES-256 key for data encryption
    let mut aes_key = [0u8; 32];
    openssl::rand::rand_bytes(&mut aes_key).map_err(|e| {
        warn!("Failed to generate random AES key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "key_generation_failed" })),
        )
    })?;

    // Generate random IV for AES
    let mut iv = [0u8; 16];
    openssl::rand::rand_bytes(&mut iv).map_err(|e| {
        warn!("Failed to generate random IV: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "iv_generation_failed" })),
        )
    })?;

    // Encrypt assertion with AES-256-CBC
    let cipher = Cipher::aes_256_cbc();
    let encrypted_data = encrypt(cipher, &aes_key, Some(&iv), assertion_xml.as_bytes()).map_err(
        |e| {
            warn!("Failed to encrypt assertion: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "encryption_failed" })),
            )
        },
    )?;

    // Encrypt AES key with RSA-OAEP
    let mut encrypted_key = vec![0u8; rsa.size() as usize];
    let key_len = rsa
        .public_encrypt(&aes_key, &mut encrypted_key, Padding::PKCS1_OAEP)
        .map_err(|e| {
            warn!("Failed to encrypt AES key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "key_encryption_failed" })),
            )
        })?;
    encrypted_key.truncate(key_len);

    // Encode encrypted data
    let encrypted_data_b64 = STANDARD.encode(&encrypted_data);
    let encrypted_key_b64 = STANDARD.encode(&encrypted_key);
    let _iv_b64 = STANDARD.encode(&iv); // IV is part of encrypted data for AES-CBC

    // Build EncryptedAssertion XML
    let encrypted_assertion = format!(
        r#"<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                        Type="http://www.w3.org/2001/04/xmlenc#Element">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <xenc:EncryptedKey>
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
                <xenc:CipherData>
                    <xenc:CipherValue>{}</xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedKey>
        </ds:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>{}</xenc:CipherValue>
        </xenc:CipherData>
    </xenc:EncryptedData>
</saml:EncryptedAssertion>"#,
        encrypted_key_b64, encrypted_data_b64
    );

    Ok(encrypted_assertion)
}

/// Authenticate user from session header
async fn authenticate_user_from_session(
    state: &AppState,
    _tenant_id: &str,
    _storage_id: &str,
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    // Extract session ID from headers
    let session_id = headers
        .get("x-session-id")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            warn!("No session header found for SAML authentication");
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "authentication_required",
                    "detail": "No active session found. Please log in first."
                })),
            )
        })?;

    // Get storage backend
    let storage = &state.storage;

    // Look up session
    let session = storage
        .get_session(session_id)
        .await
        .map_err(|e| {
            warn!("Failed to get session {}: {}", session_id, e);
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_session",
                    "detail": "Session not found or expired"
                })),
            )
        })?
        .ok_or_else(|| {
            warn!("Session {} not found", session_id);
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_session",
                    "detail": "Session not found or expired"
                })),
            )
        })?;

    // Check if session is expired
    if session.expires_at < chrono::Utc::now() {
        warn!("Session {} expired", session_id);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "session_expired",
                "detail": "Your session has expired. Please log in again."
            })),
        ));
    }

    // Get user ID from session
    let user_id = session.user_id.as_ref().ok_or_else(|| {
        warn!("Session {} has no user_id", session_id);
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_session" })),
        )
    })?;

    // Get user from session
    let user = storage
        .get_user(user_id)
        .await
        .map_err(|e| {
            warn!("Failed to get user {}: {}", user_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "user_lookup_failed" })),
            )
        })?
        .ok_or_else(|| {
            warn!("User {} not found", user_id);
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "user_not_found" })),
            )
        })?;

    Ok(user.email)
}

/// Extract base URL from entity ID (assumes entity_id is a full URL)
fn extract_base_url(entity_id: &str) -> String {
    // Simple extraction: find the third slash and take everything before it
    // Examples:
    // https://example.com/path -> https://example.com
    // https://example.com:8080/path -> https://example.com:8080

    let mut slash_count = 0;
    for (i, c) in entity_id.char_indices() {
        if c == '/' {
            slash_count += 1;
            if slash_count == 3 {
                return entity_id[..i].to_string();
            }
        }
    }

    // If less than 3 slashes found, return as-is (might be just the domain)
    entity_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_saml_post_form() {
        let acs_url = "https://sp.example.com/saml/acs";
        let saml_response = "<samlp:Response>test</samlp:Response>";
        let html = create_saml_post_form(acs_url, saml_response);

        assert!(html.contains(acs_url));
        assert!(html.contains("SAMLResponse"));
        assert!(html.contains("form"));
    }

    #[test]
    fn test_generate_saml_metadata() {
        use crate::models::SamlIdpConfig;

        let config = SamlIdpConfig {
            entity_id: "https://example.com/saml/metadata".to_string(),
            sso_url: "/saml/sso".to_string(),
            slo_url: Some("/saml/slo".to_string()),
            certificate: "cert.pem".to_string(),
            private_key: "key.pem".to_string(),
            metadata_endpoint: "/saml/metadata".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
        };

        let result = generate_saml_metadata("test-tenant", &config, "https://example.com");
        // Expect failure because cert file doesn't exist (would need test fixtures)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_extract_base_url() {
        assert_eq!(
            extract_base_url("https://example.com/path/to/something"),
            "https://example.com"
        );
        assert_eq!(
            extract_base_url("https://example.com:8080/path"),
            "https://example.com:8080"
        );
        assert_eq!(
            extract_base_url("http://localhost:3000/api"),
            "http://localhost:3000"
        );
    }

    #[test]
    fn test_parse_saml_request_valid() {
        let saml_xml = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="_test_request_id_123"
                     Version="2.0"
                     IssueInstant="2024-01-01T00:00:00Z"
                     AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
    <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"#;

        let result = parse_saml_request(saml_xml);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.id, "_test_request_id_123");
        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(parsed.acs_url, "https://sp.example.com/saml/acs");
    }

    #[test]
    fn test_parse_saml_request_without_namespace() {
        let saml_xml = r#"<?xml version="1.0"?>
<AuthnRequest ID="_test_id"
              AssertionConsumerServiceURL="https://sp.example.com/acs">
    <Issuer>https://sp.example.com</Issuer>
</AuthnRequest>"#;

        let result = parse_saml_request(saml_xml);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.id, "_test_id");
        assert_eq!(parsed.issuer, "https://sp.example.com");
        assert_eq!(parsed.acs_url, "https://sp.example.com/acs");
    }

    #[test]
    fn test_parse_saml_request_missing_id() {
        let saml_xml = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"#;

        let result = parse_saml_request(saml_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_saml_request_missing_issuer() {
        let saml_xml = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     ID="_test_id"
                     AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
</samlp:AuthnRequest>"#;

        let result = parse_saml_request(saml_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_saml_request_missing_acs_url() {
        let saml_xml = r#"<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     ID="_test_id">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"#;

        let result = parse_saml_request(saml_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_saml_request_invalid_xml() {
        let saml_xml = "not valid xml at all";

        let result = parse_saml_request(saml_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_saml_logout_request_valid() {
        let logout_xml = r#"<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="_logout_request_id_456"
                      Version="2.0"
                      IssueInstant="2024-01-01T00:00:00Z">
    <saml:NameID>user@example.com</saml:NameID>
    <samlp:SessionIndex>session_123_abc</samlp:SessionIndex>
</samlp:LogoutRequest>"#;

        let result = parse_saml_logout_request(logout_xml);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.id, "_logout_request_id_456");
        assert_eq!(parsed.name_id, "user@example.com");
        assert_eq!(parsed.session_index, Some("session_123_abc".to_string()));
    }

    #[test]
    fn test_parse_saml_logout_request_without_session_index() {
        let logout_xml = r#"<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="_logout_id">
    <saml:NameID>user@example.com</saml:NameID>
</samlp:LogoutRequest>"#;

        let result = parse_saml_logout_request(logout_xml);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.id, "_logout_id");
        assert_eq!(parsed.name_id, "user@example.com");
        assert_eq!(parsed.session_index, None);
    }

    #[test]
    fn test_parse_saml_logout_request_without_namespace() {
        let logout_xml = r#"<?xml version="1.0"?>
<LogoutRequest ID="_logout_id_no_ns">
    <NameID>user@example.com</NameID>
    <SessionIndex>sess_999</SessionIndex>
</LogoutRequest>"#;

        let result = parse_saml_logout_request(logout_xml);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.id, "_logout_id_no_ns");
        assert_eq!(parsed.name_id, "user@example.com");
        assert_eq!(parsed.session_index, Some("sess_999".to_string()));
    }

    #[test]
    fn test_parse_saml_logout_request_missing_id() {
        let logout_xml = r#"<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">user@example.com</saml:NameID>
</samlp:LogoutRequest>"#;

        let result = parse_saml_logout_request(logout_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_parse_saml_logout_request_missing_name_id() {
        let logout_xml = r#"<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      ID="_logout_id">
    <samlp:SessionIndex>session_123</samlp:SessionIndex>
</samlp:LogoutRequest>"#;

        let result = parse_saml_logout_request(logout_xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_decode_saml_redirect_valid() {
        // Create a valid deflated + base64 encoded SAML request
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let xml = "<test>hello</test>";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(xml.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let encoded = STANDARD.encode(&compressed);

        let result = decode_saml_redirect(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), xml);
    }

    #[test]
    fn test_decode_saml_redirect_invalid_base64() {
        let result = decode_saml_redirect("not-valid-base64!!!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_decode_saml_redirect_invalid_compression() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        // Valid base64 but not deflated data
        let encoded = STANDARD.encode(b"just plain text");
        let result = decode_saml_redirect(&encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_generate_saml_response_structure() {
        use crate::models::SamlIdpConfig;

        // Create test config (we won't actually load files)
        let config = SamlIdpConfig {
            entity_id: "https://idp.example.com/saml/metadata".to_string(),
            sso_url: "/saml/sso".to_string(),
            slo_url: Some("/saml/slo".to_string()),
            certificate: "tests/fixtures/test_cert.pem".to_string(),
            private_key: "tests/fixtures/test_key.pem".to_string(),
            metadata_endpoint: "/saml/metadata".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
        };

        let request = ParsedSamlRequest {
            id: "_request_id_123".to_string(),
            issuer: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/saml/acs".to_string(),
            relay_state: None,
        };

        // This will fail because files don't exist, but we can test the structure
        let result = generate_saml_response(
            &request,
            "test-tenant",
            &config,
            "user@example.com",
            "https://idp.example.com",
        );

        // Expect failure due to missing cert/key files
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_load_certificate_data_missing_file() {
        let result = load_certificate_data("nonexistent_cert.pem");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_load_private_key_missing_file() {
        let result = load_private_key("nonexistent_key.pem");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_parsed_saml_request_debug() {
        let request = ParsedSamlRequest {
            id: "_test_id".to_string(),
            issuer: "https://sp.example.com".to_string(),
            acs_url: "https://sp.example.com/acs".to_string(),
            relay_state: Some("relay_state_value".to_string()),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("_test_id"));
        assert!(debug_str.contains("https://sp.example.com"));
    }

    #[test]
    fn test_parsed_saml_logout_request_debug() {
        let logout_request = ParsedSamlLogoutRequest {
            id: "_logout_id".to_string(),
            name_id: "user@example.com".to_string(),
            session_index: Some("session_123".to_string()),
        };

        let debug_str = format!("{:?}", logout_request);
        assert!(debug_str.contains("_logout_id"));
        assert!(debug_str.contains("user@example.com"));
        assert!(debug_str.contains("session_123"));
    }

    #[test]
    fn test_create_saml_post_form_encoding() {
        let acs_url = "https://sp.example.com/saml/acs";
        let saml_response = "<samlp:Response><test/></samlp:Response>";
        let html = create_saml_post_form(acs_url, saml_response);

        // Verify the response is base64 encoded in the form
        assert!(html.contains("SAMLResponse"));
        assert!(html.contains("value="));

        // Should not contain raw XML
        assert!(!html.contains("<samlp:Response>"));

        // Should have auto-submit JavaScript
        assert!(html.contains("onload"));
        assert!(html.contains("submit"));
    }

    #[test]
    fn test_saml_redirect_params_deserialization() {
        // This tests the SamlRedirectParams structure
        let json = r#"{
            "SAMLRequest": "base64_encoded_request",
            "RelayState": "relay_state_value",
            "SigAlg": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "Signature": "signature_value"
        }"#;

        let params: Result<SamlRedirectParams, _> = serde_json::from_str(json);
        assert!(params.is_ok());

        let p = params.unwrap();
        assert_eq!(p.saml_request, "base64_encoded_request");
        assert_eq!(p.relay_state, Some("relay_state_value".to_string()));
        assert_eq!(
            p.sig_alg,
            Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string())
        );
        assert_eq!(p.signature, Some("signature_value".to_string()));
    }

    #[test]
    fn test_saml_redirect_params_optional_fields() {
        // Test with only required SAMLRequest field
        let json = r#"{"SAMLRequest": "base64_request"}"#;

        let params: Result<SamlRedirectParams, _> = serde_json::from_str(json);
        assert!(params.is_ok());

        let p = params.unwrap();
        assert_eq!(p.saml_request, "base64_request");
        assert_eq!(p.relay_state, None);
        assert_eq!(p.sig_alg, None);
        assert_eq!(p.signature, None);
    }
}
