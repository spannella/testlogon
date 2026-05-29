"""Mock SAML SP implementation (ENTERPRISE-002).

This is a mock/dev implementation that does NOT depend on python3-saml or xmlsec.
It uses Python's built-in xml.etree.ElementTree for XML parsing.

For production, this would be replaced with a full python3-saml implementation.
In dev/test mode, it validates SAMLResponse by:
1. Parsing the base64-decoded XML
2. Extracting NameID and attributes
3. Checking the issuer matches the configured IdP entity ID
4. In dev mode, skipping cryptographic signature validation
"""
from __future__ import annotations

import base64
import logging
import uuid
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from app.core.settings import S

logger = logging.getLogger(__name__)

SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


class MockSamlAuth:
    """A mock SAML auth object that mimics python3-saml's OneLogin_Saml2_Auth."""

    def __init__(self, request_data: Dict[str, Any], settings: Dict[str, Any]):
        self._request_data = request_data
        self._settings = settings
        self._errors: List[str] = []
        self._error_reason: str = ""
        self._authenticated = False
        self._attributes: Dict[str, List[str]] = {}
        self._name_id: str = ""
        self._session_index: str = ""
        self._assertion_id: str = ""

    def process_response(self) -> None:
        """Process the SAMLResponse from the IdP."""
        post_data = self._request_data.get("post_data", {})
        saml_response_b64 = post_data.get("SAMLResponse", "")
        if not saml_response_b64:
            self._errors.append("missing_saml_response")
            self._error_reason = "No SAMLResponse found in POST data"
            return

        try:
            xml_bytes = base64.b64decode(saml_response_b64)
            root = ET.fromstring(xml_bytes)
        except Exception as exc:
            self._errors.append("invalid_xml")
            self._error_reason = f"Failed to parse SAMLResponse XML: {exc}"
            return

        # Check Issuer
        issuer_elem = root.find(f"{{{SAML_ASSERTION_NS}}}Issuer")
        if issuer_elem is None:
            # Try under the Response element directly
            issuer_elem = root.find(f".//{{{SAML_ASSERTION_NS}}}Issuer")

        expected_issuer = self._settings.get("idp", {}).get("entityId", "")
        if issuer_elem is not None and expected_issuer:
            actual_issuer = (issuer_elem.text or "").strip()
            if actual_issuer != expected_issuer:
                self._errors.append("issuer_mismatch")
                self._error_reason = f"Issuer mismatch: expected {expected_issuer}, got {actual_issuer}"
                return

        # Find Assertion
        assertion = root.find(f"{{{SAML_ASSERTION_NS}}}Assertion")
        if assertion is None:
            assertion = root.find(f".//{{{SAML_ASSERTION_NS}}}Assertion")
        if assertion is None:
            self._errors.append("no_assertion")
            self._error_reason = "No Assertion element found in SAMLResponse"
            return

        # Extract assertion ID
        self._assertion_id = assertion.get("ID", f"_mock_{uuid.uuid4().hex}")

        # Extract NameID
        subject = assertion.find(f"{{{SAML_ASSERTION_NS}}}Subject")
        if subject is not None:
            name_id_elem = subject.find(f"{{{SAML_ASSERTION_NS}}}NameID")
            if name_id_elem is not None:
                self._name_id = (name_id_elem.text or "").strip()

        # Extract SessionIndex from AuthnStatement
        authn_stmt = assertion.find(f"{{{SAML_ASSERTION_NS}}}AuthnStatement")
        if authn_stmt is not None:
            self._session_index = authn_stmt.get("SessionIndex", "")

        # Extract attributes
        attr_stmt = assertion.find(f"{{{SAML_ASSERTION_NS}}}AttributeStatement")
        if attr_stmt is not None:
            for attr_elem in attr_stmt.findall(f"{{{SAML_ASSERTION_NS}}}Attribute"):
                attr_name = attr_elem.get("Name", "")
                values = []
                for val_elem in attr_elem.findall(f"{{{SAML_ASSERTION_NS}}}AttributeValue"):
                    values.append((val_elem.text or "").strip())
                if attr_name:
                    self._attributes[attr_name] = values

        # In dev mode, skip signature validation -- mark as authenticated
        self._authenticated = True

    def get_errors(self) -> List[str]:
        return self._errors

    def get_last_error_reason(self) -> str:
        return self._error_reason

    def is_authenticated(self) -> bool:
        return self._authenticated

    def get_attributes(self) -> Dict[str, List[str]]:
        return self._attributes

    def get_nameid(self) -> str:
        return self._name_id

    def get_session_index(self) -> str:
        return self._session_index

    def get_last_assertion_id(self) -> str:
        return self._assertion_id

    def login(self, return_to: str = "/") -> str:
        """Generate a redirect URL to the IdP SSO endpoint."""
        idp_sso_url = self._settings.get("idp", {}).get("singleSignOnService", {}).get("url", "")
        sp_entity_id = self._settings.get("sp", {}).get("entityId", "")
        # In production, this would build a proper AuthnRequest
        # For dev/mock, we just redirect with basic query params
        authn_request_id = f"_mock_{uuid.uuid4().hex}"
        redirect_url = f"{idp_sso_url}?SAMLRequest=mock&RelayState={return_to}&Issuer={sp_entity_id}"
        return redirect_url


def build_saml_settings(provider: Dict[str, Any], request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build SAML settings dict from our provider record."""
    sp_entity_id = provider.get("sp_entity_id", "")
    sp_acs_url = provider.get("sp_acs_url", "")

    # Build IdP cert list (support multiple for rotation)
    idp_certs = [c.get("x509_cert", "") for c in provider.get("idp_certificates", [])]

    return {
        "strict": not S.dev_mode,
        "debug": S.dev_mode,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": provider.get("idp_entity_id", ""),
            "singleSignOnService": {
                "url": provider.get("idp_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": provider.get("idp_slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509certMulti": {
                "signing": idp_certs,
            },
        },
    }


def prepare_request_data(request) -> Dict[str, Any]:
    """Convert a Starlette/FastAPI request to the format the SAML SP expects."""
    scheme = request.url.scheme
    host = request.headers.get("host", "localhost")
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": request.url.port or (443 if scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }
