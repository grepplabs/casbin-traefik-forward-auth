#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./kc-get-token.sh <username> <password> [client-id]
# Example:
#   ./kc-get-token.sh alice alicepw
#   ./kc-get-token.sh bob bobpw local-cli-client

USERNAME="${1:?username required}"
PASSWORD="${2:?password required}"
CLIENT_ID="${3:-local-cli-client}"

KEYCLOAK_REALM_URL="http://localhost:30082/realms/master"

echo "Requesting token from ${KEYCLOAK_REALM_URL} for user '${USERNAME}' using client '${CLIENT_ID}'..."

RESPONSE=$(curl -s -X POST "${KEYCLOAK_REALM_URL}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid profile email")

if [[ "$(echo "$RESPONSE" | jq -r '.access_token // empty')" == "" ]]; then
  echo "Failed to retrieve token. Full response:"
  echo "$RESPONSE" | jq .
  exit 1
fi

echo ""
echo "Token response:"
echo "$RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
echo ""
echo "Access token (truncated):"
echo "${ACCESS_TOKEN:0:80}..."

echo ""
echo "Decoded JWT claims:"
echo "$ACCESS_TOKEN" | cut -d '.' -f2 | base64 -d 2>/dev/null | jq .
