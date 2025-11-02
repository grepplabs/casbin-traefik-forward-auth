#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./kc-create-user.sh <username> <password>
#
# Example:
#   ./kc-create-user.sh alice alicepw

USERNAME="${1:?username required}"
PASSWORD="${2:?password required}"

NAMESPACE="keycloak"
REALM="master"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"

POD_NAME="$(kubectl get pods -n "$NAMESPACE" -l app=keycloak \
  -o jsonpath='{.items[0].metadata.name}')"

echo "Using Keycloak pod: $POD_NAME"

echo "Logging into Keycloak admin as '${ADMIN_USER}'..."
kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm "$REALM" \
    --user "$ADMIN_USER" \
    --password "$ADMIN_PASSWORD"

# 3. Create the user if needed
echo "Ensuring user '$USERNAME' in realm '$REALM'..."
set +e
kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh create users -r "$REALM" \
    -s "username=${USERNAME}" \
    -s "enabled=true" >/dev/null 2>&1
CREATE_RC=$?
set -e

if [ "$CREATE_RC" -eq 0 ]; then
  echo "User '$USERNAME' created."
else
  echo "User '$USERNAME' already existed or create returned non-zero, continuing."
  echo ""
fi

USER_ID="$(kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh get users -r "$REALM" --fields id,username | \
  jq -r ".[] | select(.username==\"${USERNAME}\") | .id")"

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
  echo "ERROR: could not resolve user ID for '$USERNAME' in realm '$REALM'" >&2
  exit 1
fi

echo "User '$USERNAME' has id: $USER_ID"

echo "Setting password for '$USERNAME'..."
kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh set-password -r "$REALM" \
    --userid "$USER_ID" \
    --new-password "$PASSWORD" \
    --temporary=false

echo "Password for '$USERNAME' set"
echo "Done."
