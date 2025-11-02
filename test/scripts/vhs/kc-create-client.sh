#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./kc-create-client.sh <client-id>
#
# Example:
#   ./kc-create-client.sh local-cli-client

CLIENT_ID="${1:-local-cli-client}"

# Fixed cluster config
NAMESPACE="keycloak"
REALM="master"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"

# 1. Get the running Keycloak pod
POD_NAME="$(kubectl get pods -n "$NAMESPACE" -l app=keycloak \
  -o jsonpath='{.items[0].metadata.name}')"

echo "Using Keycloak pod: $POD_NAME"
echo "Logging into Keycloak as admin '${ADMIN_USER}'..."

# 2. Login kcadm
kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm "$REALM" \
    --user "$ADMIN_USER" \
    --password "$ADMIN_PASSWORD"

echo "Ensuring public client '$CLIENT_ID' in realm '$REALM'..."

# 3. Try to create the client (public, password grant enabled)
set +e
kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh create clients -r "$REALM" \
    -s "clientId=${CLIENT_ID}" \
    -s "enabled=true" \
    -s "protocol=openid-connect" \
    -s "publicClient=true" \
    -s "directAccessGrantsEnabled=true" \
    -s "standardFlowEnabled=false" \
    -s "serviceAccountsEnabled=false" \
  >/dev/null 2>&1
CREATE_RC=$?
set -e

if [ "$CREATE_RC" -eq 0 ]; then
  echo "Client '$CLIENT_ID' created."
else
  echo "Client '$CLIENT_ID' already existed or create returned non-zero, continuing."
fi

# 4. Get internal ID so we can show some details
CLIENT_INTERNAL_ID="$(
  kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
    /opt/keycloak/bin/kcadm.sh get clients -r "$REALM" --fields id,clientId \
    | jq -r ".[] | select(.clientId==\"${CLIENT_ID}\") | .id"
)"

if [ -z "$CLIENT_INTERNAL_ID" ] || [ "$CLIENT_INTERNAL_ID" = "null" ]; then
  echo "ERROR: could not resolve internal ID for client '$CLIENT_ID'" >&2
  exit 1
fi

kubectl exec -n "$NAMESPACE" "$POD_NAME" -- \
  /opt/keycloak/bin/kcadm.sh update clients/${CLIENT_INTERNAL_ID} -r "$REALM" \
    -s 'attributes."access.token.lifespan"=3600'


echo "Client '$CLIENT_ID' internal id: $CLIENT_INTERNAL_ID"
echo ""
echo "You can now get a user token like:"
echo ""
echo "curl -s \\"
echo "  -d \"grant_type=password\" \\"
echo "  -d \"client_id=${CLIENT_ID}\" \\"
echo "  -d \"username=alice\" \\"
echo "  -d \"password=alicepw\" \\"
echo "  http://localhost:30082/realms/${REALM}/protocol/openid-connect/token | jq ."
echo ""
echo "Done"
