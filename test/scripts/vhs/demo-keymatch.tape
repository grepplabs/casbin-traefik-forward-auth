## Settings
Output demo-keymatch.gif

Require echo

Set Shell "bash"
Set FontSize 16
Set Width 1400
Set Height 800
Set Padding 32

Set BorderRadius 12
Set WindowBar Colorful
Set WindowBarSize 36
Set Margin 0
Set MarginFill "#000000"

## Intro

Sleep 1s

Type "echo '🚀  Welcome to Casbin Traefik Forward Auth!'" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'Let’s see access control with the keymatch_model in action!'" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'This demo runs on a local Kubernetes kind cluster with: Traefik as the Ingress Controller, casbin-forward-auth for authorization, Keycloak for identity and Echo as a protected sample service'" Sleep 500ms Enter
Enter
Sleep 3s
## Inspect config

Hide
Type "clear" Enter
Show

Type "echo '🔍 Let’s inspect the configuration...'" Sleep 500ms Enter
Enter
Sleep 1s

### traefik middleware

Hide
Type "clear" Enter
Show

Type "kubectl get middleware -n traefik casbin-auth -o yaml | yq" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'casbin-forward-auth acts as Traefik ForwardAuth middleware.'"
Enter
Sleep 5s

### casbin-auth-env

Hide
Type "clear" Enter
Show

Type "kubectl get cm -n casbin-auth casbin-auth-env -o yaml | yq '.data'" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'Keycloak is enabled as the authentication provider via JWT validation'" Sleep 500ms Enter
Enter
Sleep 5s

### casbin-auth-config

Hide
Type "clear" Enter
Show

Type "kubectl get cm -n casbin-auth casbin-auth-config -o yaml | yq '.data'" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'Casbin authorization input: subject -> preferred_username JWT claim, object -> URL path, action -> HTTP method'" Sleep 500ms Enter
Enter
Sleep 5s
## Enable middleware

Hide
Type "clear" Enter
### disable middleware
Type "kubectl annotate ingress echo -n default traefik.ingress.kubernetes.io/router.middlewares-" Enter
Show

### unprotected service

Hide
Type "clear" Enter
Show

Type "echo '⚠️  Echo service is unprotected; request returns 200 OK.'" Sleep 500ms Enter
Enter
Sleep 2s

Type "curl -I http://echo.127.0.0.1.nip.io:30081/alice_data/resource3" Sleep 500ms Enter
Enter
Sleep 5s

### enable middleware

Type "echo '🔐  Let’s enable Traefik ForwardAuth middleware and try the request again!'" Sleep 500ms Enter
Enter
Sleep 2s

Type "kubectl annotate ingress echo 'traefik.ingress.kubernetes.io/router.middlewares=traefik-casbin-auth@kubernetescrd' --overwrite" Sleep 500ms Enter
Enter
Sleep 2s

Type "curl -I http://echo.127.0.0.1.nip.io:30081/alice_data/resource3" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo '🚫  Request returned 401 Unauthorized - a valid JWT token is required.'" Sleep 500ms Enter
Enter
Sleep 5s
## Set token

Hide
Type "clear" Enter
Show

Type "export TOKEN=$(curl -s -d 'grant_type=password' -d 'client_id=local-cli-client' -d 'username=alice' -d 'password=alicepw' http://localhost:30082/realms/master/protocol/openid-connect/token | jq -r '.access_token')" Sleep 500ms Enter
Enter
Sleep 1s

Type "echo '🔍  Inspecting Alice’s JWT token to see her claims...'" Sleep 500ms Enter
Enter
Sleep 2s

Type "jwt decode $TOKEN --json | jq -r '.payload'" Sleep 500ms Enter
Enter
Sleep 5s
## Forbidden

Hide
Type "clear" Enter
Show

### forbidden

Hide
Type "clear" Enter
Show

Type "echo '⚠️  Alice has insufficient permissions; request returns 403 Forbidden.'" Sleep 500ms Enter
Enter
Sleep 2s

Type "curl -I --oauth2-bearer ${TOKEN} -X GET http://echo.127.0.0.1.nip.io:30081/alice_data/resource3" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'Let’s configure Casbin access policies.'" Sleep 500ms Enter
Enter
Sleep 5s
## Policies

Hide
Type "clear" Enter
Show

### download policies

Hide
Type "clear" Enter
Show

Type "echo '⬇️  Let’s download the KeyMatch example policies.'" Sleep 500ms Enter
Enter
Sleep 2s

Type "curl -s https://raw.githubusercontent.com/casbin/casbin/refs/heads/master/examples/keymatch_policy.csv -o keymatch_policy.csv" Sleep 500ms Enter
Enter
Sleep 2s

Type "(cat keymatch_policy.csv; echo)" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo 'Use casbin-kube-converter to convert downloaded CSV policies into Casbin Kube Kubernetes Custom Resources.'" Sleep 500ms Enter
Enter
Sleep 2s

Type "casbin-kube-converter -i ./keymatch_policy.csv -n casbin-auth | kubectl apply -f-" Sleep 500ms Enter
Enter
Sleep 5s
## Applied rules

Hide
Type "clear" Enter
Show

Type "echo '🧩  Let’s see the applied rules...'" Sleep 500ms Enter
Enter
Sleep 1s

Type "kubectl get rules.casbin.grepplabs.com -n casbin-auth" Sleep 500ms Enter
Enter
Sleep 1s

Type "kubectl get rules -n casbin-auth rule-e780692ab98c450477d512fbef349f1be073ecd41121ee9e3cb6a9118392016b -o yaml" Sleep 500ms Enter
Enter
Sleep 5s

## Access granted

Hide
Type "clear" Enter
Show

### ok

Hide
Type "clear" Enter
Show

Type "echo '✅  Alice has permission to access her resource; request returns 200 OK.'" Sleep 500ms Enter
Enter
Sleep 2s

Type "curl -I --oauth2-bearer ${TOKEN} -X GET http://echo.127.0.0.1.nip.io:30081/alice_data/resource3" Sleep 500ms Enter
Enter
Sleep 2s

Type "echo '🚫  Alice cannot access Cathy’s resources - request returns 403 Forbidden.'"
Enter
Sleep 2s

Type "curl -I --oauth2-bearer ${TOKEN} -X GET http://echo.127.0.0.1.nip.io:30081/cathy_data" Sleep 500ms Enter
Enter
Sleep 20s
