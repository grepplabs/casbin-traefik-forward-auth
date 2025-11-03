# Casbin Traefik Forward Auth

[![Build](https://github.com/grepplabs/casbin-traefik-forward-auth/actions/workflows/build.yml/badge.svg)](https://github.com/grepplabs/casbin-traefik-forward-auth/actions/workflows/build.yml)

A ForwardAuth service for [Traefik](https://traefik.io/) with [Casbin-based](https://casbin.org/) authorization.

This service provides a forward authentication endpoint for Traefik, allowing you to protect your services with
fine-grained access control policies defined using Casbin.
It acts as a gatekeeper, intercepting requests from Traefik, evaluating them against your Casbin policies, and then
allowing or denying the request based on the outcome.

### Key Features

- **Flexible Access Control:** Define authorization policies using the powerful Casbin model.
- **Multiple Policy Sources:** Load policies from files or directly from Kubernetes (
  using [casbin-kube](https://github.com/grepplabs/casbin-kube)).
- **Dynamic Policy Reloading:**
    - For file-based policies, automatically reload policies at a configurable interval.
    - For Kubernetes-based policies, rely on native **Informer** mechanisms to watch for changes - no separate Casbin
      watcher required.
- **Request-Based Authorization:** Authorize requests based on headers, JWT claims, query parameters, and more.
- **JWT Authentication:** Optionally validate JWT tokens to authenticate requests before applying authorization policies.
- **Declarative Configuration:** Configure authorization rules and routes using a simple YAML file.

    - Example Routing Configuration **KEYMATCH Model**

    ```yaml
    routes:
      - httpMethod: ANY
        relativePaths:
          - /*any
        params:
          - name: user
            source: basicAuthUser
          - name: resource
            source: urlPath
          - name: method
            source: httpMethod
        rules:
          - format: "%s"
            paramNames: [ user ]
          - format: "%s"
            paramNames: [ resource ]
          - format: "%s"
            paramNames: [ method ]
    ```
  [keymatch_model.conf](https://github.com/casbin/casbin/blob/master/examples/keymatch_model.conf)
  [keymatch_policy.csv](https://github.com/casbin/casbin/blob/master/examples/keymatch_policy.csv)

## Architecture

<p style="text-align: left;">
  <img src="docs/forward-auth.svg" alt="Architecture" style="max-width: 100%; width: 600px; height: auto;">
</p>

### How it works

1. [**Traefik Forward Authentication:**](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/) Traefik is
   configured to use this service as a forward authentication provider.
2. **Request Interception:** When a request comes to Traefik, it forwards the request to this service.
3. **Rule Evaluation:** The service evaluates the incoming request against the configured authorization rules.
4. **Casbin Enforcement:** The rules are then used to make a Casbin enforcement request.
5. **Authorization Response:**
    * If the request is authorized, the service returns a `200 OK` response to Traefik, which then forwards the request
      to the upstream service.
    * If the request is denied, the service returns a `403 Forbidden` response, and Traefik denies access to the
      upstream service.
    * If JWT is enabled and validation fails, returns `401 Unauthorized`.

## 🎬 Demo
Demo showing request authorization with **Casbin Traefik Forward Auth** and the **KEYMATCH** policy model.

<p style="text-align: left;">
  <img src="docs/demo-keymatch.gif" alt="Casbin Traefik Forward Auth Demo" style="max-width: 100%; width: 1400px; height: auto;">
</p>

### Installation

#### Prerequisites (for Kube Adapter)

Before installing **Casbin Traefik Forward Auth**, ensure that the **Casbin Kube** CRD is deployed in your cluster.
Casbin Kube Adapter manages Casbin policies and provides Kubernetes-native policy synchronization.

```bash
helm install casbin-kube oci://ghcr.io/grepplabs/helm/casbin-kube:0.0.1
```

**Install Casbin Traefik Forward Auth**

Install the Casbin Traefik Forward Auth Helm chart:

```bash
helm install casbin-auth oci://ghcr.io/grepplabs/helm/casbin-traefik-forward-auth:<char version> -f your-values.yaml
```

**Create a Traefik `Middleware` (ForwardAuth)**

Example Traefik CRDs:

```yaml
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: casbin-auth
  namespace: traefik
spec:
  forwardAuth:
    address: http://casbin-auth.casbin-auth.svc.cluster.local/v1/auth
    trustForwardHeader: true
    authResponseHeaders:
      - X-Casbin-Auth-JWT
      - WWW-Authenticate

``` 

**Attach the middleware to your route**

You can apply the ForwardAuth middleware in several ways:

- **Globally:** configure Traefik to use the middleware on all entrypoints (`additionalArguments` in Traefik Helm
  chart).
- **IngressRoute:** reference the middleware in
  your [IngressRoute](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/crd/http/ingressroute/).
- **Ingress:** use the annotation `traefik.ingress.kubernetes.io/router.middlewares` on standard
  Kubernetes [Ingress](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/ingress/) objects.

## Configuration

The service is configured using command-line flags or environment variables.

| Flag                                   | Environment Variable                   | Description                                                                                                                    | Default                    |
|:---------------------------------------|:---------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------|:---------------------------|
| `server-addr`                          | `SERVER_ADDR`                          | Server listen address.                                                                                                         | `:8080`                    |
| `auth-route-config-path`               | `AUTH_ROUTE_CONFIG_PATH`               | Path to the config YAML file containing route authorization rules.                                                             |                            |
| `casbin-model`                         | `CASBIN_MODEL`                         | Path or reference to the Casbin model (e.g. `file:///etc/casbin/model.conf` or `rbac_model.conf`).                             | `rbac_model.conf`          |
| `casbin-adapter`                       | `CASBIN_ADAPTER`                       | Casbin adapter. One of: `file`, `kube`.                                                                                        | `kube`                     |
| `casbin-autoload-interval`             | `CASBIN_AUTOLOAD_INTERVAL`             | Interval for automatically reloading Casbin policies (e.g. 30s, 1m). Set to 0 to disable.                                      | `0`                        |
| `casbin-adapter-file-policy-path`      | `CASBIN_ADAPTER_FILE_POLICY_PATH`      | Path to the policy file.                                                                                                       | `examples/rbac_policy.csv` |
| `casbin-adapter-kube-disable-informer` | `CASBIN_ADAPTER_KUBE_DISABLE_INFORMER` | Disable the Casbin Kubernetes informer.                                                                                        | `false`                    |
| `casbin-adapter-kube-config-context`   | `CASBIN_ADAPTER_KUBE_CONFIG_CONTEXT`   | Name of the Kubernetes context to use from the kubeconfig file.                                                                |                            |
| `casbin-adapter-kube-config-namespace` | `CASBIN_ADAPTER_KUBE_CONFIG_NAMESPACE` | Kubernetes namespace where Casbin policies are stored.                                                                         | value of `POD_NAMESPACE`   |
| `casbin-adapter-kube-config-path`      | `CASBIN_ADAPTER_KUBE_CONFIG_PATH`      | Path to the kubeconfig file.                                                                                                   |                            |
| `casbin-adapter-kube-config-labels`    | `CASBIN_ADAPTER_KUBE_CONFIG_LABELS`    | Labels to filter policies. Example: `key1=val1,key2=val2`.                                                                     |                            |
| `jwt-enabled`                          | `JWT_ENABLED`                          | Enable JWT verification for incoming requests. When enabled, `jwt-jwks-url`, `jwt-issuer`, and `jwt-audience` must be set.     | `false`                    |
| `jwt-jwks-url`                         | `JWT_JWKS_URL`                         | URL or file path to the JWKS source (e.g. `https://issuer.example.com/.well-known/jwks.json` or `file:///etc/jwks/keys.json`). |                            |
| `jwt-issuer`                           | `JWT_ISSUER`                           | Expected JWT issuer (`iss` claim).                                                                                             |                            |
| `jwt-audience`                         | `JWT_AUDIENCE`                         | Expected JWT audience (`aud` claim).                                                                                           |                            |
| `jwt-skew`                             | `JWT_SKEW`                             | Clock skew tolerance for `exp`/`nbf` claims (e.g. `30s`).                                                                      | `0`                        |
| `jwt-init-timeout`                     | `JWT_INIT_TIMEOUT`                     | Maximum time to wait for initial JWKS fetch during startup.                                                                    | `15s`                      |
| `jwt-refresh-timeout`                  | `JWT_REFRESH_TIMEOUT`                  | Timeout for individual JWKS refresh requests.                                                                                  | `2s`                       |
| `jwt-min-refresh-interval`             | `JWT_MIN_REFRESH_INTERVAL`             | Minimum interval between JWKS refresh attempts.                                                                                | `0`                        |
| `jwt-max-refresh-interval`             | `JWT_MAX_REFRESH_INTERVAL`             | Maximum interval between JWKS refresh attempts.                                                                                | `0`                        |
| `jwt-use-x509`                         | `JWT_USE_X509`                         | Indicates that the JWKS source contains X.509-encoded keys (PEM certificates) instead of standard JWK JSON.                    | `false`                    |

## Routing Configuration

The routing configuration is defined in a YAML file specified by `auth-route-config-path`. It consists of a list of
routes, each defining how incoming requests should be authorized.

### Route Fields

* `httpMethod` (string): The HTTP method to match (e.g., `GET`, `POST`, `ANY`).
* `relativePath` (array of strings): The URL path to match. Can include path parameters (e.g., `/user/:id`).
* `params` (array of objects): A list of parameters to extract from the incoming request.
    * `name` (string): The name of the parameter.
    * `source` (string): The source of the parameter. Possible values:
        * `path`: Extracts the parameter from the URL path (e.g., `:id` in `/user/:id`).
        * `query`: Extracts the parameter from the URL query string (e.g., `?q=value`).
        * `header`: Extracts the parameter from an HTTP header.
        * `claim`: Extracts the parameter from a JWT claim using. Requires a valid JWT in the `Authorization: Bearer`
          header.
        * `basicAuthUser`: Extracts the username from the `Authorization: Basic` header.
        * `url`: Extracts the full request URL.
        * `urlPath`: Extracts the request URL path.
        * `httpMethod`: Extracts the HTTP method of the request.
    * `key` (string, optional): The key to use when `source` is `query`, `header`, or `claim`. If omitted, `name` is
      used.
    * `expr` (string, optional): An expression to extract a value. Used with `source: claim`
      for [GJSON](https://github.com/tidwall/gjson) paths (e.g., `sub`, `acme/project/project\.id`) or with
      `function: regex` for regular expressions.
    * `default` (string, optional): A default value to use if the parameter is not found.
    * `function` (string, optional): A function to apply to the extracted value. Supported functions:
        * `b64dec`: Decodes a base64 encoded string.
        * `firstLabel`: Extracts the first label from a dot-separated string (e.g., `foo` from `foo.bar.com`).
        * `regex`: Extracts a substring from the value using a regular expression defined in the `expr` field. The
          `expr` field must contain a valid regular expression with at least one capturing group.
        * `tolower`: Converts the entire value to lowercase (e.g., `HeLLo` → `hello`).
        * `toupper`: Converts the entire value to uppercase (e.g., `HeLLo` → `HELLO`).
* `rules` (array of objects): A list of Casbin rules to enforce. Each rule can be a simple format string or a set of
  cases.
    * `format` (string): A format string to construct the Casbin rule. Parameters are injected using `%s`.
    * `paramNames` (array of strings): The names of the parameters to inject into the `format` string, in order.
    * `cases` (array of objects, optional): A list of conditional rules. The first `when` expression that evaluates to
      true will have its `format` and `paramNames` used.
        * `when` (string): An expression that must evaluate to true for this case to be used. Uses
          the [expr](https://expr-lang.org/) language. The following functions are available within `when` expressions:
            * `hasPrefix(s, prefix)`: Returns `true` if the string `s` begins with `prefix`.
            * `hasSuffix(s, suffix)`: Returns `true` if the string `s` ends with `suffix`.
            * `contains(s, sub)`: Returns `true` if the string `s` contains `sub`.
            * `equalsIgnoreCase(a, b)`: Returns `true` if strings `a` and `b` are equal, ignoring case.
            * `equals(a, b)`: Returns `true` if strings `a` and `b` are equal.
            * `match(s, re)`: Returns `true` if the string `s` matches the regular expression `re`.

### Examples

#### **RBAC Example: Role-Based Access Control**

This example demonstrates how a Pub/Sub-style authorization flow can be expressed using Casbin rules and route-based
parameter extraction.

##### Routing Configuration

```yaml
routes:
  - httpMethod: POST
    relativePaths:
      - /v1alpha/publish
    params:
      - name: topicId
        source: header
        expr: Host
        function: firstLabel
      - name: projectId
        source: claim
        expr: acme/project/project\.id
      - name: sub
        source: claim
        expr: sub
    rules:
      - format: iam::%s:sa/%s
        paramNames: [ projectId, sub ]
      - format: pubsub:eu-central-1:%s:topics/%s
        paramNames: [ projectId, topicId ]
      - format: pubsub:publish
``` 

##### Policies

```yaml
---
apiVersion: casbin.grepplabs.com/v1alpha1
kind: Rule
metadata:
  name: pubsub-publish
  labels:
    casbin.grepplabs.com/model: rbac
spec:
  ptype: "p"
  v0: "iam::p123:sa/user-42"
  v1: "pubsub:eu-central-1:p123:topics/orders"
  v2: "pubsub:publish"

```

##### Example Request

```text
POST /v1alpha/publish
Host: orders.example.com
Authorization: Bearer <token>

```

```json
{
  "acme/project/project.id": "p123",
  "sub": "user-42"
}
```

##### Derived Parameters

| Name        | Value     |
|-------------|-----------|
| `projectId` | `p123`    |
| `sub`       | `user-42` |
| `topicId`   | `orders`  |

##### Rendered Policy Attributes

| Attribute    | Value                                    |
|--------------|------------------------------------------|
| **Subject**  | `iam::p123:sa/user-42`                   |
| **Resource** | `pubsub:eu-central-1:p123:topics/orders` |
| **Action**   | `pubsub:publish`                         |

## Helm Chart

The project provides a Helm chart for easy deployment to Kubernetes.

### Configuration

The following table lists the configurable parameters of the casbin-traefik-forward-auth chart and their default values.

| Key                                          | Type   | Default                                                                                       | Description                                                                                                                                                         |
|----------------------------------------------|--------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `replicaCount`                               | int    | `1`                                                                                           | Number of replicas for the deployment.                                                                                                                              |
| `image.repository`                           | string | `ghcr.io/grepplabs/casbin-traefik-forward-auth`                                               | Image repository.                                                                                                                                                   |
| `image.pullPolicy`                           | string | `IfNotPresent`                                                                                | Image pull policy.                                                                                                                                                  |
| `image.tag`                                  | string | `""`                                                                                          | Overrides the image tag whose default is the chart appVersion.                                                                                                      |
| `imagePullSecrets`                           | list   | `[]`                                                                                          | Secrets to use for pulling images.                                                                                                                                  |
| `nameOverride`                               | string | `""`                                                                                          | Overrides the chart's name.                                                                                                                                         |
| `fullnameOverride`                           | string | `""`                                                                                          | Overrides the chart's full name.                                                                                                                                    |
| `serviceAccount.create`                      | bool   | `true`                                                                                        | Specifies whether a service account should be created.                                                                                                              |
| `serviceAccount.automount`                   | bool   | `true`                                                                                        | Automatically mount a ServiceAccount's API credentials.                                                                                                             |
| `serviceAccount.annotations`                 | object | `{}`                                                                                          | Annotations for the service account.                                                                                                                                |
| `serviceAccount.name`                        | string | `""`                                                                                          | The name of the service account to use. If not set and `serviceAccount.create` is true, a name is generated.                                                        |
| `podAnnotations`                             | object | `{}`                                                                                          | Annotations for the pod.                                                                                                                                            |
| `podLabels`                                  | object | `{}`                                                                                          | Labels for the pod.                                                                                                                                                 |
| `podSecurityContext`                         | object | `{}`                                                                                          | Pod security context.                                                                                                                                               |
| `securityContext`                            | object | `{}`                                                                                          | Container security context.                                                                                                                                         |
| `service.type`                               | string | `ClusterIP`                                                                                   | Service type.                                                                                                                                                       |
| `service.port`                               | int    | `80`                                                                                          | Service port.                                                                                                                                                       |
| `ingress.enabled`                            | bool   | `false`                                                                                       | Specifies whether an Ingress should be created.                                                                                                                     |
| `ingress.className`                          | string | `""`                                                                                          | Ingress class name.                                                                                                                                                 |
| `ingress.annotations`                        | object | `{}`                                                                                          | Annotations for the Ingress.                                                                                                                                        |
| `ingress.hosts`                              | list   | `[{"host":"chart-example.local","paths":[{"path":"/","pathType":"ImplementationSpecific"}]}]` | Ingress hosts.                                                                                                                                                      |
| `ingress.tls`                                | list   | `[]`                                                                                          | Ingress TLS configuration.                                                                                                                                          |
| `httpRoute.enabled`                          | bool   | `false`                                                                                       | Specifies whether an HTTPRoute should be created (requires Gateway API).                                                                                            |
| `httpRoute.annotations`                      | object | `{}`                                                                                          | Annotations for the HTTPRoute.                                                                                                                                      |
| `httpRoute.parentRefs`                       | list   | `[{"name":"gateway","sectionName":"http"}]`                                                   | Which Gateways this Route is attached to.                                                                                                                           |
| `httpRoute.hostnames`                        | list   | `["chart-example.local"]`                                                                     | Hostnames matching HTTP header.                                                                                                                                     |
| `httpRoute.rules`                            | list   | `[{"matches":[{"path":{"type":"PathPrefix","value":"/headers"}}]}]`                           | List of rules and filters applied.                                                                                                                                  |
| `resources`                                  | object | `{}`                                                                                          | Pod resource limits and requests.                                                                                                                                   |
| `livenessProbe`                              | object | `{"httpGet":{"path":"/healthz","port":"http"}}`                                               | Liveness probe configuration.                                                                                                                                       |
| `readinessProbe`                             | object | `{"httpGet":{"path":"/readyz","port":"http"}}`                                                | Readiness probe configuration.                                                                                                                                      |
| `autoscaling.enabled`                        | bool   | `false`                                                                                       | Specifies whether autoscaling should be enabled.                                                                                                                    |
| `autoscaling.minReplicas`                    | int    | `1`                                                                                           | Minimum number of replicas for autoscaling.                                                                                                                         |
| `autoscaling.maxReplicas`                    | int    | `100`                                                                                         | Maximum number of replicas for autoscaling.                                                                                                                         |
| `autoscaling.targetCPUUtilizationPercentage` | int    | `80`                                                                                          | Target CPU utilization percentage for autoscaling.                                                                                                                  |
| `extraVolumes`                               | list   | `[]`                                                                                          | Additional volumes on the output Deployment definition.                                                                                                             |
| `extraVolumeMounts`                          | list   | `[]`                                                                                          | Additional extraVolumeMounts on the output Deployment definition.                                                                                                   |
| `extraEnvFrom`                               | list   | `[]`                                                                                          | Additional environment variables from secrets or configmaps.                                                                                                        |
| `nodeSelector`                               | object | `{}`                                                                                          | Node selector for pod scheduling.                                                                                                                                   |
| `tolerations`                                | list   | `[]`                                                                                          | Tolerations for pod scheduling.                                                                                                                                     |
| `affinity`                                   | object | `{}`                                                                                          | Affinity for pod scheduling.                                                                                                                                        |
| `serviceMonitor.enabled`                     | bool   | `false`                                                                                       | If `true`, a `ServiceMonitor` resource will be created for Prometheus Operator scraping.                                                                            |
| `serviceMonitor.interval`                    | string | `"15s"`                                                                                       | Scrape interval used by Prometheus.                                                                                                                                 |
| `serviceMonitor.scrapeTimeout`               | string | `"10s"`                                                                                       | Scrape timeout used by Prometheus.                                                                                                                                  |
| `serviceMonitor.additionalLabels`            | object | `{}`                                                                                          | Extra labels to add to the `ServiceMonitor` metadata (for example `release: prometheus`).                                                                           |
| `serviceMonitor.namespace`                   | string | `""`                                                                                          | If set, the `ServiceMonitor` will select this namespace via `.spec.namespaceSelector.matchNames`. If empty, Prometheus is expected to scrape in the same namespace. |
| `serviceMonitor.relabelings`                 | list   | `[]`                                                                                          | List of `relabelings` applied to samples before ingestion.                                                                                                          |
| `serviceMonitor.metricRelabelings`           | list   | `[]`                                                                                          | List of `metricRelabelings` applied to scraped metrics.                                                                                                             |
| `application.env`                            | object | `{}`                                                                                          | Environment variables for the application.                                                                                                                          |
| `application.authRouteConfig`                | object | `{}`                                                                                          | Route configuration for the application.                                                                                                                            |
| `application.adapter.kube.namespace`         | string | `""`                                                                                          | Kubernetes namespace where Casbin policies are stored.                                                                                                              |


