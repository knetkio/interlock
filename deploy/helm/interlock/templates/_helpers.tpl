{{/*
Expand the name of the chart.
*/}}
{{- define "interlock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "interlock.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "interlock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create an image reference, preferring digest-pinned releases when provided.
With neither a digest nor a tag, the image is the chart's own appVersion, which
the release workflow sets to the version it publishes, so a chart never pulls
an image older than itself.
*/}}
{{- define "interlock.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end }}

{{/*
Image pull secrets, emitted only when the operator sets any.

Included by every workload, the migration Job included: it is a pre-install
hook that pulls the same image, so omitting it there fails the release before
anything else is applied.
*/}}
{{- define "interlock.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Redis URL as an environment variable, sourced from a Secret when one is set.

A managed Redis carries its password inside the URL, and the ConfigMap is
plaintext. When `redis.existingSecret` is set the ConfigMap omits the key
entirely and this supplies it instead; container `env` wins over `envFrom`
either way, but leaving the key out of the ConfigMap is what keeps the
credential out of `kubectl get configmap -o yaml`.
*/}}
{{- define "interlock.redisEnv" -}}
{{- if .Values.redis.existingSecret }}
- name: INTERLOCK_REDIS__URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret }}
      key: {{ .Values.redis.secretUrlKey }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "interlock.labels" -}}
helm.sh/chart: {{ include "interlock.chart" . }}
{{ include "interlock.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "interlock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "interlock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Pod annotations for every long-running workload.

Configuration reaches the containers through `envFrom`, which is read once when
a container starts. Without something on the pod template that changes with
the rendered ConfigMap, `helm upgrade` rewrites the ConfigMap, reports success
and rolls nothing, so the new value is invisible to running pods until someone
restarts them by hand. The checksum is computed from the rendered template, not
from a live lookup: the ConfigMap is itself a pre-install/pre-upgrade hook that
Helm recreates on every upgrade.

Secrets are deliberately not hashed. Production Secrets are referenced by name
and never rendered by this chart, and hashing the ones it can create would put
a digest of inline credentials in pod metadata. Rotating a Secret, or anything
supplied through extraEnvFrom, still needs a `kubectl rollout restart`.
*/}}
{{- define "interlock.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}

{{/* Shared settings and file references; secret values never enter rendered YAML. */}}
{{- define "interlock.fabricEnv" -}}
{{- if .Values.fabric.enabled }}
{{- $refs := dict }}
{{- range .Values.fabric.keyVersions }}
{{- $_ := set $refs . (printf "file:///run/secrets/fabric/key-%s" .) }}
{{- end }}
- name: INTERLOCK_FABRIC__ACTIVE_KEY_VERSION
  value: {{ .Values.fabric.activeKeyVersion | quote }}
- name: INTERLOCK_FABRIC__KEY_REFS
  value: {{ $refs | toJson | quote }}
{{- if .Values.fabric.oauthClientId }}
- name: INTERLOCK_FABRIC__OAUTH_CLIENT_ID
  value: {{ .Values.fabric.oauthClientId | quote }}
- name: INTERLOCK_FABRIC__OAUTH_REDIRECT_URI
  value: {{ required "fabric.oauthRedirectUri is required with OAuth" .Values.fabric.oauthRedirectUri | quote }}
- name: INTERLOCK_FABRIC__OAUTH_ALLOWED_TENANTS
  value: {{ .Values.fabric.oauthAllowedTenants | toJson | quote }}
{{- if .Values.fabric.oauthClientSecretKey }}
- name: INTERLOCK_FABRIC__OAUTH_CLIENT_SECRET_REF
  value: {{ printf "file:///run/secrets/fabric/%s" .Values.fabric.oauthClientSecretKey | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
