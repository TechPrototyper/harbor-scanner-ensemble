{{/*
Name of the chart (stable prefix for names/labels).
*/}}
{{- define "harbor-scanner-ensemble.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "harbor-scanner-ensemble.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart label value.
*/}}
{{- define "harbor-scanner-ensemble.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "harbor-scanner-ensemble.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-ensemble.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "harbor-scanner-ensemble.labels" -}}
helm.sh/chart: {{ include "harbor-scanner-ensemble.chart" . }}
{{ include "harbor-scanner-ensemble.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Adapter image reference (<repository>:<tag or appVersion>).
*/}}
{{- define "harbor-scanner-ensemble.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
Name of the ServiceAccount to use.
*/}}
{{- define "harbor-scanner-ensemble.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- printf "%s" (include "harbor-scanner-ensemble.fullname" .) -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Grype DB location env vars. Both point inside the writable grype-db
emptyDir so a read-only root filesystem is safe. Used by the init
container (grype db update) and inherited by the adapter (which passes
the process env to the grype child).
*/}}
{{- define "harbor-scanner-ensemble.dbEnv" -}}
- name: GRYPE_DB_CACHE_DIR
  value: {{ .Values.dbCacheDir | quote }}
- name: GRYPE_CHECK_FOR_APP_UPDATE
  value: "false"
{{- end -}}

{{/*
Environment for the adapter container: SCANNER_* from values.config plus the
engine DB location env vars.
*/}}
{{- define "harbor-scanner-ensemble.scannerEnv" -}}
- name: SCANNER_API_ADDR
  value: {{ .Values.config.apiAddr | quote }}
- name: SCANNER_SCAN_TIMEOUT
  value: {{ .Values.config.scanTimeout | quote }}
- name: SCANNER_JOB_TTL
  value: {{ .Values.config.jobTTL | quote }}
- name: SCANNER_REGISTRY_INSECURE_SKIP_TLS
  value: {{ .Values.config.registryInsecureSkipTLS | quote }}
- name: SCANNER_REGISTRY_USE_HTTP
  value: {{ .Values.config.registryUseHTTP | quote }}
- name: SCANNER_GRYPE_DB_AUTO_UPDATE
  value: {{ .Values.config.grypeDBAutoUpdate | quote }}
- name: SCANNER_PREFER_CVE
  value: {{ .Values.config.preferCVE | quote }}
- name: SCANNER_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: SCANNER_ENGINES
  value: {{ .Values.config.engines | quote }}
- name: SCANNER_ENGINE_TIMEOUT
  value: {{ .Values.config.engineTimeout | quote }}
- name: SCANNER_ALLOW_PARTIAL
  value: {{ .Values.config.allowPartial | quote }}
- name: SCANNER_PROVENANCE_PREFIX
  value: {{ .Values.config.provenancePrefix | quote }}
- name: SCANNER_DB_REFRESH_INTERVAL
  value: {{ .Values.config.dbRefreshInterval | quote }}
{{ include "harbor-scanner-ensemble.dbEnv" . }}
{{- if has "trivy" (splitList "," .Values.config.engines) }}
{{ include "harbor-scanner-ensemble.trivyEnv" . }}
{{- end -}}
{{- end -}}

{{/*
Trivy DB location env vars. Both point inside the writable trivy-db
emptyDir so a read-only root filesystem is safe. Used by the init
container (trivy db download) and inherited by the adapter (which passes
the process env to the trivy child).
*/}}
{{- define "harbor-scanner-ensemble.trivyEnv" -}}
- name: TRIVY_CACHE_DIR
  value: {{ .Values.trivyCacheDir | quote }}

{{- end -}}

{{/*
volumeMount for the Grype DB cache (writable emptyDir).
*/}}
{{- define "harbor-scanner-ensemble.dbMount" -}}
- name: grype-db
  mountPath: {{ .Values.dbCacheDir | quote }}
{{- end -}}

{{/*
volumeMount for the Trivy DB cache (writable emptyDir).
*/}}
{{- define "harbor-scanner-ensemble.trivyMount" -}}
- name: trivy-db
  mountPath: {{ .Values.trivyCacheDir | quote }}
{{- end -}}
