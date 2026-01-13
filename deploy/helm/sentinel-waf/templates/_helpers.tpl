{{/*
Expand the name of the chart.
*/}}
{{- define "sentinel-waf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sentinel-waf.fullname" -}}
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
{{- define "sentinel-waf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sentinel-waf.labels" -}}
helm.sh/chart: {{ include "sentinel-waf.chart" . }}
{{ include "sentinel-waf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sentinel
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sentinel-waf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentinel-waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: waf
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sentinel-waf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sentinel-waf.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image tag
*/}}
{{- define "sentinel-waf.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}
