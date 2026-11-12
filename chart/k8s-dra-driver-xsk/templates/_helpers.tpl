{{/* Fixed names: claims, docs and tooling reference these resources
directly, so names must not vary with the release name. */}}
{{- define "k8s-dra-driver-xsk.name" -}}
{{- default "dra-xsk-driver" .Values.nameOverride -}}
{{- end -}}

{{- define "k8s-dra-driver-xsk.fullname" -}}
{{- default "dra-xsk-driver" .Values.fullnameOverride -}}
{{- end -}}

{{- define "k8s-dra-driver-xsk.labels" -}}
app: {{ include "k8s-dra-driver-xsk.fullname" . }}
app.kubernetes.io/name: {{ include "k8s-dra-driver-xsk.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "k8s-dra-driver-xsk.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end -}}
