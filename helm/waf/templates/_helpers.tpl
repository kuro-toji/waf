{{- include "waf.deployment" . -}}
{{- include "waf.service" . -}}
{{- include "waf.configmap" . -}}
{{- include "waf.rules.configmap" . -}}