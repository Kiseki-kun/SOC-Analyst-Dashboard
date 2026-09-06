import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { qs, request } from '@/lib/api'
import type {
  Alert,
  AlertDetail,
  AnalyticsOverview,
  AppUser,
  AuditLogEntry,
  DashboardSummary,
  DetectionRule,
  IOC,
  Incident,
  IncidentDetail,
  IPInvestigation,
  Page,
  SecurityEvent,
  SecurityEventDetail,
} from '@/types/api'

/** Data that changes as telemetry arrives; short stale time keeps it live. */
const LIVE = { staleTime: 10_000, refetchInterval: 20_000 }

export function useDashboardSummary() {
  return useQuery({
    queryKey: ['analytics', 'summary'],
    queryFn: () => request<DashboardSummary>('/analytics/summary'),
    ...LIVE,
  })
}

export function useAnalyticsOverview(hours: number, days: number) {
  return useQuery({
    queryKey: ['analytics', 'overview', hours, days],
    queryFn: () => request<AnalyticsOverview>(`/analytics/overview${qs({ hours, days })}`),
    ...LIVE,
  })
}

export function useEvents(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: () => request<Page<SecurityEvent>>(`/events${qs(params)}`),
    ...LIVE,
  })
}

export function useEvent(id: string | undefined) {
  return useQuery({
    queryKey: ['event', id],
    queryFn: () => request<SecurityEventDetail>(`/events/${id}`),
    enabled: Boolean(id),
  })
}

export function useAlerts(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => request<Page<Alert>>(`/alerts${qs(params)}`),
    ...LIVE,
  })
}

export function useAlert(id: string | undefined) {
  return useQuery({
    queryKey: ['alert', id],
    queryFn: () => request<AlertDetail>(`/alerts/${id}`),
    enabled: Boolean(id),
  })
}

export function useIncidents(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['incidents', params],
    queryFn: () => request<Page<Incident>>(`/incidents${qs(params)}`),
    ...LIVE,
  })
}

export function useIncident(id: string | undefined) {
  return useQuery({
    queryKey: ['incident', id],
    queryFn: () => request<IncidentDetail>(`/incidents/${id}`),
    enabled: Boolean(id),
  })
}

export function useIpInvestigation(ip: string | undefined) {
  return useQuery({
    queryKey: ['investigation', ip],
    queryFn: () => request<IPInvestigation>(`/investigations/ip/${ip}`),
    enabled: Boolean(ip),
    retry: false,
  })
}

export function useDetectionRules() {
  return useQuery({
    queryKey: ['detection-rules'],
    queryFn: () => request<DetectionRule[]>('/detections/rules'),
  })
}

export function useIocs(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['iocs', params],
    queryFn: () => request<Page<IOC>>(`/detections/iocs${qs(params)}`),
  })
}

export function useAuditLog(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['audit', params],
    queryFn: () => request<Page<AuditLogEntry>>(`/audit${qs(params)}`),
  })
}

export function useAuditActions() {
  return useQuery({
    queryKey: ['audit-actions'],
    queryFn: () => request<string[]>('/audit/actions'),
    staleTime: 300_000,
  })
}

export function useUsers(params: Record<string, unknown>) {
  return useQuery({
    queryKey: ['users', params],
    queryFn: () => request<Page<AppUser>>(`/users${qs(params)}`),
  })
}

/* ------------------------------------------------------------- mutations */

/**
 * Invalidate everything an alert change can affect.
 *
 * Deliberately broad: an alert status change moves dashboard counters and
 * analytics too, and a stale "12 open alerts" tile after closing one is the
 * kind of small wrongness that erodes trust in the whole console.
 */
function useAlertInvalidation() {
  const queryClient = useQueryClient()
  return () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['alert'] })
    queryClient.invalidateQueries({ queryKey: ['analytics'] })
  }
}

export function useUpdateAlertStatus(alertId: string) {
  const invalidate = useAlertInvalidation()
  return useMutation({
    mutationFn: (body: { status: string; resolution_note?: string | null }) =>
      request<AlertDetail>(`/alerts/${alertId}/status`, { method: 'PATCH', body }),
    onSuccess: invalidate,
  })
}

export function useAssignAlert(alertId: string) {
  const invalidate = useAlertInvalidation()
  return useMutation({
    mutationFn: (assigneeId: string | null) =>
      request<AlertDetail>(`/alerts/${alertId}/assign`, {
        method: 'PATCH',
        body: { assignee_id: assigneeId },
      }),
    onSuccess: invalidate,
  })
}

export function useAddAlertNote(alertId: string) {
  const invalidate = useAlertInvalidation()
  return useMutation({
    mutationFn: (body: string) =>
      request(`/alerts/${alertId}/notes`, { method: 'POST', body: { body } }),
    onSuccess: invalidate,
  })
}

function useIncidentInvalidation() {
  const queryClient = useQueryClient()
  return () => {
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
    queryClient.invalidateQueries({ queryKey: ['incident'] })
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['alert'] })
    queryClient.invalidateQueries({ queryKey: ['analytics'] })
  }
}

export function useCreateIncident() {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<IncidentDetail>('/incidents', { method: 'POST', body }),
    onSuccess: invalidate,
  })
}

export function useUpdateIncident(incidentId: string) {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<IncidentDetail>(`/incidents/${incidentId}`, { method: 'PATCH', body }),
    onSuccess: invalidate,
  })
}

export function useAssignIncident(incidentId: string) {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (assigneeId: string | null) =>
      request<IncidentDetail>(`/incidents/${incidentId}/assign`, {
        method: 'PATCH',
        body: { assignee_id: assigneeId },
      }),
    onSuccess: invalidate,
  })
}

export function useAddIncidentNote(incidentId: string) {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (body: string) =>
      request(`/incidents/${incidentId}/notes`, { method: 'POST', body: { body } }),
    onSuccess: invalidate,
  })
}

export function useSimulateResponse(incidentId: string) {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (body: { action_type: string; target: string; note?: string }) =>
      request(`/incidents/${incidentId}/response-actions`, { method: 'POST', body }),
    onSuccess: invalidate,
  })
}

export function useLinkAlertToIncident(alertId: string) {
  const invalidate = useIncidentInvalidation()
  return useMutation({
    mutationFn: (incidentId: string | null) =>
      request<AlertDetail>(`/alerts/${alertId}/incident`, {
        method: 'PATCH',
        body: { incident_id: incidentId },
      }),
    onSuccess: invalidate,
  })
}

export function useUpdateDetectionRule(ruleId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<DetectionRule>(`/detections/rules/${ruleId}`, { method: 'PATCH', body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['detection-rules'] }),
  })
}

export function useCreateIoc() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { ioc_type: string; value: string; description: string }) =>
      request<IOC>('/detections/iocs', { method: 'POST', body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['iocs'] }),
  })
}

export function useUpdateIoc(iocId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: { active?: boolean; description?: string }) =>
      request<IOC>(`/detections/iocs/${iocId}`, { method: 'PATCH', body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['iocs'] }),
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<AppUser>('/users', { method: 'POST', body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useUpdateUser(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      request<AppUser>(`/users/${userId}`, { method: 'PATCH', body }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: (body: { current_password: string; new_password: string }) =>
      request('/auth/change-password', { method: 'POST', body }),
  })
}
