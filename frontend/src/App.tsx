import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { RequirePermission } from '@/components/RequirePermission'
import { ToastProvider } from '@/components/ui/toast'
import AppLayout from '@/layouts/AppLayout'
import { AuthProvider } from '@/lib/auth'
import { Permission } from '@/lib/permissions'
import AlertDetailPage from '@/pages/AlertDetailPage'
import AlertsPage from '@/pages/AlertsPage'
import AnalyticsPage from '@/pages/AnalyticsPage'
import AuditPage from '@/pages/AuditPage'
import DashboardPage from '@/pages/DashboardPage'
import DetectionsPage from '@/pages/DetectionsPage'
import EventDetailPage from '@/pages/EventDetailPage'
import EventsPage from '@/pages/EventsPage'
import IncidentDetailPage from '@/pages/IncidentDetailPage'
import IncidentsPage from '@/pages/IncidentsPage'
import InvestigatePage from '@/pages/InvestigatePage'
import LoginPage from '@/pages/LoginPage'
import ProfilePage from '@/pages/ProfilePage'
import UsersPage from '@/pages/UsersPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 401 is handled by the client's silent refresh, so retrying here would
      // just multiply requests during a genuine sign-out.
      retry: 1,
      refetchOnWindowFocus: true,
      staleTime: 15_000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <Routes>
              <Route path="/login" element={<LoginPage />} />

              <Route
                element={
                  <RequirePermission>
                    <AppLayout />
                  </RequirePermission>
                }
              >
                <Route
                  index
                  element={
                    <RequirePermission permission={Permission.DASHBOARD_READ}>
                      <DashboardPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="alerts"
                  element={
                    <RequirePermission permission={Permission.ALERT_READ}>
                      <AlertsPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="alerts/:alertId"
                  element={
                    <RequirePermission permission={Permission.ALERT_READ}>
                      <AlertDetailPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="incidents"
                  element={
                    <RequirePermission permission={Permission.INCIDENT_READ}>
                      <IncidentsPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="incidents/:incidentId"
                  element={
                    <RequirePermission permission={Permission.INCIDENT_READ}>
                      <IncidentDetailPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="events"
                  element={
                    <RequirePermission permission={Permission.EVENT_READ}>
                      <EventsPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="events/:eventId"
                  element={
                    <RequirePermission permission={Permission.EVENT_READ}>
                      <EventDetailPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="investigate"
                  element={
                    <RequirePermission permission={Permission.INVESTIGATION_READ}>
                      <InvestigatePage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="analytics"
                  element={
                    <RequirePermission permission={Permission.ANALYTICS_READ}>
                      <AnalyticsPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="detections"
                  element={
                    <RequirePermission permission={Permission.DETECTION_READ}>
                      <DetectionsPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="audit"
                  element={
                    <RequirePermission permission={Permission.AUDIT_READ}>
                      <AuditPage />
                    </RequirePermission>
                  }
                />
                <Route
                  path="users"
                  element={
                    <RequirePermission permission={Permission.USER_READ}>
                      <UsersPage />
                    </RequirePermission>
                  }
                />
                <Route path="profile" element={<ProfilePage />} />
              </Route>

              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
