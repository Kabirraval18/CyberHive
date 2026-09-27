const API_BASE = ''

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      ...(options.body
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...(options.headers || {}),
    },
    cache: options.cache || 'no-store',
  })

  const responseData = await response.json().catch(() => null)

  if (!response.ok) {
    const error = new Error(
      responseData?.error ||
        `Request failed (${response.status})`,
    )

    error.status = response.status
    error.data = responseData

    throw error
  }

  return responseData
}

// ------------------------------------------------------
// Authentication
// ------------------------------------------------------

export async function getCurrentUser() {
  return apiRequest('/api/auth/me')
}

export async function login(username, password) {
  return apiRequest('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      username,
      password,
    }),
  })
}

export async function logout() {
  return apiRequest('/api/auth/logout', {
    method: 'POST',
  })
}

// ------------------------------------------------------
// Dashboard
// ------------------------------------------------------

export async function getDashboard() {
  return apiRequest(
    `/api/dashboard?_=${Date.now()}`,
  )
}

export async function getActivity() {
  return apiRequest(
    `/api/analytics/activity?_=${Date.now()}`,
  )
}

export async function getStats() {
  return apiRequest('/api/stats')
}

export async function getSettings() {
  return apiRequest(`/api/settings?_=${Date.now()}`)
}

// ------------------------------------------------------
// Sessions
// ------------------------------------------------------

export async function getSessions() {
  return apiRequest('/api/sessions')
}

export async function filterSessions(params = {}) {
  const searchParams = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.set(key, value)
    }
  })

  const query = searchParams.toString()

  return apiRequest(
    `/api/sessions/filter${query ? `?${query}` : ''}`,
  )
}

export async function getInvestigation(sessionId) {
  return apiRequest(
    `/api/sessions/by-session-id/${encodeURIComponent(
      sessionId,
    )}/investigation`,
  )
}

// ------------------------------------------------------
// Intelligence
// ------------------------------------------------------

export async function getRisk(sessionId) {
  return apiRequest(
    `/api/risk/${encodeURIComponent(sessionId)}`,
  )
}

export async function getMitre(sessionId) {
  return apiRequest(
    `/api/mitre/${encodeURIComponent(sessionId)}`,
  )
}

export async function getRecommendations(sessionId) {
  return apiRequest(
    `/api/recommendations/${encodeURIComponent(sessionId)}`,
  )
}

export async function getThreatIntelligenceStatus() {
  return apiRequest(
    '/api/threat-intelligence/status',
  )
}

export async function getAbuseIpDb(ip, refresh = false) {
  const params = new URLSearchParams({
    ip,
  })

  if (refresh) {
    params.set('refresh', 'true')
  }

  return apiRequest(
    `/api/threat-intelligence/abuseipdb?${params.toString()}`,
  )
}

export async function getVirusTotal(ip, refresh = false) {
  const params = new URLSearchParams({
    ip,
  })

  if (refresh) {
    params.set('refresh', 'true')
  }

  return apiRequest(
    `/api/threat-intelligence/virustotal?${params.toString()}`,
  )
}

// ------------------------------------------------------
// Alerts
// ------------------------------------------------------

export async function getAlerts(params = {}) {
  const searchParams = new URLSearchParams()

  Object.entries(params).forEach(([key, value]) => {
    if (
      value !== undefined &&
      value !== null &&
      value !== ''
    ) {
      searchParams.set(key, value)
    }
  })

  const query = searchParams.toString()

  return apiRequest(
    `/api/alerts${query ? `?${query}` : ''}`,
  )
}

export async function acknowledgeAlert(alertId) {
  return apiRequest(
    `/api/alerts/${encodeURIComponent(alertId)}/acknowledge`,
    {
      method: 'POST',
    },
  )
}

// ------------------------------------------------------
// Analytics
// ------------------------------------------------------

export async function getSecurityAnalytics() {
  return apiRequest('/api/analytics/security')
}

// ------------------------------------------------------
// Reports
// ------------------------------------------------------

export function getSessionReportUrl(sessionId) {
  return `/api/reports/session/${encodeURIComponent(
    sessionId,
  )}.pdf`
}

export function getSummaryReportUrl() {
  return '/api/reports/summary.pdf'
}

export function getSessionsCsvUrl() {
  return '/api/reports/sessions.csv'
}

// ------------------------------------------------------

export { apiRequest }