import { useEffect, useMemo, useState } from 'react'

function AlertsView({
  onOpenInvestigation,
}) {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [search, setSearch] = useState('')
  const [acknowledgingId, setAcknowledgingId] =
    useState(null)

  useEffect(() => {
    let active = true
    let timeoutId = null
    let firstLoad = true

    const loadAlerts = async () => {
      try {
        if (firstLoad) {
          setLoading(true)
          setError('')
        }

        const params = new URLSearchParams()

        if (filter === 'acknowledged') {
        params.set('acknowledged', 'true')
        }

        if (filter === 'unacknowledged') {
        params.set('acknowledged', 'false')
        }

        params.set('_', Date.now().toString())

        const response = await fetch(
        `/api/alerts?${params.toString()}`,
        {
            credentials: 'include',
            cache: 'no-store',
        },
        )

        if (!response.ok) {
          throw new Error(
            `Alerts API request failed (${response.status})`,
          )
        }

        const data = await response.json()

        if (!data.success) {
          throw new Error(
            data.error ||
              'Unable to load alerts',
          )
        }

        if (active) {
          setAlerts(
            Array.isArray(data.alerts)
              ? data.alerts
              : [],
          )
          setError('')
        }
      } catch (err) {
        if (active && firstLoad) {
          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load alerts',
          )
        }
      } finally {
        if (active) {
          if (firstLoad) {
            setLoading(false)
          }

          firstLoad = false

          timeoutId = window.setTimeout(
            loadAlerts,
            5000,
          )
        }
      }
    }

    loadAlerts()

    return () => {
      active = false

      if (timeoutId !== null) {
        window.clearTimeout(timeoutId)
      }
    }
  }, [filter])

  const filteredAlerts = useMemo(() => {
    const normalizedSearch =
      search.trim().toLowerCase()

    return alerts.filter((alert) => {
      const severityMatches =
        severity === 'all' ||
        String(alert.severity || '')
          .toLowerCase() ===
          severity.toLowerCase()

      if (!severityMatches) {
        return false
      }

      if (!normalizedSearch) {
        return true
      }

      return [
        alert.session_id,
        alert.source_ip,
        alert.title,
        alert.message,
        alert.severity,
      ]
        .filter(Boolean)
        .some((value) =>
          String(value)
            .toLowerCase()
            .includes(normalizedSearch),
        )
    })
  }, [alerts, search, severity])

  const unacknowledgedCount =
    alerts.filter(
      (alert) => !alert.acknowledged,
    ).length

  const severityCounts = {
    Critical: alerts.filter(
      (alert) =>
        alert.severity === 'Critical',
    ).length,

    High: alerts.filter(
      (alert) => alert.severity === 'High',
    ).length,

    Medium: alerts.filter(
      (alert) =>
        alert.severity === 'Medium',
    ).length,

    Low: alerts.filter(
      (alert) => alert.severity === 'Low',
    ).length,
  }

  const acknowledgeAlert = async (alertId) => {
    try {
      setAcknowledgingId(alertId)

      const response = await fetch(
        `/api/alerts/${alertId}/acknowledge`,
        {
          method: 'POST',
          credentials: 'include',
        },
      )

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(
          data.error ||
            'Unable to acknowledge alert',
        )
      }

      setAlerts((current) =>
        current.map((alert) =>
          alert.id === alertId
            ? data.alert
            : alert,
        ),
      )
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to acknowledge alert',
      )
    } finally {
      setAcknowledgingId(null)
    }
  }

  const formatDate = (value) => {
    if (!value) {
      return 'UNKNOWN'
    }

    const date = new Date(value)

    if (Number.isNaN(date.getTime())) {
      return 'UNKNOWN'
    }

    return new Intl.DateTimeFormat(
      'en-IN',
      {
        dateStyle: 'medium',
        timeStyle: 'short',
        timeZone: 'Asia/Kolkata',
      },
    ).format(date)
  }

  const severityClass = (value) =>
    `alert-severity alert-severity-${String(
      value || 'unknown',
    ).toLowerCase()}`

  return (
    <section className="alerts-view">
      <div className="alerts-header">
        <div>
          <span className="eyebrow">
            SECURITY ALERTS
          </span>

          <h1>Persistent threat signals.</h1>

          <p>
            Review threshold-triggered security
            alerts generated from observed
            CyberHive sessions.
          </p>
        </div>

        <div className="alerts-header-status">
          <span>UNACKNOWLEDGED</span>

          <strong>
            {unacknowledgedCount}
          </strong>
        </div>
      </div>

      <div className="alerts-summary-grid">
        <SummaryCard
          label="TOTAL"
          value={alerts.length}
        />

        <SummaryCard
          label="CRITICAL"
          value={severityCounts.Critical}
        />

        <SummaryCard
          label="HIGH"
          value={severityCounts.High}
        />

        <SummaryCard
          label="MEDIUM"
          value={severityCounts.Medium}
        />
      </div>

      <div className="alerts-toolbar panel">
        <div className="alerts-filter-group">
          <button
            type="button"
            className={
              filter === 'all'
                ? 'alert-filter active'
                : 'alert-filter'
            }
            onClick={() => setFilter('all')}
          >
            ALL
          </button>

          <button
            type="button"
            className={
              filter === 'unacknowledged'
                ? 'alert-filter active'
                : 'alert-filter'
            }
            onClick={() =>
              setFilter('unacknowledged')
            }
          >
            OPEN
          </button>

          <button
            type="button"
            className={
              filter === 'acknowledged'
                ? 'alert-filter active'
                : 'alert-filter'
            }
            onClick={() =>
              setFilter('acknowledged')
            }
          >
            ACKNOWLEDGED
          </button>
        </div>

        <div className="alerts-control-group">
          <select
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value)
            }
            className="alerts-select"
          >
            <option value="all">
              ALL SEVERITIES
            </option>

            <option value="Critical">
              CRITICAL
            </option>

            <option value="High">
              HIGH
            </option>

            <option value="Medium">
              MEDIUM
            </option>

            <option value="Low">
              LOW
            </option>
          </select>

          <input
            type="search"
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
            placeholder="Search IP, session, reason..."
            className="alerts-search"
          />
        </div>
      </div>

      {error && (
        <div className="alerts-error panel">
          <strong>
            ALERT DATA UNAVAILABLE
          </strong>

          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="alerts-state panel">
          <span className="eyebrow">
            SECURITY ALERTS
          </span>

          <h2>
            Loading alert history...
          </h2>

          <p>
            Reading persistent alert records
            from the CyberHive backend.
          </p>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="alerts-state panel">
          <span className="eyebrow">
            NO MATCHING ALERTS
          </span>

          <h2>
            No alerts match the current view.
          </h2>

          <p>
            Change the acknowledgement,
            severity, or search filters.
          </p>
        </div>
      ) : (
        <div className="alerts-list">
          {filteredAlerts.map((alert) => (
            <article
              key={alert.id}
              className={
                alert.acknowledged
                  ? 'alert-card panel acknowledged'
                  : 'alert-card panel'
              }
            >
              <div className="alert-card-top">
                <div className="alert-card-heading">
                  <span className="alert-id">
                    ALERT #
                    {String(alert.id).padStart(
                      3,
                      '0',
                    )}
                  </span>

                  <span
                    className={severityClass(
                      alert.severity,
                    )}
                  >
                    {alert.severity ||
                      'UNKNOWN'}
                  </span>

                  {alert.acknowledged && (
                    <span className="alert-status acknowledged">
                      ACKNOWLEDGED
                    </span>
                  )}
                </div>

                <time>
                  {formatDate(
                    alert.created_at,
                  )}
                </time>
              </div>

              <div className="alert-card-main">
                <div className="alert-card-copy">
                  <h2>
                    {alert.title ||
                      'Security alert'}
                  </h2>

                  <p>
                    {alert.message ||
                      'No alert message available.'}
                  </p>

                  <div className="alert-risk-explanation">
                    This score records the session risk when the
                    alert was created. The current session risk may
                    change as additional telemetry is processed.
                  </div>

                </div>

                <div className="alert-risk">
                  <span>
                    RISK AT TRIGGER
                  </span>

                  <strong>
                    {alert.risk_score}
                  </strong>

                  <small>
                    / 100
                  </small>

                  <em>
                    Historical alert score
                  </em>
                </div>
              </div>

              <div className="alert-facts">
                <AlertFact
                  label="SOURCE IP"
                  value={
                    alert.source_ip ||
                    'UNKNOWN'
                  }
                  mono
                />

                <AlertFact
                  label="SESSION"
                  value={
                    alert.session_id ||
                    'UNKNOWN'
                  }
                  mono
                />

                <AlertFact
                  label="CREATED"
                  value={formatDate(
                    alert.created_at,
                  )}
                />

                <AlertFact
                  label="STATUS"
                  value={
                    alert.acknowledged
                      ? 'ACKNOWLEDGED'
                      : 'OPEN'
                  }
                />
              </div>

              <div className="alert-actions">
                <button
                  type="button"
                  className="alert-action primary"
                  onClick={() =>
                    onOpenInvestigation(
                      alert.session_id,
                    )
                  }
                >
                  INVESTIGATE →
                </button>

                {!alert.acknowledged && (
                  <button
                    type="button"
                    className="alert-action"
                    disabled={
                      acknowledgingId ===
                      alert.id
                    }
                    onClick={() =>
                      acknowledgeAlert(
                        alert.id,
                      )
                    }
                  >
                    {acknowledgingId ===
                    alert.id
                      ? 'ACKNOWLEDGING...'
                      : 'ACKNOWLEDGE'}
                  </button>
                )}
              </div>

              {alert.acknowledged_at && (
                <div className="alert-acknowledged-info">
                  Acknowledged{' '}
                  {formatDate(
                    alert.acknowledged_at,
                  )}
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </section>
  )
}

function SummaryCard({
  label,
  value,
}) {
  return (
    <div className="alert-summary-card panel">
      <span>{label}</span>

      <strong>{value}</strong>
    </div>
  )
}

function AlertFact({
  label,
  value,
  mono = false,
}) {
  return (
    <div className="alert-fact">
      <span>{label}</span>

      <strong
        className={
          mono ? 'alert-fact-mono' : ''
        }
      >
        {value}
      </strong>
    </div>
  )
}

export default AlertsView