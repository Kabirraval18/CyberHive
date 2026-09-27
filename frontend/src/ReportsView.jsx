import { useEffect, useState } from 'react'

function ReportsView() {
  const [sessions, setSessions] = useState([])
  const [selectedSession, setSelectedSession] =
    useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true

    const loadSessions = async () => {
      try {
        const response = await fetch(
          `/api/sessions?_=${Date.now()}`,
          {
            credentials: 'include',
            cache: 'no-store',
          },
        )

        if (!response.ok) {
          throw new Error(
            `Sessions API request failed (${response.status})`,
          )
        }

        const data = await response.json()

        if (!data.success) {
          throw new Error(
            data.error ||
              'Unable to load sessions',
          )
        }

        if (active) {
          const items = Array.isArray(
            data.sessions,
          )
            ? data.sessions
            : []

          setSessions(items)

          if (items.length > 0) {
            setSelectedSession(
              items[0].session_id,
            )
          }

          setError('')
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load sessions',
          )
        }
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadSessions()

    return () => {
      active = false
    }
  }, [])

  return (
    <section className="reports-view">
      <div className="reports-header">
        <div>
          <span className="eyebrow">
            SECURITY REPORTING
          </span>

          <h1>Evidence, structured.</h1>

          <p>
            Generate session-level reports,
            security summaries, and structured
            CSV exports directly from CyberHive
            telemetry.
          </p>
        </div>
      </div>

      {error && (
        <div className="reports-error panel">
          <strong>REPORT DATA UNAVAILABLE</strong>
          <span>{error}</span>
        </div>
      )}

      <div className="reports-grid">
        <article className="report-card panel">
          <div className="report-card-number">
            01
          </div>

          <span className="eyebrow">
            SESSION REPORT
          </span>

          <h2>Detailed session evidence.</h2>

          <p>
            Generate a PDF containing session
            details, event timeline, behavior,
            risk, threat intelligence, MITRE
            mappings, and recommendations.
          </p>

          <div className="report-control">
            <label htmlFor="session-report">
              SESSION
            </label>

            <select
              id="session-report"
              value={selectedSession}
              disabled={
                loading || sessions.length === 0
              }
              onChange={(event) =>
                setSelectedSession(
                  event.target.value,
                )
              }
            >
              {sessions.length === 0 ? (
                <option value="">
                  NO SESSIONS AVAILABLE
                </option>
              ) : (
                sessions.map((session) => (
                  <option
                    key={session.id}
                    value={session.session_id}
                  >
                    {session.session_id}
                  </option>
                ))
              )}
            </select>
          </div>

          <a
            className="report-button primary"
            href={
              selectedSession
                ? `/api/reports/session/${encodeURIComponent(
                    selectedSession,
                  )}.pdf`
                : undefined
            }
            target="_blank"
            rel="noreferrer"
            onClick={(event) => {
              if (!selectedSession) {
                event.preventDefault()
              }
            }}
          >
            GENERATE SESSION PDF →
          </a>
        </article>

        <article className="report-card panel">
          <div className="report-card-number">
            02
          </div>

          <span className="eyebrow">
            SECURITY SUMMARY
          </span>

          <h2>System-level findings.</h2>

          <p>
            Generate a summary PDF containing
            reporting information, activity
            trends, source activity, command
            patterns, behavior, risk, and MITRE
            findings.
          </p>

          <a
            className="report-button"
            href="/api/reports/summary.pdf"
            target="_blank"
            rel="noreferrer"
          >
            GENERATE SUMMARY PDF →
          </a>
        </article>

        <article className="report-card panel">
          <div className="report-card-number">
            03
          </div>

          <span className="eyebrow">
            DATA EXPORT
          </span>

          <h2>Structured session data.</h2>

          <p>
            Export session-level CyberHive
            information in CSV format for
            analysis, archival, or further
            processing.
          </p>

          <a
            className="report-button"
            href="/api/reports/sessions.csv"
          >
            EXPORT SESSIONS CSV →
          </a>
        </article>
      </div>

      <div className="reports-note panel">
        <span className="eyebrow">
          DATA PRINCIPLE
        </span>

        <p>
          Reports are generated from persisted
          CyberHive records. Missing enrichment
          remains missing rather than being
          replaced with fabricated information.
        </p>
      </div>
    </section>
  )
}

export default ReportsView