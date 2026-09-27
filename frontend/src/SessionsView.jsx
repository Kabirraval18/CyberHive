import { useEffect, useMemo, useState } from 'react'
import {
  filterSessions,
} from './api'

function SessionsView({ onOpenInvestigation }) {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [sourceIp, setSourceIp] = useState('')
  const [behavior, setBehavior] = useState('')
  const [severity, setSeverity] = useState('')

  const loadSessions = async () => {
    try {
      setLoading(true)
      setError('')

      const response = await filterSessions({
        source_ip: sourceIp,
        behavior,
        severity,
      })

      if (!response.success) {
        throw new Error(
          response.error || 'Unable to load sessions',
        )
      }

      setSessions(
        Array.isArray(response.sessions)
          ? response.sessions
          : [],
      )
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load sessions',
      )
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false

    const initialLoad = async () => {
        await Promise.resolve()

        if (cancelled) {
        return
        }

        try {
        setLoading(true)
        setError('')

        const response = await filterSessions()

        if (cancelled) {
            return
        }

        if (!response.success) {
            throw new Error(
            response.error || 'Unable to load sessions',
            )
        }

        setSessions(
            Array.isArray(response.sessions)
            ? response.sessions
            : [],
        )
        } catch (err) {
        if (!cancelled) {
            setError(
            err instanceof Error
                ? err.message
                : 'Unable to load sessions',
            )
        }
        } finally {
        if (!cancelled) {
            setLoading(false)
        }
        }
    }

    initialLoad()

    return () => {
        cancelled = true
    }
    }, [])

  const behaviors = useMemo(() => {
    return [
      ...new Set(
        sessions
          .map((session) => session.behavior_label)
          .filter(Boolean),
      ),
    ].sort()
  }, [sessions])

  const formatDate = (value) => {
    if (!value) {
      return 'UNKNOWN'
    }

    const date = new Date(value)

    if (Number.isNaN(date.getTime())) {
      return 'UNKNOWN'
    }

    return new Intl.DateTimeFormat('en-IN', {
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZone: 'Asia/Kolkata',
    }).format(date)
  }

  const clearFilters = () => {
    setSourceIp('')
    setBehavior('')
    setSeverity('')

    setTimeout(() => {
      loadSessions()
    }, 0)
  }

  return (
    <section className="sessions-view">
      <div className="sessions-heading">
        <div>
          <span className="eyebrow">
            ATTACK ACTIVITY
          </span>

          <h1>Sessions</h1>

          <p>
            Review reconstructed honeypot sessions and open
            individual investigations.
          </p>
        </div>

        <span className="count-pill">
          {sessions.length}
        </span>
      </div>

      <div className="sessions-filters panel">
        <div className="sessions-filter-field">
          <label htmlFor="source-ip">
            SOURCE IP
          </label>

          <input
            id="source-ip"
            value={sourceIp}
            onChange={(event) =>
              setSourceIp(event.target.value)
            }
            placeholder="e.g. 127.0.0.1"
          />
        </div>

        <div className="sessions-filter-field">
          <label htmlFor="behavior">
            BEHAVIOR
          </label>

          <select
            id="behavior"
            value={behavior}
            onChange={(event) =>
              setBehavior(event.target.value)
            }
          >
            <option value="">
              All behaviors
            </option>

            {behaviors.map((item) => (
              <option
                key={item}
                value={item}
              >
                {item}
              </option>
            ))}
          </select>
        </div>

        <div className="sessions-filter-field">
          <label htmlFor="severity">
            SEVERITY
          </label>

          <select
            id="severity"
            value={severity}
            onChange={(event) =>
              setSeverity(event.target.value)
            }
          >
            <option value="">
              All severities
            </option>

            <option value="Low">
              Low
            </option>

            <option value="Medium">
              Medium
            </option>

            <option value="High">
              High
            </option>

            <option value="Critical">
              Critical
            </option>
          </select>
        </div>

        <div className="sessions-filter-actions">
          <button
            type="button"
            className="sessions-filter-button primary"
            onClick={loadSessions}
          >
            APPLY
          </button>

          <button
            type="button"
            className="sessions-filter-button"
            onClick={clearFilters}
          >
            CLEAR
          </button>
        </div>
      </div>

      {loading ? (
        <div className="sessions-state panel">
          <span className="eyebrow">
            SESSION INDEX
          </span>

          <h2>
            Loading sessions...
          </h2>
        </div>
      ) : error ? (
        <div className="sessions-state panel">
          <span className="eyebrow">
            SESSION INDEX
          </span>

          <h2>
            Unable to load sessions.
          </h2>

          <p>{error}</p>
        </div>
      ) : sessions.length === 0 ? (
        <div className="sessions-state panel">
          <span className="eyebrow">
            SESSION INDEX
          </span>

          <h2>
            No sessions match the selected filters.
          </h2>
        </div>
      ) : (
        <div className="session-table panel">
          <div className="session-table-header">
            <span>SESSION</span>
            <span>SOURCE</span>
            <span>BEHAVIOR</span>
            <span>RISK</span>
            <span>ACTIVITY</span>
            <span />
          </div>

          <div className="session-table-body">
            {sessions.map((session) => (
              <article
                className="session-table-row"
                key={session.id}
              >
                <div>
                  <strong className="session-id">
                    {session.session_id}
                  </strong>

                  <span>
                    {formatDate(session.start_time)}
                  </span>
                </div>

                <div>
                  <strong>
                    {session.source_ip || 'UNKNOWN'}
                  </strong>

                  <span>
                    {session.username || 'unknown user'}
                  </span>
                </div>

                <div>
                  <strong>
                    {session.behavior_label ||
                      'Not analyzed'}
                  </strong>

                  <span>
                    {session.protocol || 'unknown protocol'}
                  </span>
                </div>

                <div>
                  {session.risk ? (
                    <>
                      <strong
                        className={`risk-text risk-${String(
                          session.risk.severity || '',
                        ).toLowerCase()}`}
                      >
                        {session.risk.score}
                      </strong>

                      <span>
                        {session.risk.severity}
                      </span>
                    </>
                  ) : (
                    <>
                      <strong>—</strong>
                      <span>No score</span>
                    </>
                  )}
                </div>

                <div>
                  <strong>
                    {session.command_count || 0}
                  </strong>

                  <span>
                    command
                    {session.command_count === 1
                      ? ''
                      : 's'}
                  </span>
                </div>

                <div className="session-table-action">
                  <button
                    type="button"
                    onClick={() =>
                      onOpenInvestigation(
                        session.session_id,
                      )
                    }
                  >
                    INVESTIGATE →
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}
    </section>
  )
}

export default SessionsView