import { useEffect, useState } from 'react'
import { getInvestigation } from './api'

function InvestigationView({
  sessionId,
  onBack,
}) {
  const [investigation, setInvestigation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false

    const loadInvestigation = async () => {
      if (!sessionId) {
        return
      }

      try {
        setLoading(true)
        setError('')

        const response = await getInvestigation(sessionId)

        if (cancelled) {
          return
        }

        if (!response.success) {
          throw new Error(
            response.error ||
              'Unable to load investigation',
          )
        }

        setInvestigation(response)
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load investigation',
          )
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadInvestigation()

    return () => {
      cancelled = true
    }
  }, [sessionId])

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
      timeStyle: 'medium',
      timeZone: 'Asia/Kolkata',
    }).format(date)
  }

  const formatDuration = (value) => {
    if (
      value === null ||
      value === undefined ||
      Number.isNaN(Number(value))
    ) {
      return 'UNKNOWN'
    }

    const seconds = Number(value)

    if (seconds < 60) {
      return `${seconds.toFixed(1)}s`
    }

    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = Math.round(seconds % 60)

    return `${minutes}m ${remainingSeconds}s`
  }

  const getRiskClass = (severity) => {
    return `investigation-risk investigation-risk-${String(
      severity || '',
    ).toLowerCase()}`
  }

  if (loading) {
    return (
      <section className="investigation-view">
        <div className="investigation-state panel">
          <span className="eyebrow">
            SESSION INVESTIGATION
          </span>

          <h1>Loading investigation...</h1>

          <p>
            Reconstructing the session intelligence chain.
          </p>
        </div>
      </section>
    )
  }

  if (error) {
    return (
      <section className="investigation-view">
        <button
          type="button"
          className="back-button"
          onClick={onBack}
        >
          ← BACK TO SESSIONS
        </button>

        <div className="investigation-state panel">
          <span className="eyebrow">
            INVESTIGATION ERROR
          </span>

          <h1>
            Unable to load investigation.
          </h1>

          <p>{error}</p>
        </div>
      </section>
    )
  }

  if (!investigation) {
    return null
  }

  const session = investigation.session || {}
  const analysis = investigation.analysis || {}
  const risk = investigation.risk || null

  const mitre = Array.isArray(investigation.mitre)
    ? investigation.mitre
    : []

  const recommendations = Array.isArray(
    investigation.recommendations,
  )
    ? investigation.recommendations
    : []

  const threatIntelligence = Array.isArray(
    investigation.threat_intelligence,
  )
    ? investigation.threat_intelligence
    : []

  const events = Array.isArray(investigation.events)
    ? investigation.events
    : []

  const commands = Array.isArray(
    investigation.commands,
  )
    ? investigation.commands
    : []

  const authenticationEvents = Array.isArray(
    investigation.authentication_events,
  )
    ? investigation.authentication_events
    : []

  const contributingFactors = Array.isArray(
    risk?.contributing_factors,
  )
    ? risk.contributing_factors
    : []

  const behaviorLabel =
    analysis.behavior_label ||
    analysis.behavior ||
    session.behavior_label ||
    'Not analyzed'

  const behaviorConfidence =
    analysis.behavior_confidence ??
    analysis.confidence

  const automationProfile =
    analysis.automation_profile ||
    analysis.automation ||
    'Not available'

  const cluster =
    analysis.cluster ||
    analysis.cluster_label ||
    'Not assigned'

  const anomaly =
    analysis.anomaly_score ??
    analysis.anomaly ??
    null

  return (
    <section className="investigation-view">
      <div className="investigation-header">
        <div>
          <button
            type="button"
            className="back-button"
            onClick={onBack}
          >
            ← BACK TO SESSIONS
          </button>

          <span className="eyebrow">
            SESSION INVESTIGATION
          </span>

          <h1>
            {session.session_id || sessionId}
          </h1>

          <p>
            Evidence reconstruction for a single observed
            honeypot session.
          </p>
        </div>

        {risk && (
          <div
            className={getRiskClass(
              risk.severity,
            )}
          >
            <span>RISK</span>

            <strong>
              {risk.score}
            </strong>

            <small>
              {risk.severity || 'UNKNOWN'}
            </small>
          </div>
        )}
      </div>

      <div className="investigation-grid">
        {/* -------------------------------------------------
            SESSION INFORMATION
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                SESSION
              </span>

              <h2>Session information</h2>
            </div>
          </div>

          <div className="investigation-facts">
            <Fact
              label="SESSION ID"
              value={session.session_id || sessionId}
              mono
            />

            <Fact
              label="SOURCE IP"
              value={session.source_ip || 'UNKNOWN'}
              mono
            />

            <Fact
              label="PROTOCOL"
              value={session.protocol || 'UNKNOWN'}
            />

            <Fact
              label="USERNAME"
              value={session.username || 'UNKNOWN'}
            />

            <Fact
              label="START TIME"
              value={formatDate(session.start_time)}
            />

            <Fact
              label="END TIME"
              value={formatDate(session.end_time)}
            />

            <Fact
              label="DURATION"
              value={formatDuration(session.duration)}
            />

            <Fact
              label="COMMAND COUNT"
              value={session.command_count ?? 0}
            />

            <Fact
              label="AUTHENTICATION"
              value={
                session.authentication_result ||
                'UNKNOWN'
              }
            />
          </div>
        </article>

        {/* -------------------------------------------------
            BEHAVIOR
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                BEHAVIORAL ANALYSIS
              </span>

              <h2>Observed behavior</h2>
            </div>
          </div>

          <div className="behavior-primary">
            <span>BEHAVIOR LABEL</span>

            <strong>
              {behaviorLabel}
            </strong>
          </div>

          <div className="investigation-facts compact">
            <Fact
              label="CONFIDENCE"
              value={
                behaviorConfidence === null ||
                behaviorConfidence === undefined
                  ? 'UNKNOWN'
                  : `${(
                      Number(behaviorConfidence) <= 1
                        ? Number(
                            behaviorConfidence,
                          ) * 100
                        : Number(
                            behaviorConfidence,
                          )
                    ).toFixed(1)}%`
              }
            />

            <Fact
              label="AUTOMATION PROFILE"
              value={automationProfile}
            />

            <Fact
              label="CLUSTER"
              value={cluster}
            />

            <Fact
              label="ANOMALY"
              value={
                anomaly === null
                  ? 'UNKNOWN'
                  : anomaly
              }
            />
          </div>
        </article>

        {/* -------------------------------------------------
            RISK
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                RISK ENGINE
              </span>

              <h2>Risk assessment</h2>
            </div>

            {risk && (
              <span
                className={getRiskClass(
                  risk.severity,
                )}
              >
                {risk.severity}
              </span>
            )}
          </div>

          {risk ? (
            <>
              <div className="risk-score-large">
                <strong>
                  {risk.score}
                </strong>

                <span>
                  / 100
                </span>
              </div>

              <div className="risk-bar">
                <span
                  style={{
                    width: `${Math.max(
                      0,
                      Math.min(
                        100,
                        Number(risk.score) || 0,
                      ),
                    )}%`,
                  }}
                />
              </div>

              <span className="risk-version">
                SCORING VERSION{' '}
                {risk.scoring_version || 'UNKNOWN'}
              </span>

              <div className="factor-list">
                {contributingFactors.length === 0 ? (
                  <EmptyInline
                    text="No contributing risk factors recorded."
                  />
                ) : (
                  contributingFactors.map(
                    (factor, index) => (
                      <div
                        className="factor-item"
                        key={
                          factor.id ||
                          `${factor.name}-${index}`
                        }
                      >
                        <span>
                          {String(index + 1).padStart(
                            2,
                            '0',
                          )}
                        </span>

                        <div>
                          <strong>
                            {factor.name ||
                              factor.factor ||
                              'Risk factor'}
                          </strong>

                          <p>
                            {factor.evidence ||
                              factor.reason ||
                              'Evidence recorded by the risk engine.'}
                          </p>
                        </div>
                      </div>
                    ),
                  )
                )}
              </div>
            </>
          ) : (
            <EmptyInline
              text="Risk score has not been generated for this session."
            />
          )}
        </article>

        {/* -------------------------------------------------
            THREAT INTELLIGENCE
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                THREAT INTELLIGENCE
              </span>

              <h2>Source intelligence</h2>
            </div>
          </div>

          {threatIntelligence.length === 0 ? (
            <EmptyInline
              text="No external threat-intelligence result is available for this session."
            />
          ) : (
            <div className="intel-list">
              {threatIntelligence.map(
                (item, index) => (
                  <div
                    className="intel-item"
                    key={
                      item.provider ||
                      item.source ||
                      index
                    }
                  >
                    <span className="intel-provider">
                      {item.provider ||
                        item.source ||
                        'PROVIDER'}
                    </span>

                    <div className="intel-grid">
                      <Fact
                        label="IP"
                        value={
                          item.ip ||
                          session.source_ip ||
                          'UNKNOWN'
                        }
                        mono
                      />

                      <Fact
                        label="REPUTATION"
                        value={
                          item.reputation_score ??
                          item.abuse_confidence_score ??
                          item.malicious ??
                          'UNKNOWN'
                        }
                      />

                      <Fact
                        label="COUNTRY"
                        value={
                          item.country ||
                          'UNKNOWN'
                        }
                      />

                      <Fact
                        label="ASN"
                        value={
                          item.asn ||
                          'UNKNOWN'
                        }
                      />

                      <Fact
                        label="ORGANIZATION"
                        value={
                          item.organization ||
                          item.isp ||
                          'UNKNOWN'
                        }
                      />

                      <Fact
                        label="STATUS"
                        value={
                          item.status ||
                          'AVAILABLE'
                        }
                      />
                    </div>
                  </div>
                ),
              )}
            </div>
          )}
        </article>

        {/* -------------------------------------------------
            MITRE
        ------------------------------------------------- */}

        <article className="investigation-card panel wide-card">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                MITRE ATT&CK
              </span>

              <h2>Technique mapping</h2>
            </div>

            <span className="count-pill">
              {mitre.length}
            </span>
          </div>

          {mitre.length === 0 ? (
            <EmptyInline
              text="No evidence-backed MITRE ATT&CK mapping is available for this session."
            />
          ) : (
            <div className="mitre-list">
              {mitre.map((mapping, index) => (
                <div
                  className="mitre-item"
                  key={
                    mapping.id ??
                    `${mapping.technique_id}-${mapping.event_id ?? index}`
                    }
                >
                  <div className="mitre-id">
                    {mapping.technique_id ||
                      mapping.id ||
                      'T----'}
                  </div>

                  <div className="mitre-copy">
                    <strong>
                      {mapping.technique_name ||
                        mapping.technique ||
                        'Unknown technique'}
                    </strong>

                    <span>
                      {mapping.tactic ||
                        'Unknown tactic'}
                    </span>

                    <p>
                      {mapping.evidence ||
                        mapping.observed_command ||
                        'Behavioral evidence recorded in the session.'}
                    </p>
                  </div>

                  <span className="mitre-confidence">
                    {mapping.confidence !==
                    undefined
                      ? `${(
                          Number(
                            mapping.confidence,
                          ) <= 1
                            ? Number(
                                mapping.confidence,
                              ) * 100
                            : Number(
                                mapping.confidence,
                              )
                        ).toFixed(0)}%`
                      : '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </article>

        {/* -------------------------------------------------
            RECOMMENDATIONS
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                DEFENSIVE RESPONSE
              </span>

              <h2>Recommendations</h2>
            </div>

            <span className="count-pill">
              {recommendations.length}
            </span>
          </div>

          {recommendations.length === 0 ? (
            <EmptyInline
              text="No evidence-specific recommendations were generated."
            />
          ) : (
            <div className="recommendation-list">
              {recommendations.map(
                (recommendation, index) => (
                  <div
                    className="recommendation-item"
                    key={
                      recommendation.id ||
                      `${recommendation.title}-${index}`
                    }
                  >
                    <span className="recommendation-number">
                      {String(index + 1).padStart(
                        2,
                        '0',
                      )}
                    </span>

                    <div>
                      <span>
                        {recommendation.category ||
                          'DEFENSIVE ACTION'}
                      </span>

                      <strong>
                        {recommendation.title ||
                          'Review observed activity'}
                      </strong>

                      <p>
                        {recommendation.reason ||
                          'Recommendation generated from observed session evidence.'}
                      </p>

                      {Array.isArray(
                        recommendation.actions,
                      ) &&
                        recommendation.actions.length >
                          0 && (
                          <ul>
                            {recommendation.actions.map(
                              (action) => (
                                <li key={action}>
                                  {action}
                                </li>
                              ),
                            )}
                          </ul>
                        )}
                    </div>
                  </div>
                ),
              )}
            </div>
          )}
        </article>

        {/* -------------------------------------------------
            EVENT TIMELINE
        ------------------------------------------------- */}

        <article className="investigation-card panel wide-card">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                EVIDENCE TIMELINE
              </span>

              <h2>Session activity</h2>
            </div>

            <span className="count-pill">
              {events.length}
            </span>
          </div>

          {events.length === 0 ? (
            <EmptyInline
              text="No event timeline data is available."
            />
          ) : (
            <div className="investigation-timeline">
              {events.map((event, index) => (
                <div
                  className="investigation-event"
                  key={
                    event.id ||
                    event.event_id ||
                    index
                  }
                >
                  <div className="investigation-event-marker">
                    <span />
                  </div>

                  <div className="investigation-event-content">
                    <div className="investigation-event-meta">
                      <span>
                        {formatDate(
                          event.timestamp ||
                            event.created_at,
                        )}
                      </span>

                      <span>
                        {event.event_type ||
                          event.type ||
                          'EVENT'}
                      </span>
                    </div>

                    <strong>
                      {event.command ||
                        event.description ||
                        'Event recorded'}
                    </strong>

                    <p>
                      {event.source_ip ||
                        session.source_ip ||
                        'UNKNOWN SOURCE'}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </article>

        {/* -------------------------------------------------
            COMMANDS
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                COMMAND ACTIVITY
              </span>

              <h2>Commands</h2>
            </div>

            <span className="count-pill">
              {commands.length}
            </span>
          </div>

          {commands.length === 0 ? (
            <EmptyInline
              text="No command records are available."
            />
          ) : (
            <div className="command-list">
              {commands.map((command, index) => (
                <div
                  className="command-item"
                  key={index}
                >
                  <span>
                    {String(index + 1).padStart(
                      2,
                      '0',
                    )}
                  </span>

                  <code>
                    {typeof command === 'string'
                      ? command
                      : command.command ||
                        command.value ||
                        'Unknown command'}
                  </code>
                </div>
              ))}
            </div>
          )}
        </article>

        {/* -------------------------------------------------
            AUTHENTICATION
        ------------------------------------------------- */}

        <article className="investigation-card panel">
          <div className="investigation-card-header">
            <div>
              <span className="eyebrow">
                AUTHENTICATION
              </span>

              <h2>Authentication activity</h2>
            </div>

            <span className="count-pill">
              {authenticationEvents.length}
            </span>
          </div>

          {authenticationEvents.length === 0 ? (
            <EmptyInline
              text="No separate authentication event records are available."
            />
          ) : (
            <div className="command-list">
              {authenticationEvents.map(
                (event, index) => (
                  <div
                    className="command-item"
                    key={
                      event.id ||
                      event.event_id ||
                      index
                    }
                  >
                    <span>
                      {String(index + 1).padStart(
                        2,
                        '0',
                      )}
                    </span>

                    <div>
                      <strong>
                        {event.result ||
                          event.outcome ||
                          event.event_type ||
                          'Authentication event'}
                      </strong>

                      <code>
                        {event.username ||
                          session.username ||
                          'unknown user'}
                      </code>
                    </div>
                  </div>
                ),
              )}
            </div>
          )}
        </article>
      </div>
    </section>
  )
}

function Fact({
  label,
  value,
  mono = false,
}) {
  return (
    <div className="investigation-fact">
      <span>{label}</span>

      <strong className={mono ? 'fact-mono' : ''}>
        {value === null ||
        value === undefined ||
        value === ''
          ? 'UNKNOWN'
          : String(value)}
      </strong>
    </div>
  )
}

function EmptyInline({ text }) {
  return (
    <div className="investigation-empty-inline">
      {text}
    </div>
  )
}

export default InvestigationView