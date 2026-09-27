import { useEffect, useRef, useState } from 'react'
import { useLenis } from 'lenis/react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import {
  getCurrentUser,
  login,
  logout,
  getDashboard,
  getActivity,
} from './api'
import SessionsView from './SessionsView'
import InvestigationView from './InvestigationView'
import AlertsView from './AlertsView'
import ReportsView from './ReportsView'
import './App.css'

gsap.registerPlugin(ScrollTrigger)

function App() {
  const pageRef = useRef(null)
  const animationsInitialized = useRef(false)
  const lenis = useLenis()

  const [user, setUser] = useState(null)
  const [view, setView] = useState('overview')
  const [selectedSessionId, setSelectedSessionId] =
    useState(null)
  const [authLoading, setAuthLoading] = useState(true)

  const [dashboard, setDashboard] = useState(null)
  const [activity, setActivity] = useState([])

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const handleLogout = async () => {
    try {
      await logout()
    } finally {
      setUser(null)
      setDashboard(null)
      setActivity([])
      setView('overview')
    }
  }


  useEffect(() => {
    let active = true

    const checkAuthentication = async () => {
      try {
        const response = await getCurrentUser()

        if (active && response.success && response.user) {
          setUser(response.user)
        }
      } catch {
        if (active) {
          setUser(null)
        }
      } finally {
        if (active) {
          setAuthLoading(false)
        }
      }
    }

    checkAuthentication()

    return () => {
      active = false
    }
  }, [])
  /*
   * ------------------------------------------------------
   * Lenis <-> GSAP synchronization
   * ------------------------------------------------------
   */

  useEffect(() => {
    if (!lenis) {
      return undefined
    }

    const update = (time) => {
      lenis.raf(time * 1000)
    }

    const handleLenisScroll = () => {
      ScrollTrigger.update()
    }

    lenis.on('scroll', handleLenisScroll)

    gsap.ticker.add(update)
    gsap.ticker.lagSmoothing(0)

    return () => {
      lenis.off('scroll', handleLenisScroll)
      gsap.ticker.remove(update)
    }
  }, [lenis])

  /*
   * ------------------------------------------------------
   * Dashboard API
   * ------------------------------------------------------
   */

  useEffect(() => {
    if (!user) {
      return undefined
    }

    let active = true
    let firstLoad = true
    let timeoutId = null

    const loadDashboard = async () => {
      try {
        if (firstLoad) {
          setLoading(true)
          setError(null)
        }

        const [dashboardData, activityData] = await Promise.all([
          getDashboard(),
          getActivity(),
        ])

        if (!dashboardData.success) {
          throw new Error(
            dashboardData.error || 'Unable to load dashboard data',
          )
        }

        if (!activityData.success) {
          throw new Error(
            activityData.error || 'Unable to load analytics data',
          )
        }

        if (active) {
          setDashboard(dashboardData)

          setActivity(
            Array.isArray(activityData.activity)
              ? [...activityData.activity].sort(
                  (a, b) =>
                    new Date(b.timestamp).getTime() -
                    new Date(a.timestamp).getTime(),
                )
              : [],
          )

          setError(null)
        }
      } catch (err) {
        if (active && firstLoad) {
          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load telemetry',
          )
        }
      } finally {
        if (active) {
          if (firstLoad) {
            setLoading(false)
          }

          firstLoad = false

          timeoutId = window.setTimeout(
            loadDashboard,
            5000,
          )
        }
      }
    }

    loadDashboard()

    return () => {
      active = false

      if (timeoutId !== null) {
        window.clearTimeout(timeoutId)
      }
    }
  }, [user])

  /*
   * ------------------------------------------------------
   * GSAP animations
   * ------------------------------------------------------
   */

  useEffect(() => {
    if (
      !dashboard ||
      !pageRef.current ||
      animationsInitialized.current
    ) {
      return undefined
    }

    animationsInitialized.current = true

    window.scrollTo({
      top: 0,
      left: 0,
      behavior: 'auto',
    })

    const context = gsap.context(() => {
      /*
       * Hero entrance
       */

      const intro = gsap.timeline({
        defaults: {
          ease: 'power3.out',
        },
      })

      intro
        .from('.hero-kicker', {
          opacity: 0,
          y: 18,
          duration: 0.65,
        })
        .from(
          '.hero-title',
          {
            opacity: 0,
            y: 38,
            duration: 0.85,
          },
          '-=0.4',
        )
        .from(
          '.hero-description',
          {
            opacity: 0,
            y: 18,
            duration: 0.6,
          },
          '-=0.45',
        )
        .from(
          '.hero-actions',
          {
            opacity: 0,
            y: 12,
            duration: 0.5,
          },
          '-=0.4',
        )
        .from(
          '.field-visual',
          {
            opacity: 0,
            scale: 0.94,
            duration: 0.9,
          },
          '-=0.55',
        )

      /*
       * Repeating scroll reveals
       */

      const createReveal = (
        selector,
        trigger,
        vars = {},
      ) => {
        gsap.fromTo(
          selector,
          {
            opacity: 0,
            y: 30,
            ...vars.initial,
          },
          {
            opacity: 1,
            y: 0,
            duration: vars.duration || 0.7,
            stagger: vars.stagger || 0.08,
            ease: 'power3.out',

            scrollTrigger: {
              trigger,
              start: 'top 86%',
              end: 'bottom 15%',
              toggleActions:
                'play reverse play reverse',
            },

            ...vars.animation,
          },
        )
      }

      createReveal(
        '.metric-block',
        '.metrics-section',
        {
          stagger: 0.09,
        },
      )

      createReveal(
        '.analytics-panel',
        '.analytics-panel',
        {
          initial: {
            y: 35,
          },
        },
      )

      createReveal(
        '.signal-panel',
        '.signal-panel',
        {
          initial: {
            x: 35,
            y: 0,
          },
        },
      )

      createReveal(
        '.session-panel',
        '.session-panel',
        {
          initial: {
            y: 30,
          },
        },
      )

      createReveal(
        '.manifesto-panel',
        '.manifesto-panel',
        {
          initial: {
            scale: 0.97,
            y: 20,
          },
        },
      )

      /*
       * Subtle hero parallax
       */

      gsap.to('.field-visual', {
        yPercent: -7,
        ease: 'none',
        scrollTrigger: {
          trigger: '.hero-section',
          start: 'top top',
          end: 'bottom top',
          scrub: 1.2,
        },
      })

      /*
       * Metric counters
       */

      

      requestAnimationFrame(() => {
        ScrollTrigger.refresh()
      })
    }, pageRef)

    const handleResize = () => {
      ScrollTrigger.refresh()
    }

    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener(
        'resize',
        handleResize,
      )

      context.revert()
    }
  }, [dashboard])

  if (authLoading) {
    return (
      <div className="app">
        <header className="nav">
          <Brand />
          <StatusPill label="AUTHENTICATING" />
        </header>

        <main className="loading-page">
          <span className="eyebrow">
            CYBERHIVE / SECURITY INTELLIGENCE
          </span>

          <h1>
            Verifying analyst access.
          </h1>

          <p>
            Establishing a secure session with the security API...
          </p>

          <div className="loading-track">
            <span />
          </div>
        </main>
      </div>
    )
  }

  if (!user) {
    return (
      <LoginScreen onLogin={setUser} />
    )
  }

  /*
   * ------------------------------------------------------
   * Loading
   * ------------------------------------------------------
   */

  if (loading || !dashboard) {
    return (
      <div className="app">
        <header className="nav">
          <Brand />
          <StatusPill label="CONNECTING" />
        </header>

        <main className="loading-page">
          <span className="eyebrow">
            CYBERHIVE / SECURITY INTELLIGENCE
          </span>

          <h1>
            Preparing the telemetry layer.
          </h1>

          <p>
            Connecting to the local security API...
          </p>

          <div className="loading-track">
            <span />
          </div>
        </main>
      </div>
    )
  }

  /*
   * ------------------------------------------------------
   * Error
   * ------------------------------------------------------
   */

  if (error) {
    return (
      <div className="app">
        <header className="nav">
          <Brand />
        </header>

        <main className="error-page">
          <span className="error-index">01</span>

          <div>
            <span className="eyebrow">
              CONNECTION ERROR
            </span>

            <h1>Telemetry unavailable.</h1>

            <p>{error}</p>

            <small>
              Start the Flask API on port 5000 and refresh.
            </small>
          </div>
        </main>
      </div>
    )
  }

  const {
    stats,
    recent_events: recentEvents,
    recent_sessions: recentSessions,
  } = dashboard

  const formatActivityTimestamp = (timestamp) => {
    if (!timestamp) {
      return 'UNKNOWN TIME'
    }

    const date = new Date(timestamp)

    if (Number.isNaN(date.getTime())) {
      return 'UNKNOWN TIME'
    }

    const parts = new Intl.DateTimeFormat('en-IN', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).formatToParts(date)

    const getPart = (type) =>
      parts.find((part) => part.type === type)?.value || ''

    const year = getPart('year')
    const month = getPart('month')
    const day = getPart('day')
    const hour = getPart('hour')
    const minute = getPart('minute')
    const second = getPart('second')

    const fraction =
      timestamp.match(/\.(\d+)/)?.[1] || '000000'

    return `${year}-${month}-${day} ${hour}:${minute}:${second}.${fraction.slice(0, 6)} IST`
  }

  const getActivityDescription = (item) => {
    if (item.command) {
      return item.command
    }

    switch (item.event_type) {
      case 'cowrie.session.connect':
        return 'Session connected'

      case 'cowrie.session.closed':
        return 'Session closed'

      case 'cowrie.log.closed':
        return 'TTY log closed'

      case 'cowrie.login.failed':
        return 'Login failed'

      case 'cowrie.login.success':
        return 'Login successful'

      case 'cowrie.session.params':
        return 'Session parameters captured'

      default:
        return 'Event recorded'
    }
  }

  const activityCount = activity.length

  /*
   * ------------------------------------------------------
   * Dashboard
   * ------------------------------------------------------
   */

  return (
    <div className="app">
      <div className="site-grid" />

      <header className="nav">
        <Brand />

        <div className="nav-right">
          <nav className="app-nav">
            <button
              type="button"
              className={
                view === 'overview'
                  ? 'app-nav-button active'
                  : 'app-nav-button'
              }
              onClick={() => setView('overview')}
            >
              OVERVIEW
            </button>

            <button
              type="button"
              className={
                view === 'sessions'
                  ? 'app-nav-button active'
                  : 'app-nav-button'
              }
              onClick={() => setView('sessions')}
            >
              SESSIONS
            </button>

             <button
                type="button"
                className={
                  view === 'alerts'
                    ? 'app-nav-button active'
                    : 'app-nav-button'
                }
                onClick={() => setView('alerts')}
              >
                ALERTS
              </button>

              <button
                type="button"
                className={
                  view === 'reports'
                    ? 'app-nav-button active'
                    : 'app-nav-button'
                }
                onClick={() => setView('reports')}
              >
                REPORTS
              </button>

          </nav>

          <span className="nav-user">
            {user.username}
          </span>

          <button
            type="button"
            className="logout-button"
            onClick={handleLogout}
          >
            LOG OUT
          </button>

          <StatusPill label="OPERATIONAL" />
        </div>
      </header>

      <main className="page" ref={pageRef}>
        {view === 'investigation' &&
        selectedSessionId ? (
          <InvestigationView
            sessionId={selectedSessionId}
            onBack={() => setView('sessions')}
          />
        ) : view === 'sessions' ? (
          <SessionsView
            onOpenInvestigation={(sessionId) => {
              setSelectedSessionId(sessionId)
              setView('investigation')
            }}
          />
        ) : view === 'alerts' ? (
          <AlertsView
            onOpenInvestigation={(sessionId) => {
              setSelectedSessionId(sessionId)
              setView('investigation')
            }}
          />
        ) : view === 'reports' ? (
          <ReportsView />
        ) : (
          <>
            <section className="hero-section">
              <div className="hero-copy">
                <span className="eyebrow hero-kicker">
                  BEHAVIORAL THREAT INTELLIGENCE
                </span>

                <h1 className="hero-title">
                  See what
                  <br />
                  attackers
                  <br />
                  <em>leave behind.</em>
                </h1>

                <p className="hero-description">
                  CyberHive turns honeypot telemetry into structured
                  evidence, giving defenders a clearer picture of
                  sessions, commands and attacker behaviour.
                </p>

                <div className="hero-actions">
                  <span className="hero-action primary">
                    <span className="action-dot" />
                    TELEMETRY ACTIVE
                  </span>

                  <span className="hero-action">
                    AUGUST 2026 / LAB
                  </span>
                </div>
              </div>

              <div className="field-visual">
                <div className="field-grid" />

                <div className="field-ring field-ring-outer" />
                <div className="field-ring field-ring-middle" />
                <div className="field-ring field-ring-inner" />

                <div className="orbit-track orbit-track-outer">
                  <span className="field-node node-blue node-a" />
                  <span className="field-node node-coral node-b" />
                  <span className="field-node node-blue node-c" />
                </div>

                <div className="orbit-track orbit-track-middle">
                  <span className="field-node node-violet node-d" />
                  <span className="field-node node-mint node-e" />
                  <span className="field-node node-coral node-f" />
                </div>

                <div className="orbit-track orbit-track-inner">
                  <span className="field-node node-blue node-g" />
                  <span className="field-node node-violet node-h" />
                </div>

                <div className="field-core">
                  <span>CYBER</span>
                  <strong>HIVE</strong>
                </div>

                <div className="field-label label-a">
                  CAPTURE
                </div>

                <div className="field-label label-b">
                  ANALYZE
                </div>

                <div className="field-label label-c">
                  UNDERSTAND
                </div>
              </div>
            </section>

            <section className="metrics-section">
              <div className="section-intro">
                <span className="eyebrow">
                  CURRENT SIGNAL
                </span>

                <p>
                  A compact view of what CyberHive has observed so far.
                </p>
              </div>

              <div className="metrics-grid">
                <MetricBlock
                  number="01"
                  label="SESSIONS"
                  value={stats.total_sessions}
                  description="ATTACK SESSIONS"
                  accent="blue"
                />

                <MetricBlock
                  number="02"
                  label="EVENTS"
                  value={stats.total_events}
                  description="NORMALIZED EVENTS"
                  accent="violet"
                />

                <MetricBlock
                  number="03"
                  label="COMMANDS"
                  value={stats.total_commands}
                  description="ATTACKER COMMANDS"
                  accent="coral"
                />

                <MetricBlock
                  number="04"
                  label="SOURCE IPS"
                  value={stats.unique_source_ips}
                  description="UNIQUE ORIGINS"
                  accent="mint"
                />
              </div>
            </section>

            <section className="content-layout">
              <article className="analytics-panel panel">
                <div className="panel-top">
                  <div>
                    <span className="eyebrow">
                      TELEMETRY
                    </span>

                    <h2>Activity horizon</h2>
                  </div>

                  <span className="future-chip">
                    {activityCount} SIGNAL{activityCount === 1 ? '' : 'S'}
                  </span>
                </div>

                <div className="chart-stage">
                  {activity.length === 0 ? (
                    <div className="activity-empty">
                      <span>NO LIVE TELEMETRY</span>

                      <strong>
                        Incoming Cowrie activity will appear here
                        with precise timestamps and source intelligence.
                      </strong>
                    </div>
                  ) : (
                    <div className="activity-timeline">
                      <div className="activity-timeline-line" />

                      {activity.map((item, index) => (
                        <div
                          className="activity-item"
                          key={`${item.activity_type}-${item.event_id || item.session_id}-${item.timestamp}-${index}`}
                        >
                          <div className="activity-marker">
                            <span />
                          </div>

                          <div className="activity-content">
                            <div className="activity-meta">
                              <span className="activity-time">
                                {formatActivityTimestamp(item.timestamp)}
                              </span>

                              <span
                                className={`activity-type activity-type-${item.activity_type}`}
                              >
                                {item.activity_type === 'event'
                                  ? 'EVENT'
                                  : 'SESSION'}
                              </span>
                            </div>

                            <div className="activity-main">
                              <strong>
                                {item.source_ip || 'UNKNOWN SOURCE'}
                              </strong>

                              <span>
                                {item.activity_type === 'event'
                                  ? item.event_type || 'Unknown event'
                                  : item.protocol || 'Unknown protocol'}
                              </span>
                            </div>

                            <div className="activity-detail">
                              {item.activity_type === 'event' ? (
                                <>
                                  <span>
                                    SESSION {item.session_id || 'UNKNOWN'}
                                  </span>

                                  <span>
                                    {getActivityDescription(item)}
                                  </span>
                                </>
                              ) : (
                                <>
                                  <span>
                                    USER {item.username || 'UNKNOWN'}
                                  </span>

                                  <span>
                                    {item.command_count} COMMAND
                                    {item.command_count === 1 ? '' : 'S'}
                                  </span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="panel-footer">
                  <span>DATA SOURCE / COWRIE</span>
                  <span>PRECISE EVENT TIMELINE / IST</span>
                </div>
              </article>

              <article className="signal-panel panel">
                <div className="panel-top">
                  <div>
                    <span className="eyebrow">
                      EVENT STREAM
                    </span>

                    <h2>Latest signals</h2>
                  </div>

                  <span className="count-pill">
                    {recentEvents.length}
                  </span>
                </div>

                {recentEvents.length === 0 ? (
                  <EmptyState
                    title="No events yet"
                    description="Incoming Cowrie telemetry will appear here."
                  />
                ) : (
                  <div className="signal-list">
                    {recentEvents.map((event, index) => (
                      <div
                        className="signal-item"
                        key={event.id}
                      >
                        <span className="signal-number">
                          {String(index + 1).padStart(2, '0')}
                        </span>

                        <div className="signal-body">
                          <div className="signal-meta">
                            <span>
                              {event.event_type}
                            </span>

                            <span>
                              {event.source_ip || 'UNKNOWN'}
                            </span>
                          </div>

                          <strong>
                            {getActivityDescription(event)}
                          </strong>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </article>
            </section>

            <section className="secondary-layout">
              <article className="session-panel panel">
                <div className="panel-top">
                  <div>
                    <span className="eyebrow">
                      ATTACK ACTIVITY
                    </span>

                    <h2>Recent sessions</h2>
                  </div>

                  <span className="count-pill">
                    {recentSessions.length}
                  </span>
                </div>

                {recentSessions.length === 0 ? (
                  <EmptyState
                    title="No attack sessions"
                    description="The session layer is waiting for honeypot activity."
                  />
                ) : (
                  <div className="session-list">
                    {recentSessions.map((session) => (
                      <div
                        className="session-row"
                        key={session.id}
                      >
                        <div className="session-badge">
                          {session.protocol?.slice(0, 1) ||
                            'S'}
                        </div>

                        <div className="session-copy">
                          <strong>
                            {session.session_id}
                          </strong>

                          <div>
                            <span>
                              {session.source_ip}
                            </span>

                            <span>
                              {session.username ||
                                'unknown user'}
                            </span>
                          </div>
                        </div>

                        <div className="session-commands">
                          <strong>
                            {session.command_count}
                          </strong>

                          <span>commands</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </article>

              <article className="manifesto-panel">
                <span className="eyebrow">
                  CYBERHIVE
                </span>

                <div className="manifesto-number">
                  ∞
                </div>

                <h2>
                  Every
                  <br />
                  interaction
                  <br />
                  <em>leaves evidence.</em>
                </h2>

                <p>
                  The platform is designed to make hostile behaviour
                  observable, structured and eventually explainable.
                </p>

                <div className="manifesto-line" />
              </article>
            </section>
          </>
        )}
      </main>

      <footer className="footer">
        <span>CYBERHIVE / 2026</span>

        <span>
          BEHAVIORAL THREAT INTELLIGENCE PLATFORM
        </span>
      </footer>
    </div>
  )
}

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">C</span>

      <div className="brand-copy">
        <strong>CyberHive</strong>

        <span>
          THREAT INTELLIGENCE PLATFORM
        </span>
      </div>
    </div>
  )
}

function StatusPill({ label }) {
  return (
    <div className="status-pill">
      <span className="status-dot" />
      {label}
    </div>
  )
}

function MetricBlock({
  number,
  label,
  value,
  description,
  accent,
}) {
  return (
    <article
      className={`metric-block metric-${accent}`}
    >
      <div className="metric-header">
        <span>{number}</span>
        <span className="metric-dot" />
      </div>

      <span className="metric-label">
        {label}
      </span>

      <strong
        className="metric-value"
        data-value={value}
      >
        {value}
      </strong>

      <span className="metric-description">
        {description}
      </span>
    </article>
  )
}

function EmptyState({
  title,
  description,
}) {
  return (
    <div className="empty-state">
      <div className="empty-symbol">
        <span />
      </div>

      <strong>{title}</strong>

      <p>{description}</p>
    </div>
  )
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (event) => {
    event.preventDefault()

    if (!username.trim() || !password) {
      setError('Enter your username and password.')
      return
    }

    setSubmitting(true)
    setError('')

    try {
      const response = await login(
        username.trim(),
        password,
      )

      if (!response.success || !response.user) {
        throw new Error(
          response.error || 'Login failed',
        )
      }

      onLogin(response.user)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to sign in',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="app">
      <div className="site-grid" />

      <header className="nav">
        <Brand />

        <StatusPill label="SECURE ACCESS" />
      </header>

      <main className="login-page">
        <section className="login-card">
          <span className="eyebrow">
            CYBERHIVE / SECURITY INTELLIGENCE
          </span>

          <h1>
            Analyst
            <br />
            <em>access.</em>
          </h1>

          <p>
            Sign in to access the CyberHive security
            intelligence workspace.
          </p>

          <form onSubmit={handleSubmit}>
            <label>
              Username

              <input
                value={username}
                onChange={(event) =>
                  setUsername(event.target.value)
                }
                autoComplete="username"
                disabled={submitting}
              />
            </label>

            <label>
              Password

              <div className="password-field">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(event) =>
                    setPassword(event.target.value)
                  }
                  autoComplete="current-password"
                  disabled={submitting}
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() =>
                    setShowPassword((current) => !current)
                  }
                  disabled={submitting}
                  aria-label={
                    showPassword
                      ? 'Hide password'
                      : 'Show password'
                  }
                >
                  <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    {showPassword ? (
                      <>
                        <path
                          d="M2.5 12s3.4-6 9.5-6 9.5 6 9.5 6-3.4 6-9.5 6-9.5-6-9.5-6Z"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />

                        <circle
                          cx="12"
                          cy="12"
                          r="2.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                        />
                      </>
                    ) : (
                      <>
                        <path
                          d="M3 3l18 18"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                        />

                        <path
                          d="M10.4 6.2C10.9 6.1 11.4 6 12 6c6.1 0 9.5 6 9.5 6s-3.4 6-9.5 6c-1.1 0-2.1-.2-3-.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />

                        <path
                          d="M6.4 7.4C3.8 9.2 2.5 12 2.5 12s3.4 6 9.5 6"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.8"
                          strokeLinecap="round"
                        />
                      </>
                    )}
                  </svg>
                </button>
              </div>
            </label>

            {error && (
              <div className="login-error">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
            >
              {submitting
                ? 'AUTHENTICATING...'
                : 'SIGN IN'}
            </button>
          </form>
        </section>
      </main>
    </div>
  )
}

export default App