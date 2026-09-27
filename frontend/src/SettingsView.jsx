import { useEffect, useState } from 'react'
import { getSettings } from './api'

function SettingStatus({ label, value, tone = 'default' }) {
  return (
    <div className="settings-row">
      <div>
        <span className="eyebrow">{label}</span>
      </div>
      <strong className={`settings-value ${tone}`}>{value}</strong>
    </div>
  )
}

function SettingsView() {
  const [settings, setSettings] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    getSettings()
      .then((response) => {
        if (!active) return
        if (!response.success) throw new Error(response.error || 'Unable to load settings')
        setSettings(response.settings || null)
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : 'Unable to load settings')
      })
      .finally(() => {
        if (active) setLoading(false)
      })

    return () => { active = false }
  }, [])

  if (loading) {
    return (
      <section className="settings-view">
        <div className="sessions-state panel">
          <span className="eyebrow">SECURE CONFIGURATION</span>
          <h1>Loading settings.</h1>
          <p>Reading backend-authoritative configuration status.</p>
        </div>
      </section>
    )
  }

  if (error || !settings) {
    return (
      <section className="settings-view">
        <div className="reports-error panel">
          <strong>SETTINGS UNAVAILABLE</strong>
          <span>{error || 'No configuration data was returned.'}</span>
        </div>
      </section>
    )
  }

  const status = (enabled, configured) => {
    if (!enabled) return ['DISABLED', 'muted']
    return [configured ? 'CONFIGURED' : 'NOT CONFIGURED', configured ? 'good' : 'muted']
  }

  const [abuseLabel, abuseTone] = status(settings.abuseipdb_enabled, settings.abuseipdb_configured)
  const [vtLabel, vtTone] = status(settings.virustotal_enabled, settings.virustotal_configured)
  const [smtpLabel, smtpTone] = status(settings.email_alerts_enabled, settings.smtp_configured)

  return (
    <section className="settings-view">
      <div className="sessions-heading">
        <div>
          <span className="eyebrow">OPERATIONAL CONFIGURATION</span>
          <h1>Settings</h1>
          <p>Backend-authoritative configuration status. Secret values are never returned to the browser.</p>
        </div>
        <span className="count-pill">ENV</span>
      </div>

      <div className="settings-grid">
        <article className="panel settings-card">
          <span className="eyebrow">RISK & ALERTING</span>
          <SettingStatus label="RISK ALERT THRESHOLD" value={`${settings.risk_alert_threshold} / 100`} />
          <SettingStatus label="EMAIL ALERTS" value={smtpLabel} tone={smtpTone} />
        </article>

        <article className="panel settings-card">
          <span className="eyebrow">THREAT INTELLIGENCE</span>
          <SettingStatus label="ABUSEIPDB" value={abuseLabel} tone={abuseTone} />
          <SettingStatus label="VIRUSTOTAL" value={vtLabel} tone={vtTone} />
          <SettingStatus label="CACHE DURATION" value={`${settings.intel_cache_seconds}s`} />
        </article>

        <article className="panel settings-card">
          <span className="eyebrow">TELEMETRY</span>
          <SettingStatus label="COWRIE" value={settings.cowrie_configured ? `CONFIGURED / ${settings.cowrie_endpoint_type}` : 'NOT CONFIGURED'} tone={settings.cowrie_configured ? 'good' : 'muted'} />
          <SettingStatus label="REFRESH INTERVAL" value={`${settings.dashboard_refresh_interval_ms}ms`} />
          <p className="settings-note">Change COWRIE_LOG_URL or COWRIE_LOG_PATH in the server environment to move between local VirtualBox Kali and a remote physical Kali sensor without changing application source code.</p>
        </article>

        <article className="panel settings-card">
          <span className="eyebrow">SESSION SECURITY</span>
          <SettingStatus label="SESSION LIFETIME" value={`${Math.round(settings.session_lifetime_seconds / 60)} minutes`} />
          <SettingStatus label="SECURE COOKIE" value={settings.session_cookie_secure ? 'ENABLED' : 'DISABLED'} tone={settings.session_cookie_secure ? 'good' : 'muted'} />
          <p className="settings-note">Cookie security is environment-dependent. HTTPS deployments should enable secure cookies.</p>
        </article>
      </div>

      <div className="panel settings-security-note">
        <span className="eyebrow">SECRET BOUNDARY</span>
        <p>API keys, SMTP credentials, the Flask secret key, and other secrets remain server-side. This screen exposes configuration status only.</p>
      </div>
    </section>
  )
}

export default SettingsView
