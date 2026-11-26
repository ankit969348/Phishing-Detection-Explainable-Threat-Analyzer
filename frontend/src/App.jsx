import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowLeft, ArrowUpRight, BarChart3, Bell,
  Check, CheckCircle2, ChevronRight, Clock3, Eye, FileText, Globe,
  LayoutDashboard, LoaderCircle, Lock, LogOut, Mail, Menu, Search,
  Shield, ShieldAlert, ShieldCheck, Sparkles, Trash2, X
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import './App.css'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '')

const riskColor = (label = '') => {
  const value = label.toLowerCase()
  if (value === 'phishing') return 'danger'
  if (value === 'suspicious') return 'warning'
  return 'safe'
}

const explainFlag = (flag) => {
  const value = flag.toLowerCase()
  if (value.includes('urgency/pressure')) {
    return {
      title: 'Urgency and pressure language',
      explanation: 'The message contains words that create urgency or pressure, such as immediately, verify, suspend or password.',
      risk: 'Attackers often use urgent language to make recipients act without verifying the request.',
      action: 'Verify the request through the organization’s official website or app. Do not follow unexpected links.'
    }
  }
  if (value.includes('does not use https')) {
    return {
      title: 'HTTPS protection not detected',
      explanation: 'The submitted URL uses HTTP instead of HTTPS.',
      risk: 'Data exchanged with an HTTP website is not protected by HTTPS encryption during transmission.',
      action: 'Avoid entering credentials or personal information. Navigate to the official HTTPS website instead.'
    }
  }
  if (value.includes('many hyphens')) {
    return {
      title: 'Unusual number of hyphens',
      explanation: 'The URL contains multiple hyphens in its address.',
      risk: 'Attackers sometimes create misleading domain names that imitate trusted brands or login pages.',
      action: 'Inspect the actual registered domain carefully before opening the website.'
    }
  }
  if (value.includes('suspicious keyword')) {
    return {
      title: 'Suspicious URL keywords',
      explanation: 'The URL contains words commonly associated with account access or verification, such as login, secure, verify or account.',
      risk: 'These terms can be used to make a fraudulent website appear like a genuine account or banking service.',
      action: 'Do not enter credentials until you independently verify the website address.'
    }
  }
  if (value.includes('ip address')) {
    return {
      title: 'IP address used instead of a domain',
      explanation: 'The website address appears to use a direct IP address.',
      risk: 'Some malicious websites use direct IP addresses to avoid recognizable domain names.',
      action: 'Verify the destination independently before visiting it.'
    }
  }
  if (value.includes('subdomain')) {
    return {
      title: 'Unusual subdomain structure',
      explanation: 'The URL contains several subdomains.',
      risk: 'Complex subdomain structures can make an unrelated domain look like a trusted organization.',
      action: 'Read the registered domain from right to left and verify its ownership.'
    }
  }
  if (value.includes('at sign') || value.includes('@')) {
    return {
      title: 'Unusual @ symbol in URL',
      explanation: 'The URL contains an @ symbol, which can make its destination confusing.',
      risk: 'In URLs, text before @ may be interpreted as user information rather than the destination host.',
      action: 'Do not open the link until you have verified its actual destination.'
    }
  }
  if (value.includes('long url')) {
    return {
      title: 'Unusually long URL',
      explanation: 'The URL exceeds the configured length threshold.',
      risk: 'Long URLs can hide confusing paths or misleading parameters.',
      action: 'Inspect the domain and avoid shortened or unexpected links.'
    }
  }
  return {
    title: 'Additional detection indicator',
    explanation: flag,
    risk: 'This indicator was returned by the configured detection system.',
    action: 'Review the submitted content carefully before interacting with it.'
  }
}

function App() {
  const [page, setPage] = useState('Overview')
  const [scanType, setScanType] = useState('email')
  const [emailText, setEmailText] = useState('')
  const [urlText, setUrlText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [selectedReport, setSelectedReport] = useState(null)

  const [history, setHistory] = useState([])
  const [authPrompt, setAuthPrompt] = useState('')
  const [showNotifications, setShowNotifications] = useState(false)
  const [legalModal, setLegalModal] = useState('') // 'terms' | 'privacy' | 'security' | ''
  const [mobileMenu, setMobileMenu] = useState(false)

  // Persistent Notification States (Read & Dismissed)
  const [readNotifs, setReadNotifs] = useState(() => {
    try { return JSON.parse(localStorage.getItem('tl-read-notifs') || '[]') } catch { return [] }
  })
  const [dismissedNotifs, setDismissedNotifs] = useState(() => {
    try { return JSON.parse(localStorage.getItem('tl-dismissed-notifs') || '[]') } catch { return [] }
  })

  useEffect(() => {
    localStorage.setItem('tl-read-notifs', JSON.stringify(readNotifs))
  }, [readNotifs])

  useEffect(() => {
    localStorage.setItem('tl-dismissed-notifs', JSON.stringify(dismissedNotifs))
  }, [dismissedNotifs])

  // Authentication states
  const [token, setToken] = useState(() => localStorage.getItem('threatlens-token') || '')
  const [user, setUser] = useState(null)
  const [authMode, setAuthMode] = useState('login')
  const [showAuth, setShowAuth] = useState(true)
  const [authLoading, setAuthLoading] = useState(false)
  const [authError, setAuthError] = useState('')
  const [authSuccess, setAuthSuccess] = useState('')
  const [authForm, setAuthForm] = useState({ username: '', email: '', password: '' })

  const fetchDbHistory = async (authToken) => {
    try {
      const res = await fetch(`${API_BASE_URL}/history/`, {
        headers: { Authorization: `Token ${authToken}` }
      })
      if (res.ok) {
        const items = await res.json()
        setHistory(items)
      }
    } catch (err) {
      console.error('Failed to load history:', err)
    }
  }

  useEffect(() => {
    if (!token) {
      setUser(null)
      return
    }
    const verifySession = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/auth/me/`, {
          headers: { Authorization: `Token ${token}` }
        })
        if (!response.ok) throw new Error('Session expired')
        const data = await response.json()
        setUser(data)
        fetchDbHistory(token)
      } catch {
        localStorage.removeItem('threatlens-token')
        setToken('')
        setUser(null)
      }
    }
    verifySession()
  }, [token])

  const totals = useMemo(() => {
    const counts = { phishing: 0, suspicious: 0, legitimate: 0 }
    history.forEach(item => {
      Object.values(item.result || {}).forEach(scan => {
        const label = (scan.label || '').toLowerCase()
        if (counts[label] !== undefined) counts[label] += 1
      })
    })
    return {
      scans: history.length,
      phishing: counts.phishing,
      suspicious: counts.suspicious,
      legitimate: counts.legitimate
    }
  }, [history])

  const alertItems = useMemo(() => {
    return history
      .filter(h =>
        !dismissedNotifs.includes(String(h.id)) &&
        Object.values(h.result || {}).some(s =>
          ['phishing', 'suspicious'].includes((s.label || '').toLowerCase())
        )
      )
      .slice(0, 8)
  }, [history, dismissedNotifs])

  const unreadAlertCount = useMemo(() => {
    return alertItems.filter(item => !readNotifs.includes(String(item.id))).length
  }, [alertItems, readNotifs])

  const markNotifRead = (id, e) => {
    if (e) e.stopPropagation()
    const key = String(id)
    setReadNotifs(prev => (prev.includes(key) ? prev : [...prev, key]))
  }

  const dismissNotif = (id, e) => {
    if (e) e.stopPropagation()
    const key = String(id)
    setDismissedNotifs(prev => (prev.includes(key) ? prev : [...prev, key]))
  }

  const markAllAlertsRead = () => {
    const allIds = alertItems.map(i => String(i.id))
    setReadNotifs(prev => Array.from(new Set([...prev, ...allIds])))
  }

  const chartData = useMemo(() => {
    const days = []
    for (let i = 6; i >= 0; i--) {
      const date = new Date()
      date.setDate(date.getDate() - i)
      const key = date.toLocaleDateString()
      const dayItems = history.filter(item =>
        new Date(item.timestamp).toLocaleDateString() === key
      )
      let threats = 0
      dayItems.forEach(item => {
        Object.values(item.result || {}).forEach(scan => {
          if (['phishing', 'suspicious'].includes((scan.label || '').toLowerCase())) {
            threats += 1
          }
        })
      })
      days.push({
        day: date.toLocaleDateString('en', { weekday: 'short' }),
        scans: dayItems.length,
        threats
      })
    }
    return days
  }, [history])

  const saveSession = (data) => {
    localStorage.setItem('threatlens-token', data.token)
    setToken(data.token)
    setUser(data.user)
    setShowAuth(false)
    setAuthError('')
    setAuthSuccess(data.message || 'Authentication successful!')
    setAuthForm({ username: '', email: '', password: '' })
  }

  const handleAuth = async (event) => {
    event.preventDefault()
    setAuthLoading(true)
    setAuthError('')
    setAuthSuccess('')

    const endpoint = authMode === 'signup'
      ? `${API_BASE_URL}/auth/signup/`
      : `${API_BASE_URL}/auth/login/`

    const payload = authMode === 'signup'
      ? authForm
      : { username: authForm.username, password: authForm.password }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(Array.isArray(data.error) ? data.error.join(' ') : data.error || 'Authentication failed.')
      }
      if (authMode === 'signup') {
        setAuthMode('login')
        setAuthSuccess(data.message || 'Account created successfully! Please sign in.')
        setAuthForm(prev => ({ ...prev, password: '' }))
      } else {
        saveSession(data)
      }
    } catch (error) {
      setAuthError(error.message)
    } finally {
      setAuthLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      if (token) {
        await fetch(`${API_BASE_URL}/auth/logout/`, {
          method: 'POST',
          headers: { Authorization: `Token ${token}` }
        })
      }
    } catch (error) {
      console.error('Logout request failed:', error)
    } finally {
      localStorage.removeItem('threatlens-token')
      setToken('')
      setUser(null)
      setHistory([])
      setResult(null)
      setSelectedReport(null)
      setPage('Overview')
      setAuthSuccess('')
    }
  }

  const runScan = async (event) => {
    event.preventDefault()
    setError('')
    setResult(null)

    const payload = {}
    if (scanType === 'email' || scanType === 'both') {
      if (!emailText.trim()) {
        setError('Please enter email content before scanning.')
        return
      }
      payload.text = emailText.trim()
    }
    if (scanType === 'url' || scanType === 'both') {
      if (!urlText.trim()) {
        setError('Please enter a URL before scanning.')
        return
      }
      payload.url = urlText.trim()
    }

    setLoading(true)
    try {
      const response = await fetch(`${API_BASE_URL}/scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Token ${token}` } : {})
        },
        body: JSON.stringify(payload)
      })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || 'The scan request could not be completed.')
      }
      const record = {
        id: `${Date.now()}`,
        timestamp: new Date().toISOString(),
        type: scanType,
        result: data,
        emailPreview: payload.text || '',
        urlPreview: payload.url || ''
      }
      setResult(record)
      setHistory(previous => [record, ...previous].slice(0, 100))
      setPage('Scanner')
    } catch (err) {
      setError(`${err.message}. Check that the backend server is reachable.`)
    } finally {
      setLoading(false)
    }
  }

  const clearHistory = async () => {
    if (!user) {
      setAuthPrompt('Sign in or create an account to manage your scan history.')
      return
    }
    if (window.confirm('Delete all saved scan history from your account?')) {
      try {
        await fetch(`${API_BASE_URL}/history/`, {
          method: 'DELETE',
          headers: { Authorization: `Token ${token}` }
        })
      } catch (err) {
        console.error(err)
      }
      setHistory([])
      setResult(null)
      setSelectedReport(null)
    }
  }

  const navItems = [
    { name: 'Overview', short: 'Home', icon: LayoutDashboard },
    { name: 'Scanner', short: 'Scan', icon: Search },
    { name: 'Scan History', short: 'History', icon: Clock3 },
    { name: 'Reports', short: 'Reports', icon: FileText },
    { name: 'About Project', short: 'About', icon: Shield }
  ]

  const goTo = (name) => {
    if (!user && (name === 'Scan History' || name === 'Reports')) {
      setAuthPrompt(`Create a free account or sign in to access ${name} and export PDF security reports.`)
      setMobileMenu(false)
      return
    }
    setPage(name)
    if (name !== 'Reports') setSelectedReport(null)
    setMobileMenu(false)
    setError('')
  }

  const formatDate = (value) => new Date(value).toLocaleString()

  const renderFinding = (scan, title) => (
    <div className="finding-card" key={title}>
      <div className="finding-heading">
        <div>
          <span className="eyebrow">{title} ANALYSIS</span>
          <h3>{title === 'Email' ? 'Email threat assessment' : 'URL threat assessment'}</h3>
        </div>
        <span className={`status-pill ${riskColor(scan.label)}`}>
          {scan.label || 'Unknown'}
        </span>
      </div>
      <div className="risk-row">
        <div>
          <span className="muted">Risk score</span>
          <div className="risk-number">{Number(scan.risk_score ?? 0).toFixed(1)}<small>/100</small></div>
        </div>
        <div className="risk-meter">
          <div
            className={`risk-meter-fill ${riskColor(scan.label)}`}
            style={{ width: `${Math.max(0, Math.min(100, Number(scan.risk_score) || 0))}%` }}
          />
        </div>
      </div>

      {(scan.domain || scan.sender_domain || scan.domain_creation_date) && (
        <div
          className="domain-intel-box"
          style={{
            marginTop: '14px',
            marginBottom: '14px',
            padding: '12px 16px',
            borderRadius: '10px',
            background: 'rgba(15, 23, 42, 0.65)',
            border: '1px solid rgba(148, 163, 184, 0.18)',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '18px',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.88rem'
          }}
        >
          <div>
            <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              Verified Domain
            </span>
            <strong style={{ color: '#e2e8f0' }}>{scan.domain || scan.sender_domain}</strong>
          </div>
          <div>
            <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              Creation Date
            </span>
            <strong style={{ color: scan.domain_creation_date ? '#38bdf8' : '#94a3b8' }}>
              {scan.domain_creation_date || 'Hidden / WHOIS Protected'}
            </strong>
          </div>
          <div>
            <span style={{ color: '#94a3b8', display: 'block', fontSize: '0.75rem', textTransform: 'uppercase' }}>
              Domain Age
            </span>
            <strong style={{ color: typeof scan.domain_age_days === 'number' ? (scan.domain_age_days < 180 ? '#f59e0b' : '#34d399') : '#94a3b8' }}>
              {typeof scan.domain_age_days === 'number'
                ? `${scan.domain_age_days.toLocaleString()} days (${(scan.domain_age_days / 365).toFixed(1)} yrs)`
                : 'Not publicly listed'}
            </strong>
          </div>
        </div>
      )}

      <div className="explanation-block">
        <h4>
          {scan.red_flags?.length ? <AlertTriangle size={16} /> : <ShieldCheck size={16} color="#34d399" />}
          Explainable Threat Analysis
        </h4>

        {scan.red_flags?.length ? (
          <div className="explanation-list">
            {scan.red_flags.map((flag, index) => {
              const detail = explainFlag(flag)
              return (
                <div className="explanation-item" key={index}>
                  <div className="explanation-title">
                    <span className="indicator-number">{index + 1}</span>
                    <strong>{detail.title}</strong>
                    <span className="indicator-status">Detected</span>
                  </div>
                  <p>{detail.explanation}</p>
                  <div className="explanation-detail">
                    <strong>Why is this risky?</strong>
                    <p>{detail.risk}</p>
                  </div>
                  <div className="recommendation-detail">
                    <strong>Recommended action</strong>
                    <p>{detail.action}</p>
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', color: '#a7f3d0', fontSize: '0.9rem' }}>
            <strong>No suspicious indicators detected.</strong> Domain structure, transport security, and content signals passed ThreatLens safety checks.
          </div>
        )}
      </div>

      <div className="risk-interpretation">
        <h4>Risk Score Interpretation</h4>
        <p>
          {Number(scan.risk_score) >= 70
            ? 'The model classifies this result as phishing. Treat it as potentially malicious.'
            : Number(scan.risk_score) >= 40
            ? 'The model classifies this result as suspicious. Additional verification is recommended.'
            : 'The model classifies this result as legitimate. This does not guarantee safety.'}
        </p>
        <div className="threshold-list">
          <span>0–39: Legitimate</span>
          <span>40–69: Suspicious</span>
          <span>70–100: Phishing</span>
        </div>
      </div>

      <button
        className="button secondary no-print"
        onClick={() => {
          if (!user) {
            setAuthPrompt('Sign in or create an account to export and print official PDF reports.')
            return
          }
          window.print()
        }}
      >
        <FileText size={16} /> Export PDF Report
      </button>

      <p className="disclaimer">
        This result is an automated model assessment, not a guarantee that the content is safe or malicious.
      </p>
    </div>
  )

  const renderResult = (record, isStandaloneReport = false) => {
    if (!record) return null
    return (
      <section className="results-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">{isStandaloneReport ? 'OFFICIAL ARCHIVED REPORT' : 'SCAN OUTPUT'}</span>
            <h2>Threat analysis report</h2>
            <p className="muted">Report ID #{String(record.id).slice(-6)} · {formatDate(record.timestamp)}</p>
          </div>
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            {isStandaloneReport && (
              <button className="button secondary no-print" onClick={() => setSelectedReport(null)}>
                <ArrowLeft size={16} /> Back to All Reports
              </button>
            )}
            <button className="button primary no-print" onClick={() => window.print()}>
              <FileText size={16} /> Print / Save PDF
            </button>
          </div>
        </div>
        {record.emailPreview && (
          <div className="input-preview">
            <strong><Mail size={15} /> Scanned email content</strong>
            <p>{record.emailPreview}</p>
          </div>
        )}
        {record.urlPreview && (
          <div className="input-preview">
            <strong><Globe size={15} /> Scanned URL</strong>
            <p className="url-preview">{record.urlPreview}</p>
          </div>
        )}
        <div className="finding-grid">
          {record.result.email && renderFinding(record.result.email, 'Email')}
          {record.result.url && renderFinding(record.result.url, 'URL')}
        </div>
      </section>
    )
  }

  const renderOverview = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">SECURITY OPERATIONS</span>
          <h1>Threat overview</h1>
          <p className="muted">Monitor scans and review detected phishing indicators.</p>
        </div>
        <button className="button primary" onClick={() => goTo('Scanner')}>
          <Search size={17} /> New scan
        </button>
      </div>

      <div className="stats-grid">
        <StatCard icon={Activity} title="Total scan records" value={totals.scans} note="Saved in workspace" tone="blue" />
        <StatCard icon={ShieldAlert} title="Phishing detections" value={totals.phishing} note="Model label: phishing" tone="red" />
        <StatCard icon={AlertTriangle} title="Suspicious detections" value={totals.suspicious} note="Requires manual review" tone="amber" />
        <StatCard icon={ShieldCheck} title="Legitimate detections" value={totals.legitimate} note="Model label: legitimate" tone="green" />
      </div>

      <div className="overview-grid">
        <div className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h3>Scan &amp; Threat Telemetry</h3>
              <p className="muted">7-day volume comparison (Total Scans vs. Threats Flagged)</p>
            </div>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', fontSize: '0.78rem' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#60a5fa' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#60a5fa' }} /> Scans
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', color: '#f87171' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f87171' }} /> Threats
              </span>
            </div>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 12, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.38} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.38} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="day" stroke="#94a3b8" tickLine={false} axisLine={false} fontSize={12} />
                <YAxis allowDecimals={false} stroke="#94a3b8" tickLine={false} axisLine={false} fontSize={12} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 12, boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}
                  labelStyle={{ color: '#f8fafc', fontWeight: 700, marginBottom: 4 }}
                />
                <Area type="monotone" name="Total Scans" dataKey="scans" stroke="#60a5fa" fill="url(#scanGradient)" strokeWidth={2.5} activeDot={{ r: 5 }} />
                <Area type="monotone" name="Threats Flagged" dataKey="threats" stroke="#f87171" fill="url(#threatGradient)" strokeWidth={2.5} activeDot={{ r: 5 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {!history.length && <p className="chart-empty">Your scan telemetry will appear here after your first scan.</p>}
        </div>

        <div className="panel distribution-panel">
          <div className="panel-heading">
            <div>
              <h3>Detection summary</h3>
              <p className="muted">Classification ratio</p>
            </div>
            <BarChart3 size={19} className="muted-icon" />
          </div>
          {[
            ['Phishing', totals.phishing, 'danger'],
            ['Suspicious', totals.suspicious, 'warning'],
            ['Legitimate', totals.legitimate, 'safe']
          ].map(([label, value, tone]) => (
            <div className="distribution-item" key={label}>
              <div className="distribution-label"><span>{label}</span><strong>{value}</strong></div>
              <div className="distribution-track">
                <div className={`distribution-fill ${tone}`} style={{
                  width: `${totals.phishing + totals.suspicious + totals.legitimate
                    ? value / (totals.phishing + totals.suspicious + totals.legitimate) * 100 : 0}%`
                }} />
              </div>
            </div>
          ))}
          <p className="small-note">Synchronized with your ThreatLens scanner workspace.</p>
        </div>
      </div>

      <div className="panel recent-panel">
        <div className="panel-heading">
          <div>
            <h3>Recent scans</h3>
            <p className="muted">Latest scan records</p>
          </div>
          <button className="text-button" onClick={() => goTo('Scan History')}>View history <ChevronRight size={15} /></button>
        </div>
        {history.length ? (
          <HistoryTable
            items={history.slice(0, 5)}
            onSelect={record => { setResult(record); setPage('Scanner') }}
          />
        ) : (
          <EmptyState icon={Search} title="No scans yet" text="Run your first email or URL scan to populate this dashboard." />
        )}
      </div>
    </>
  )

  const renderScanner = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">THREAT DETECTION</span>
          <h1>Security scanner</h1>
          <p className="muted">Submit email content, a URL, or both for real-time Explainable AI analysis.</p>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button className="button secondary small-button" onClick={() => goTo('Overview')}>
            <ArrowLeft size={15} /> Overview
          </button>
          <span className="connection-status"><span /> API: /api/scan/</span>
        </div>
      </div>

      <div className="panel scanner-panel">
        <div className="scanner-tabs">
          <button className={scanType === 'email' ? 'active' : ''} onClick={() => { setScanType('email'); setResult(null) }}><Mail size={16} /> Email scan</button>
          <button className={scanType === 'url' ? 'active' : ''} onClick={() => { setScanType('url'); setResult(null) }}><Globe size={16} /> URL scan</button>
          <button className={scanType === 'both' ? 'active' : ''} onClick={() => { setScanType('both'); setResult(null) }}><Activity size={16} /> Combined scan</button>
        </div>
        <form onSubmit={runScan} className="scan-form">
          {(scanType === 'email' || scanType === 'both') && (
            <label className="form-field">
              <span>Email content</span>
              <textarea value={emailText} onChange={e => setEmailText(e.target.value)} placeholder="Paste the email message here. Include sender claims, links and message body where available..." rows={6} />
              <small>Paste the message text. Avoid entering passwords or other sensitive information.</small>
            </label>
          )}
          {(scanType === 'url' || scanType === 'both') && (
            <label className="form-field">
              <span>Website URL</span>
              <input value={urlText} onChange={e => setUrlText(e.target.value)} placeholder="https://example.com/login" />
              <small>Enter the full URL you want to assess.</small>
            </label>
          )}
          {error && <div className="error-message"><AlertTriangle size={16} /> {error}</div>}
          <div className="form-footer">
            <p className="muted"><Shield size={15} /> Analysis is performed by your configured backend model.</p>
            <button className="button primary" type="submit" disabled={loading}>
              {loading ? <><LoaderCircle className="spin" size={17} /> Analyzing...</> : <><Search size={17} /> Analyze threat</>}
            </button>
          </div>
        </form>
      </div>

      {result ? renderResult(result, false) : (
        <div className="panel scanner-guidance">
          <div className="guidance-icon"><ShieldCheck size={24} /></div>
          <div>
            <h3>Understand the result</h3>
            <p className="muted">The API returns a risk score, a classification label and red-flag indicators. Review the explanation and verify suspicious content through trusted channels before taking action.</p>
          </div>
        </div>
      )}
    </>
  )

  const renderHistory = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">ACTIVITY LOG</span>
          <h1>Scan history</h1>
          <p className="muted">Review all saved scan records in your workspace.</p>
        </div>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button className="button secondary small-button" onClick={() => goTo('Overview')}>
            <ArrowLeft size={15} /> Back
          </button>
          <button className="button danger-outline" onClick={clearHistory} disabled={!history.length}>
            <Trash2 size={16} /> Clear history
          </button>
        </div>
      </div>
      <div className="panel recent-panel">
        {history.length ? (
          <HistoryTable items={history} onSelect={record => { setResult(record); setPage('Scanner') }} />
        ) : (
          <EmptyState icon={Clock3} title="History is empty" text="Your completed scans will be listed here." />
        )}
      </div>
    </>
  )

  const renderReports = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">DOCUMENTATION &amp; AUDIT</span>
          <h1>{selectedReport ? 'Detailed Security Report' : 'Scan reports'}</h1>
          <p className="muted">
            {selectedReport
              ? 'Dedicated forensic summary view — print or export as PDF.'
              : 'Select any saved scan below to open its dedicated report view.'}
          </p>
        </div>
        <button
          className="button secondary small-button no-print"
          onClick={() => (selectedReport ? setSelectedReport(null) : goTo('Overview'))}
        >
          <ArrowLeft size={15} /> {selectedReport ? 'All Reports' : 'Back to Overview'}
        </button>
      </div>

      {selectedReport ? (
        renderResult(selectedReport, true)
      ) : (
        <>
          <div className="panel recent-panel">
            {history.length ? (
              <div className="report-list">
                {history.map(item => {
                  const labels = Object.values(item.result || {}).map(x => x.label).filter(Boolean)
                  const worst = labels.includes('phishing') ? 'phishing' : labels.includes('suspicious') ? 'suspicious' : 'legitimate'
                  const preview = item.urlPreview || item.emailPreview || `${item.type} analysis`
                  return (
                    <div className="report-row" key={item.id}>
                      <div className="report-icon"><FileText size={19} /></div>
                      <div className="report-info" style={{ minWidth: 0, flex: 1 }}>
                        <strong style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {preview.slice(0, 65)}{preview.length > 65 ? '...' : ''}
                        </strong>
                        <span>{formatDate(item.timestamp)} · {item.type.toUpperCase()} scan</span>
                      </div>
                      <span className={`status-pill ${riskColor(worst)}`}>{worst}</span>
                      <button
                        className="button primary small-button"
                        onClick={() => setSelectedReport(item)}
                      >
                        Open Report <ArrowUpRight size={15} />
                      </button>
                    </div>
                  )
                })}
              </div>
            ) : (
              <EmptyState icon={FileText} title="No reports available" text="Reports are generated after you complete a scan." />
            )}
          </div>
          <div className="notice-panel">
            <AlertTriangle size={18} />
            <p><strong>Report limitations:</strong> Reports contain the results returned by the current backend API. They do not include live sandbox detonation unless configured.</p>
          </div>
        </>
      )}
    </>
  )

  const renderAbout = () => (
    <>
      <div className="welcome-row">
        <div>
          <span className="eyebrow">PROJECT INFORMATION</span>
          <h1>About the analyzer</h1>
          <p className="muted">Project scope, architecture and current analysis capabilities.</p>
        </div>
        <button className="button secondary small-button" onClick={() => goTo('Overview')}>
          <ArrowLeft size={15} /> Back
        </button>
      </div>
      <div className="about-hero panel">
        <div className="about-mark"><Shield size={32} /></div>
        <div>
          <span className="eyebrow">MACHINE LEARNING · CYBERSECURITY</span>
          <h2>Phishing Detection &amp; Explainable Threat Analyzer</h2>
          <p className="muted">A web-based application and browser extension that analyzes email text and URLs using trained machine learning models, domain intelligence, and Explainable AI.</p>
        </div>
      </div>
      <div className="about-grid">
        <InfoCard icon={Mail} title="Email analysis" text="Uses text cleaning, TF-IDF vectorization and a trained classification model to assess submitted email content." />
        <InfoCard icon={Globe} title="URL analysis" text="Uses multi-part TLD parsing (.edu.in/.gov.in), WHOIS domain age, HTTPS checks, and lexical ML scoring." />
        <InfoCard icon={Activity} title="Explainable output" text="Displays the model risk score, classification label and clear threat indicators." />
        <InfoCard icon={ShieldCheck} title="Security & Privacy" text="Token-authenticated workspace with encrypted transport and zero third-party data resale." />
      </div>
      <div className="panel methodology-panel">
        <h3>Verified ML Model Evaluation Benchmarks</h3>
        <p className="muted" style={{ marginBottom: '14px' }}>Evaluated on an 80/20 stratified test split across 5,807 email samples and 235,795 URL samples.</p>
        <div className="about-grid" style={{ marginBottom: '18px' }}>
          <div className="stat-card">
            <span className="eyebrow">EMAIL CLASSIFIER (RF + TF-IDF)</span>
            <strong className="stat-value">98.80% Accuracy</strong>
            <span className="stat-note">Precision: 97.96% · Recall: 97.96% · F1-Score: 97.96%</span>
            <span className="stat-note">Test Set (1,162): 812 TN, 336 TP, 7 FP, 7 FN</span>
          </div>
          <div className="stat-card">
            <span className="eyebrow">URL CLASSIFIER (RF + LEXICAL)</span>
            <strong className="stat-value">93.78% Accuracy</strong>
            <span className="stat-note">Precision: 91.25% · Recall: 98.57% · F1-Score: 94.77%</span>
            <span className="stat-note">Test Set (47,159): 17,641 TN, 26,583 TP, 2,548 FP, 387 FN</span>
          </div>
        </div>
      </div>
    </>
  )

  if (showAuth) {
    return (
      <>
        <AuthScreen
          authMode={authMode}
          setAuthMode={setAuthMode}
          authForm={authForm}
          setAuthForm={setAuthForm}
          handleAuth={handleAuth}
          authLoading={authLoading}
          authError={authError}
          authSuccess={authSuccess}
          onGuest={() => setShowAuth(false)}
          onOpenLegal={(type) => setLegalModal(type)}
        />
        <LegalModal type={legalModal} onClose={() => setLegalModal('')} />
      </>
    )
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-icon"><Shield size={22} /></div>
          <div><strong>ThreatLens</strong><span>SECURITY ANALYZER</span></div>
          <button className="mobile-close" onClick={() => setMobileMenu(false)}><X size={19} /></button>
        </div>
        <div className="sidebar-label">WORKSPACE</div>
        <nav className="side-nav">
          {navItems.map(item => {
            const Icon = item.icon
            return (
              <button key={item.name} className={page === item.name ? 'selected' : ''} onClick={() => goTo(item.name)}>
                <Icon size={18} /><span>{item.name}</span>
                {page === item.name && <ChevronRight size={15} className="nav-chevron" />}
              </button>
            )
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="system-card">
            <span className="system-dot" />
            <div><strong>ThreatLens Cloud</strong><small>Security patch active</small></div>
          </div>

          <div className="profile-row">
            <div className="avatar">
              {user ? user.username?.charAt(0).toUpperCase() : 'G'}
            </div>
            <div className="profile-info">
              <strong>{user ? user.username : 'Guest Workspace'}</strong>
              <small>{user ? user.email : 'Guest Access'}</small>
            </div>
          </div>

          {user ? (
            <button className="sidebar-auth-button" onClick={handleLogout}>
              <LogOut size={16} /> Logout
            </button>
          ) : (
            <button className="sidebar-auth-button" onClick={() => setShowAuth(true)}>
              <ShieldCheck size={16} /> Sign In / Create Account
            </button>
          )}
        </div>
      </aside>

      {mobileMenu && <button className="mobile-overlay" onClick={() => setMobileMenu(false)} aria-label="Close navigation" />}

      <main className="main-area" style={{ paddingBottom: '74px' }}>
        <header className="topbar">
          <button className="mobile-menu-button" onClick={() => setMobileMenu(true)}><Menu size={20} /></button>
          <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>{page}</strong></div>
          <div className="topbar-right">
            <span className="top-status"><span /> System ready</span>

            <div className="notif-wrapper">
              <button
                type="button"
                className="top-icon-btn"
                onClick={() => setShowNotifications(!showNotifications)}
                aria-label="Security Alerts"
              >
                <Bell size={18} />
                {unreadAlertCount > 0 && (
                  <span className="notif-badge">{unreadAlertCount}</span>
                )}
              </button>
              {showNotifications && (
                <div className="notif-dropdown" style={{ width: '320px', maxWidth: '90vw' }}>
                  <div className="notif-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong>Security Alerts ({unreadAlertCount} new)</strong>
                    {alertItems.length > 0 && (
                      <button
                        type="button"
                        onClick={markAllAlertsRead}
                        style={{ background: 'none', border: 'none', color: '#38bdf8', fontSize: '0.75rem', cursor: 'pointer', fontWeight: 600 }}
                      >
                        Mark all read
                      </button>
                    )}
                  </div>
                  {alertItems.map(item => {
                    const isRead = readNotifs.includes(String(item.id))
                    return (
                      <div
                        key={item.id}
                        className="notif-item"
                        style={{
                          opacity: isRead ? 0.62 : 1,
                          borderLeft: isRead ? '3px solid transparent' : '3px solid #ef4444',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: '8px'
                        }}
                        onClick={() => {
                          markNotifRead(item.id)
                          setSelectedReport(item)
                          setPage('Reports')
                          setShowNotifications(false)
                        }}
                      >
                        <div style={{ minWidth: 0, flex: 1 }}>
                          <strong style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {!isRead && <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />}
                            {item.type.toUpperCase()} Threat Flagged
                          </strong>
                          <small style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {item.urlPreview || item.emailPreview || formatDate(item.timestamp)}
                          </small>
                        </div>
                        <div style={{ display: 'flex', gap: '4px' }}>
                          {!isRead && (
                            <button
                              type="button"
                              title="Mark as read"
                              onClick={(e) => markNotifRead(item.id, e)}
                              style={{ background: 'rgba(56,189,248,0.15)', border: 'none', color: '#38bdf8', borderRadius: 6, padding: '4px 6px', cursor: 'pointer' }}
                            >
                              <Check size={13} />
                            </button>
                          )}
                          <button
                            type="button"
                            title="Dismiss alert"
                            onClick={(e) => dismissNotif(item.id, e)}
                            style={{ background: 'rgba(239,68,68,0.15)', border: 'none', color: '#f87171', borderRadius: 6, padding: '4px 6px', cursor: 'pointer' }}
                          >
                            <X size={13} />
                          </button>
                        </div>
                      </div>
                    )
                  })}
                  {alertItems.length === 0 && (
                    <p className="notif-empty">All caught up! No unread security alerts.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="page-content">
          {page === 'Overview' && renderOverview()}
          {page === 'Scanner' && renderScanner()}
          {page === 'Scan History' && renderHistory()}
          {page === 'Reports' && renderReports()}
          {page === 'About Project' && renderAbout()}

          <footer className="app-footer" style={{ flexWrap: 'wrap', gap: '12px' }}>
            <span>ThreatLens · Phishing Detection &amp; Explainable Threat Analyzer</span>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              <button type="button" onClick={() => setLegalModal('terms')} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.82rem', textDecoration: 'underline' }}>
                Terms &amp; Conditions
              </button>
              <button type="button" onClick={() => setLegalModal('privacy')} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '0.82rem', textDecoration: 'underline' }}>
                Privacy Policy
              </button>
              <button type="button" onClick={() => setLegalModal('security')} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', fontSize: '0.82rem', textDecoration: 'underline' }}>
                Security &amp; Compliance
              </button>
            </div>
          </footer>
        </div>
      </main>

      {/* Mobile Sticky Bottom Navigation Bar */}
      <nav
        className="mobile-bottom-nav no-print"
        style={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          zIndex: 900,
          background: 'rgba(15, 23, 42, 0.96)',
          backdropFilter: 'blur(12px)',
          borderTop: '1px solid rgba(148, 163, 184, 0.18)',
          display: 'none',
          justifyContent: 'space-around',
          padding: '6px 4px'
        }}
      >
        {navItems.map(item => {
          const Icon = item.icon
          const active = page === item.name
          return (
            <button
              key={item.name}
              type="button"
              onClick={() => goTo(item.name)}
              style={{
                background: 'none',
                border: 'none',
                color: active ? '#38bdf8' : '#94a3b8',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '3px',
                fontSize: '0.7rem',
                fontWeight: active ? 700 : 500,
                padding: '4px 8px',
                cursor: 'pointer'
              }}
            >
              <Icon size={18} />
              <span>{item.short}</span>
            </button>
          )
        })}
      </nav>

      {authPrompt && (
        <div className="modal-backdrop" onClick={() => setAuthPrompt('')}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-icon"><Lock size={24} /></div>
            <h3>Registered Feature</h3>
            <p>{authPrompt}</p>
            <div className="modal-actions">
              <button className="button primary" onClick={() => { setAuthPrompt(''); setAuthMode('signup'); setShowAuth(true) }}>
                Create Account
              </button>
              <button className="button secondary" onClick={() => { setAuthPrompt(''); setAuthMode('login'); setShowAuth(true) }}>
                Sign In
              </button>
            </div>
            <button className="modal-close-text" onClick={() => setAuthPrompt('')}>
              Continue as Guest
            </button>
          </div>
        </div>
      )}

      <LegalModal type={legalModal} onClose={() => setLegalModal('')} />
    </div>
  )
}

function LegalModal({ type, onClose }) {
  if (!type) return null
  const content = {
    terms: {
      title: 'Terms & Conditions',
      items: [
        'ThreatLens is provided for defensive cybersecurity analysis, educational research, and personal phishing verification.',
        'Automated risk scores and Explainable AI indicators assist human decision-making and do not constitute an absolute legal or financial guarantee.',
        'Users must not submit unlawful content, private credentials, or attempt automated abuse/scraping of the scanning API.'
      ]
    },
    privacy: {
      title: 'Privacy Policy & Data Protection',
      items: [
        'Zero Data Selling: Submitted emails and URLs are processed solely for threat classification and are never sold or shared with advertisers.',
        'Guest Mode scans remain transient in your browser session; Registered User scan histories are isolated per account via token authentication.',
        'Do not paste sensitive passwords, banking PINs, or private OTPs into the scanner input box.'
      ]
    },
    security: {
      title: 'Security Architecture & Patch Notes',
      items: [
        'Transport Security: All API communications enforce HTTPS/TLS encryption with token-based session validation.',
        'Browser Extension Isolation: Content scripts route scans through a privileged Manifest V3 background service worker to prevent page-level CSP tampering.',
        'Input & SSRF Hardening: URLs and text payloads are sanitized prior to lexical and WHOIS evaluation.'
      ]
    }
  }[type]

  return (
    <div className="modal-backdrop" onClick={onClose} style={{ zIndex: 2000 }}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '520px', textAlign: 'left' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldCheck size={22} color="#38bdf8" />
            <h3 style={{ margin: 0 }}>{content.title}</h3>
          </div>
          <button type="button" onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>
        <ul style={{ paddingLeft: '18px', color: '#cbd5e1', fontSize: '0.9rem', lineHeight: 1.6, margin: '0 0 18px' }}>
          {content.items.map((pt, idx) => <li key={idx} style={{ marginBottom: '8px' }}>{pt}</li>)}
        </ul>
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" className="button primary" onClick={onClose}>Acknowledge &amp; Close</button>
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, title, value, note, tone }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}><Icon size={19} /></div>
      <span className="stat-title">{title}</span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-note">{note}</span>
    </div>
  )
}

function HistoryTable({ items, onSelect }) {
  return (
    <div className="table-scroll">
      <table className="history-table">
        <thead>
          <tr><th>SCAN TYPE</th><th>DATE &amp; TIME</th><th>DETECTION</th><th>RESULT</th><th /></tr>
        </thead>
        <tbody>
          {items.map(item => {
            const scans = Object.entries(item.result || {})
            const labels = scans.map(([, scan]) => scan.label || 'unknown')
            const worst = labels.includes('phishing') ? 'phishing' : labels.includes('suspicious') ? 'suspicious' : labels[0] || 'unknown'
            return (
              <tr key={item.id}>
                <td><span className="type-cell">{item.type === 'email' ? <Mail size={15} /> : item.type === 'url' ? <Globe size={15} /> : <Activity size={15} />}{item.type}</span></td>
                <td>{new Date(item.timestamp).toLocaleString()}</td>
                <td>{scans.map(([type]) => type).join(' + ')}</td>
                <td><span className={`status-pill ${riskColor(worst)}`}>{worst}</span></td>
                <td><button className="icon-button" onClick={() => onSelect(item)} aria-label="View scan result"><ArrowUpRight size={17} /></button></td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function EmptyState({ icon: Icon, title, text }) {
  return (
    <div className="empty-state">
      <div><Icon size={22} /></div>
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  )
}

function InfoCard({ icon: Icon, title, text }) {
  return (
    <div className="panel info-card">
      <div className="info-icon"><Icon size={19} /></div>
      <h3>{title}</h3>
      <p className="muted">{text}</p>
    </div>
  )
}

function AuthScreen({
  authMode,
  setAuthMode,
  authForm,
  setAuthForm,
  handleAuth,
  authLoading,
  authError,
  authSuccess,
  onGuest,
  onOpenLegal
}) {
  const isSignup = authMode === 'signup'
  const isReset = authMode === 'reset'
  const [resetEmail, setResetEmail] = useState('')
  const [resetOtp, setResetOtp] = useState('')
  const [resetNewPassword, setResetNewPassword] = useState('')
  const [otpSent, setOtpSent] = useState(false)
  const [resendTimer, setResendTimer] = useState(0)
  const [resetBusy, setResetBusy] = useState(false)
  const [resetErr, setResetErr] = useState('')
  const [resetMsg, setResetMsg] = useState('')
  const [localError, setLocalError] = useState('')
  const [localSuccess, setLocalSuccess] = useState('')

  useEffect(() => {
    if (resendTimer <= 0) return
    const interval = setInterval(() => {
      setResendTimer(prev => (prev > 0 ? prev - 1 : 0))
    }, 1000)
    return () => clearInterval(interval)
  }, [resendTimer])

  const onValidatedAuthSubmit = (e) => {
    e.preventDefault()
    setLocalError('')
    setLocalSuccess('')
    if (!authForm.username.trim()) {
      setLocalError('Please enter your username.')
      return
    }
    if (isSignup && !authForm.email.trim()) {
      setLocalError('Please enter your email address.')
      return
    }
    if (!authForm.password) {
      setLocalError('Please enter your password.')
      return
    }
    handleAuth(e)
  }

  const requestOtpCode = async () => {
    if (!resetEmail.trim()) {
      setResetErr('Please enter your registered email address.')
      return
    }
    setResetBusy(true); setResetErr(''); setResetMsg('')
    try {
      const res = await fetch(`${API_BASE_URL}/auth/send-reset-otp/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail.trim() })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to send OTP')
      setOtpSent(true)
      setResendTimer(60)
      setResetMsg(data.message || '6-digit OTP sent to your email.')
    } catch (err) {
      setResetErr(err.message)
    } finally {
      setResetBusy(false)
    }
  }

  const handleSendOtp = (e) => { e.preventDefault(); requestOtpCode() }

  const handleConfirmReset = async (e) => {
    e.preventDefault()
    setResetErr(''); setResetMsg('')
    if (!resetOtp.trim() || resetOtp.trim().length < 6) {
      setResetErr('Please enter the 6-digit OTP code.')
      return
    }
    if (!resetNewPassword) {
      setResetErr('Please enter a strong new password.')
      return
    }
    setResetBusy(true)
    try {
      const res = await fetch(`${API_BASE_URL}/auth/reset-password/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: resetEmail.trim(),
          otp: resetOtp.trim(),
          new_password: resetNewPassword
        })
      })
      const data = await res.json()
      if (!res.ok) {
        const msg = Array.isArray(data.error) ? data.error.join(' ') : data.error
        throw new Error(msg || 'Password reset failed')
      }
      setOtpSent(false); setResetOtp(''); setResetNewPassword(''); setResendTimer(0)
      setLocalError('')
      setLocalSuccess(data.message || 'Password reset successful! Please sign in with your new password.')
      setAuthMode('login')
    } catch (err) {
      setResetErr(err.message)
    } finally {
      setResetBusy(false)
    }
  }

  const displayError = localError || authError
  const displaySuccess = localSuccess || authSuccess

  return (
    <div className="auth-page auth-split-layout">
      {/* Left Brand & Live Security Showcase (Automatically visible on Desktop/Laptop, hidden on Mobile) */}
      <div className="auth-showcase-panel">
        <div className="showcase-inner">
          <div className="auth-brand" style={{ marginBottom: '28px' }}>
            <div className="auth-logo" style={{ width: 52, height: 52 }}>
              <ShieldCheck size={30} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.55rem' }}>ThreatLens</h2>
              <span>EXPLAINABLE THREAT ANALYZER</span>
            </div>
          </div>

          <span className="eyebrow" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={14} /> AI-POWERED CYBER DEFENSE
          </span>
          <h1 style={{ fontSize: '2.15rem', lineHeight: 1.2, margin: '10px 0 14px', color: '#f8fafc' }}>
            Detect Phishing Before It Reaches Your Credentials.
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '0.98rem', lineHeight: 1.6, marginBottom: '26px' }}>
            Real-time machine learning inspection for suspicious emails, deceptive URLs, and live browser protection with transparent risk reasoning.
          </p>

          <div className="showcase-metrics">
            <div className="showcase-metric-card">
              <strong>98.8%</strong>
              <span>Email Detection Accuracy</span>
            </div>
            <div className="showcase-metric-card">
              <strong>&lt; 50ms</strong>
              <span>Zero-Delay Link Hover Guard</span>
            </div>
            <div className="showcase-metric-card">
              <strong>WHOIS + ML</strong>
              <span>Domain Age &amp; Lexical Audit</span>
            </div>
          </div>

          <div className="showcase-preview-box">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '0.76rem', fontWeight: 700, color: '#38bdf8' }}>LIVE EXPLAINABLE AI ENGINE</span>
              <span style={{ fontSize: '0.72rem', background: 'rgba(16,185,129,0.16)', color: '#34d399', padding: '2px 8px', borderRadius: 99 }}>ACTIVE</span>
            </div>
            <p style={{ margin: 0, fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.5 }}>
              Protects webmail, WhatsApp Web, and direct links against credential harvesting, spoofed domains, and unencrypted login traps.
            </p>
          </div>
        </div>
      </div>

      {/* Right Authentication Card */}
      <div className="auth-form-column">
        <div className="auth-card">
          <div className="auth-brand mobile-only-brand">
            <div className="auth-logo"><ShieldCheck size={27} /></div>
            <div><h2>ThreatLens</h2><span>SECURITY ANALYZER</span></div>
          </div>

          <div className="auth-heading">
            <span className="eyebrow">SECURE WORKSPACE</span>
            <h1>{isReset ? 'Reset your password' : isSignup ? 'Create your account' : 'Welcome back'}</h1>
            <p>
              {isReset
                ? 'Verify your registered email with a 6-digit OTP to set a new password.'
                : isSignup
                  ? 'Create an account to manage your security scans & PDF reports.'
                  : 'Sign in to access your security workspace.'}
            </p>
          </div>

          {!isReset && (
            <div className="auth-tabs">
              <button
                type="button"
                className={!isSignup ? 'active' : ''}
                onClick={() => { setLocalError(''); setLocalSuccess(''); setAuthMode('login') }}
              >
                Login
              </button>
              <button
                type="button"
                className={isSignup ? 'active' : ''}
                onClick={() => { setLocalError(''); setLocalSuccess(''); setAuthMode('signup') }}
              >
                Sign Up
              </button>
            </div>
          )}

          {isReset ? (
            <form onSubmit={otpSent ? handleConfirmReset : handleSendOtp} className="auth-form" noValidate>
              <label className="form-field">
                <span>Registered Email</span>
                <input type="email" value={resetEmail} onChange={e => setResetEmail(e.target.value)} placeholder="Enter your registered email" disabled={otpSent} />
              </label>

              {otpSent && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem', marginTop: '-4px' }}>
                    <span className="muted">{resendTimer > 0 ? `Resend OTP in ${resendTimer}s` : 'Did not receive code?'}</span>
                    <button
                      type="button"
                      className="auth-link"
                      style={{ margin: 0, opacity: resendTimer > 0 ? 0.5 : 1, cursor: resendTimer > 0 ? 'not-allowed' : 'pointer' }}
                      disabled={resendTimer > 0 || resetBusy}
                      onClick={requestOtpCode}
                    >
                      {resendTimer > 0 ? `Wait ${resendTimer}s` : 'Resend OTP'}
                    </button>
                  </div>
                  <label className="form-field">
                    <span>6-Digit OTP</span>
                    <input type="text" maxLength={6} value={resetOtp} onChange={e => setResetOtp(e.target.value.replace(/\D/g, ''))} placeholder="Enter 6-digit code" />
                  </label>
                  <label className="form-field">
                    <span>New Password</span>
                    <input type="password" value={resetNewPassword} onChange={e => setResetNewPassword(e.target.value)} placeholder="Enter strong new password" />
                  </label>
                </>
              )}

              {resetErr && <div className="error-message"><AlertTriangle size={16} /> {resetErr}</div>}
              {resetMsg && <div className="auth-success"><CheckCircle2 size={16} /> {resetMsg}</div>}

              <button className="button primary auth-submit" type="submit" disabled={resetBusy}>
                {resetBusy ? 'Please wait...' : otpSent ? 'Verify OTP & Reset Password' : 'Send 6-Digit OTP'}
              </button>
              <button
                type="button"
                className="auth-link"
                onClick={() => { setOtpSent(false); setResetErr(''); setResetMsg(''); setResendTimer(0); setAuthMode('login') }}
              >
                Back to Sign In
              </button>
            </form>
          ) : (
            <>
              <form onSubmit={onValidatedAuthSubmit} className="auth-form" noValidate>
                <label className="form-field">
                  <span>Username</span>
                  <input type="text" value={authForm.username} onChange={e => { setLocalError(''); setAuthForm({ ...authForm, username: e.target.value }) }} placeholder="Enter username" />
                </label>

                {isSignup && (
                  <label className="form-field">
                    <span>Email address</span>
                    <input type="email" value={authForm.email} onChange={e => { setLocalError(''); setAuthForm({ ...authForm, email: e.target.value }) }} placeholder="Enter email address" />
                  </label>
                )}

                <label className="form-field">
                  <span>Password</span>
                  <input type="password" value={authForm.password} onChange={e => { setLocalError(''); setAuthForm({ ...authForm, password: e.target.value }) }} placeholder="Enter password" />
                </label>

                {displayError && <div className="error-message"><AlertTriangle size={16} /> {displayError}</div>}
                {displaySuccess && <div className="auth-success"><CheckCircle2 size={16} /> {displaySuccess}</div>}

                <button className="button primary auth-submit" type="submit" disabled={authLoading}>
                  {authLoading ? 'Please wait...' : isSignup ? 'Create Account' : 'Sign In'}
                </button>
              </form>

              {!isSignup && (
                <button
                  type="button"
                  className="auth-link"
                  onClick={() => { setResetErr(''); setResetMsg(''); setOtpSent(false); setResendTimer(0); setLocalError(''); setLocalSuccess(''); setAuthMode('reset') }}
                >
                  Forgot password?
                </button>
              )}
            </>
          )}

          <div className="auth-divider"><span>OR</span></div>
          <button type="button" className="button secondary auth-guest" onClick={onGuest}>
            Continue as Guest
          </button>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', marginTop: '14px', fontSize: '0.78rem' }}>
            <button type="button" onClick={() => onOpenLegal('terms')} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', textDecoration: 'underline' }}>
              Terms
            </button>
            <button type="button" onClick={() => onOpenLegal('privacy')} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', textDecoration: 'underline' }}>
              Privacy Policy
            </button>
            <button type="button" onClick={() => onOpenLegal('security')} style={{ background: 'none', border: 'none', color: '#38bdf8', cursor: 'pointer', textDecoration: 'underline' }}>
              Security
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
