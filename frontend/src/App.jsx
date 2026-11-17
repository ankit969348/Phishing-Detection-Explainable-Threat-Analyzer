import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, BarChart3, Bell,
  CheckCircle2, ChevronRight, Clock3, FileText, Globe,
  LayoutDashboard, LoaderCircle, LogOut, Mail, Menu, Search, Lock,
  Shield, ShieldAlert, ShieldCheck, Trash2, X
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import './App.css'








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


  const [history, setHistory] = useState([])
  const [authPrompt, setAuthPrompt] = useState('')
  const [showNotifications, setShowNotifications] = useState(false)


  const [mobileMenu, setMobileMenu] = useState(false)


// Authentication states
const [token, setToken] = useState(
  () => localStorage.getItem('threatlens-token') || ''
)
const [user, setUser] = useState(null)
const [authMode, setAuthMode] = useState('login')
const [showAuth, setShowAuth] = useState(true)
const [authLoading, setAuthLoading] = useState(false)
const [authError, setAuthError] = useState('')
const [authSuccess, setAuthSuccess] = useState('')

const [authForm, setAuthForm] = useState({
  username: '',
  email: '',
  password: ''
})
 // django api history


const fetchDbHistory = async (authToken) => {
    try {
      const res = await fetch('/api/history/', {
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
        const response = await fetch('/api/auth/me/', {
          headers: {
            Authorization: `Token ${token}`
          }
        })

        if (!response.ok) {
          throw new Error('Session expired')
        }

        const data = await response.json()
        setUser(data)
        fetchDbHistory(token)

      } catch (error) {
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
  setAuthForm({
    username: '',
    email: '',
    password: ''
  })
}

const handleAuth = async (event) => {
  event.preventDefault()

  setAuthLoading(true)
  setAuthError('')
  setAuthSuccess('')

  const endpoint =
    authMode === 'signup'
      ? '/api/auth/signup/'
      : '/api/auth/login/'

  const payload =
    authMode === 'signup'
      ? authForm
      : {
          username: authForm.username,
          password: authForm.password
        }

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        Array.isArray(data.error)
          ? data.error.join(' ')
          : data.error || 'Authentication failed.'
      )
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
      await fetch('/api/auth/logout/', {
        method: 'POST',
        headers: {
          Authorization: `Token ${token}`
        }
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
      const response = await fetch('/api/scan/', {
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
      setError(`${err.message}. Check that the Django server is running on port 8000.`)
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
        await fetch('/api/history/', {
          method: 'DELETE',
          headers: { Authorization: `Token ${token}` }
        })
      } catch (err) {
        console.error(err)
      }
      setHistory([])
      setResult(null)
    }
  }

  const navItems = [
    { name: 'Overview', icon: LayoutDashboard },
    { name: 'Scanner', icon: Search },
    { name: 'Scan History', icon: Clock3 },
    { name: 'Reports', icon: FileText },
    { name: 'About Project', icon: Shield }
  ]

  const goTo = (name) => {
    if (!user && (name === 'Scan History' || name === 'Reports')) {
      setAuthPrompt(`Create a free account or sign in to access ${name} and export PDF security reports.`)
      setMobileMenu(false)
      return
    }
    setPage(name)
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




       <div className="explanation-block">
  <h4>
    <AlertTriangle size={16} />
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
    <p className="muted">No red flags returned. This does not guarantee safety.</p>
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

  const renderResult = (record) => {
    if (!record) return null
    return (
      <section className="results-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">SCAN OUTPUT</span>
            <h2>Threat analysis report</h2>
            <p className="muted">{formatDate(record.timestamp)}</p>
          </div>
          <button className="button secondary" onClick={() => window.print()}>
            <FileText size={16} /> Print report
          </button>
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
        <StatCard icon={Activity} title="Total scan records" value={totals.scans} note="Saved in this browser" tone="blue" />
        <StatCard icon={ShieldAlert} title="Phishing detections" value={totals.phishing} note="Model label: phishing" tone="red" />
        <StatCard icon={AlertTriangle} title="Suspicious detections" value={totals.suspicious} note="Requires manual review" tone="amber" />
        <StatCard icon={ShieldCheck} title="Legitimate detections" value={totals.legitimate} note="Model label: legitimate" tone="green" />
      </div>

      <div className="overview-grid">
        <div className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h3>Scan activity</h3>
              <p className="muted">Last 7 days, based on saved scan records</p>
            </div>
            <span className="subtle-tag">7 DAYS</span>
          </div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#263448" />
                <XAxis dataKey="day" stroke="#8190a5" tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} stroke="#8190a5" tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: '#111d2d', border: '1px solid #293b53', borderRadius: 10 }} />
                <Area type="monotone" dataKey="scans" stroke="#60a5fa" fill="url(#scanGradient)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {!history.length && <p className="chart-empty">Your scan activity will appear here after your first scan.</p>}
        </div>

        <div className="panel distribution-panel">
          <div className="panel-heading">
            <div>
              <h3>Detection summary</h3>
              <p className="muted">Based on saved scan results</p>
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
          <p className="small-note">Counts are derived from this browser's saved scan history, not from a central server.</p>
        </div>
      </div>

      <div className="panel recent-panel">
        <div className="panel-heading">
          <div>
            <h3>Recent scans</h3>
            <p className="muted">Latest scan records saved on this device</p>
          </div>
          <button className="text-button" onClick={() => goTo('Scan History')}>View history <ChevronRight size={15} /></button>
        </div>
        {history.length ? (
          <HistoryTable items={history.slice(0, 5)} onSelect={setResult} onOpen={() => goTo('Scanner')} />
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
          <p className="muted">Submit email content, a URL, or both for analysis by your Django ML API.</p>
        </div>
        <span className="connection-status"><span /> API route: /api/scan/</span>
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
              <textarea value={emailText} onChange={e => setEmailText(e.target.value)} placeholder="Paste the email message here. Include sender claims, links and message body where available..." rows={7} />
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

      {result ? renderResult(result) : (
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
          <p className="muted">Review scan records saved locally in this browser.</p>
        </div>
        <button className="button danger-outline" onClick={clearHistory} disabled={!history.length}><Trash2 size={16} /> Clear history</button>
      </div>
      <div className="panel recent-panel">
        {history.length ? (
          <HistoryTable items={history} onSelect={record => { setResult(record); setPage('Scanner') }} onOpen={() => setPage('Scanner')} />
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
          <span className="eyebrow">DOCUMENTATION</span>
          <h1>Scan reports</h1>
          <p className="muted">Open a saved analysis and print it or save it as PDF.</p>
        </div>
      </div>
      <div className="panel recent-panel">
        {history.length ? (
          <div className="report-list">
            {history.map(item => {
              const labels = Object.values(item.result || {}).map(x => x.label).filter(Boolean)
              const worst = labels.includes('phishing') ? 'phishing' : labels.includes('suspicious') ? 'suspicious' : 'legitimate'
              return (
                <div className="report-row" key={item.id}>
                  <div className="report-icon"><FileText size={19} /></div>
                  <div className="report-info">
                    <strong>Threat analysis report</strong>
                    <span>{formatDate(item.timestamp)} · {item.type} scan</span>
                  </div>
                  <span className={`status-pill ${riskColor(worst)}`}>{worst}</span>
                  <button className="button secondary small-button" onClick={() => { setResult(item); setPage('Scanner') }}>Open report <ArrowUpRight size={15} /></button>
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
        <p><strong>Report limitations:</strong> Reports contain the results returned by the current backend API. They do not include forensic evidence, sender authentication checks or external reputation lookups unless those capabilities are added to the backend.</p>
      </div>
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
      </div>
      <div className="about-hero panel">
        <div className="about-mark"><Shield size={32} /></div>
        <div>
          <span className="eyebrow">MACHINE LEARNING · CYBERSECURITY</span>
          <h2>Phishing Detection &amp; Explainable Threat Analyzer</h2>
          <p className="muted">A web-based application that analyzes submitted email text and URLs using trained machine learning models and returns risk assessments with detection indicators.</p>
        </div>
      </div>
      <div className="about-grid">
        <InfoCard icon={Mail} title="Email analysis" text="Uses text cleaning, TF-IDF vectorization and a trained classification model to assess submitted email content." />
        <InfoCard icon={Globe} title="URL analysis" text="Uses URL characteristics such as length, dots, hyphens, subdomains, IP presence, HTTPS and suspicious terms." />
        <InfoCard icon={Activity} title="Explainable output" text="Displays the model risk score, classification label and heuristic red flags returned by the backend." />
        <InfoCard icon={ShieldCheck} title="Backend architecture" text="React frontend communicates with a Django REST API through the Vite development proxy." />
      </div>
      <div className="panel methodology-panel">
          <h3>Verified ML Model Evaluation Benchmarks</h3>
          <p className="muted" style={{marginBottom: "14px"}}>Evaluated on an 80/20 stratified test split across 5,807 email samples and 235,795 URL samples.</p>
          <div className="about-grid" style={{marginBottom: "18px"}}>
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
          <h3>Current system workflow</h3>
          <ol>
            <li>User submits email content, URL or both through the scanner.</li>
            <li>React sends a POST request to <code>/api/scan/</code>.</li>
            <li>Django passes the input to the corresponding trained ML model.</li>
            <li>The backend returns a risk score, label and red-flag indicators.</li>
            <li>The dashboard displays the result and saves authenticated scan records to PostgreSQL.</li>
          </ol>
        </div>
    </>
  )



      if (showAuth) {
  return (
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
    />
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
            <div><strong>Local analyzer</strong><small>Development environment</small></div>
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
  <button
    className="sidebar-auth-button"
    onClick={handleLogout}
  >
    <LogOut size={16} />
    Logout
  </button>
) : (
  <button
    className="sidebar-auth-button"
    onClick={() => setShowAuth(true)}
  >
    <ShieldCheck size={16} />
    Sign In / Create Account
  </button>
)}



        </div>
      </aside>

      {mobileMenu && <button className="mobile-overlay" onClick={() => setMobileMenu(false)} aria-label="Close navigation" />}

      <main className="main-area">
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
                  {totals.phishing + totals.suspicious > 0 && (
                    <span className="notif-badge">{totals.phishing + totals.suspicious}</span>
                  )}
                </button>
                {showNotifications && (
                  <div className="notif-dropdown">
                    <div className="notif-header">
                      <strong>Security Alerts</strong>
                      <span>{totals.phishing + totals.suspicious} flagged</span>
                    </div>
                    {history
                      .filter(h =>
                        Object.values(h.result || {}).some(s =>
                          ['phishing', 'suspicious'].includes((s.label || '').toLowerCase())
                        )
                      )
                      .slice(0, 4)
                      .map(item => (
                        <div
                          key={item.id}
                          className="notif-item"
                          onClick={() => {
                            setResult(item)
                            setPage('Scanner')
                            setShowNotifications(false)
                          }}
                        >
                          <strong>{item.type.toUpperCase()} Threat Flagged</strong>
                          <small>{formatDate(item.timestamp)}</small>
                        </div>
                      ))}
                    {totals.phishing + totals.suspicious === 0 && (
                      <p className="notif-empty">No phishing or suspicious alerts yet.</p>
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
          <footer className="app-footer">
            <span>ThreatLens · Phishing Detection &amp; Explainable Threat Analyzer</span>
            <span>For educational and defensive security use</span>
          </footer>
        </div>
      </main>

      
        {authPrompt && (
          <div className="modal-backdrop" onClick={() => setAuthPrompt('')}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()}>
              <div className="modal-icon"><Lock size={24} /></div>
              <h3>Registered Feature</h3>
              <p>{authPrompt}</p>
              <div className="modal-actions">
                <button
                  className="button primary"
                  onClick={() => {
                    setAuthPrompt('')
                    setAuthMode('signup')
                    setShowAuth(true)
                  }}
                >
                  Create Account
                </button>
                <button
                  className="button secondary"
                  onClick={() => {
                    setAuthPrompt('')
                    setAuthMode('login')
                    setShowAuth(true)
                  }}
                >
                  Sign In
                </button>
              </div>
              <button className="modal-close-text" onClick={() => setAuthPrompt('')}>
                Continue as Guest
              </button>
            </div>
          </div>
        )}
      
     


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
  onGuest
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

  const apiBase = typeof API_BASE_URL !== 'undefined' ? API_BASE_URL : 'http://127.0.0.1:8000/api'

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
      const res = await fetch(`${apiBase}/auth/send-reset-otp/`, {
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

  const handleSendOtp = (e) => {
    e.preventDefault()
    requestOtpCode()
  }

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
      const res = await fetch(`${apiBase}/auth/reset-password/`, {
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
    <div className="auth-page">
      <div className="auth-card">

        <div className="auth-brand">
          <div className="auth-logo">
            <ShieldCheck size={27} />
          </div>
          <div>
            <h2>ThreatLens</h2>
            <span>SECURITY ANALYZER</span>
          </div>
        </div>

        <div className="auth-heading">
          <span className="eyebrow">SECURE WORKSPACE</span>
          <h1>{isReset ? 'Reset your password' : isSignup ? 'Create your account' : 'Welcome back'}</h1>
          <p>
            {isReset
              ? 'Verify your registered email with a 6-digit OTP to set a new password.'
              : isSignup
                ? 'Create an account to manage your security scans.'
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
              <input
                type="email"
                value={resetEmail}
                onChange={e => setResetEmail(e.target.value)}
                placeholder="Enter your registered email"
                disabled={otpSent}
              />
            </label>

            {otpSent && (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.85rem', marginTop: '-4px' }}>
                  <span className="muted">
                    {resendTimer > 0 ? `Resend OTP in ${resendTimer}s` : 'Did not receive code?'}
                  </span>
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
                  <input
                    type="text"
                    maxLength={6}
                    value={resetOtp}
                    onChange={e => setResetOtp(e.target.value.replace(/\D/g, ''))}
                    placeholder="Enter 6-digit code"
                  />
                </label>

                <label className="form-field">
                  <span>New Password</span>
                  <input
                    type="password"
                    value={resetNewPassword}
                    onChange={e => setResetNewPassword(e.target.value)}
                    placeholder="Enter strong new password"
                  />
                </label>
              </>
            )}

            {resetErr && (
              <div className="error-message">
                <AlertTriangle size={16} />
                {resetErr}
              </div>
            )}

            {resetMsg && (
              <div className="auth-success">
                <CheckCircle2 size={16} />
                {resetMsg}
              </div>
            )}

            <button
              className="button primary auth-submit"
              type="submit"
              disabled={resetBusy}
            >
              {resetBusy ? 'Please wait...' : otpSent ? 'Verify OTP & Reset Password' : 'Send 6-Digit OTP'}
            </button>

            <button
              type="button"
              className="auth-link"
              onClick={() => {
                setOtpSent(false); setResetErr(''); setResetMsg(''); setResendTimer(0)
                setAuthMode('login')
              }}
            >
              Back to Sign In
            </button>
          </form>
        ) : (
          <>
            <form onSubmit={onValidatedAuthSubmit} className="auth-form" noValidate>
              <label className="form-field">
                <span>Username</span>
                <input
                  type="text"
                  value={authForm.username}
                  onChange={e => {
                    setLocalError('')
                    setAuthForm({ ...authForm, username: e.target.value })
                  }}
                  placeholder="Enter username"
                />
              </label>

              {isSignup && (
                <label className="form-field">
                  <span>Email address</span>
                  <input
                    type="email"
                    value={authForm.email}
                    onChange={e => {
                      setLocalError('')
                      setAuthForm({ ...authForm, email: e.target.value })
                    }}
                    placeholder="Enter email address"
                  />
                </label>
              )}

              <label className="form-field">
                <span>Password</span>
                <input
                  type="password"
                  value={authForm.password}
                  onChange={e => {
                    setLocalError('')
                    setAuthForm({ ...authForm, password: e.target.value })
                  }}
                  placeholder="Enter password"
                />
              </label>

              {displayError && (
                <div className="error-message">
                  <AlertTriangle size={16} />
                  {displayError}
                </div>
              )}

              {displaySuccess && (
                <div className="auth-success">
                  <CheckCircle2 size={16} />
                  {displaySuccess}
                </div>
              )}

              <button
                className="button primary auth-submit"
                type="submit"
                disabled={authLoading}
              >
                {authLoading
                  ? 'Please wait...'
                  : isSignup
                    ? 'Create Account'
                    : 'Sign In'}
              </button>
            </form>

            {!isSignup && (
              <button
                type="button"
                className="auth-link"
                onClick={() => {
                  setResetErr(''); setResetMsg(''); setOtpSent(false); setResendTimer(0)
                  setLocalError(''); setLocalSuccess('')
                  setAuthMode('reset')
                }}
              >
                Forgot password?
              </button>
            )}
          </>
        )}

        <div className="auth-divider">
          <span>OR</span>
        </div>

        <button
          type="button"
          className="button secondary auth-guest"
          onClick={onGuest}
        >
          Continue as Guest
        </button>

        <p className="auth-footer">
          ThreatLens · Phishing Detection & Explainable Threat Analyzer
        </p>

      </div>
    </div>
  )
}






function AccountAccess({ user, setShowAuth, handleLogout }) {
  return (
    <div className="account-access">
      {user ? (
        <>
          <div className="account-user">
            <div className="account-avatar">
              {user.username?.charAt(0).toUpperCase()}
            </div>
            <div>
              <strong>{user.username}</strong>
              <span>{user.email || 'ThreatLens User'}</span>
            </div>
          </div>

          <button
            className="account-button logout-button"
            onClick={handleLogout}
          >
            Logout
          </button>
        </>
      ) : (
        <>
          <div className="account-user">
            <div className="account-avatar">G</div>
            <div>
              <strong>Guest Workspace</strong>
              <span>You're using guest access</span>
            </div>
          </div>

          <button
            className="account-button"
            onClick={() => setShowAuth(true)}
          >
            Sign In / Create Account
          </button>
        </>
      )}
    </div>
  )
}







export default App
