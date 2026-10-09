import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { ShieldAlert, Eye, EyeOff, Terminal } from 'lucide-react'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw]     = useState(false)
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const { login }               = useAuth()
  const navigate                = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.error ?? 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="scanlines min-h-screen bg-bg flex items-center justify-center
                    bg-grid-pattern bg-grid">
      {/* Glow */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-96 h-96 bg-accent/5 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-sm animate-slide-in">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14
                          bg-accent/15 border border-accent/30 rounded-2xl mb-4">
            <ShieldAlert size={26} className="text-accent" />
          </div>
          <h1 className="font-display text-3xl font-bold text-text">Forensight</h1>
          <p className="text-dim text-sm mt-1.5 font-mono">
            Security Event Monitor
          </p>
        </div>

        {/* Card */}
        <div className="card border-border/80">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-dim font-mono uppercase
                                tracking-widest mb-1.5">
                Username
              </label>
              <input
                className="input"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="admin"
                autoComplete="username"
                autoFocus
              />
            </div>

            <div>
              <label className="block text-xs text-dim font-mono uppercase
                                tracking-widest mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  className="input pr-10"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-subtle
                             hover:text-dim transition-colors"
                >
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <p className="text-xs text-critical bg-critical/10 border border-critical/20
                            rounded-lg px-3 py-2 font-mono">
                ✗ {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading || !username || !password}
              className="btn-primary w-full mt-2 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white
                                   rounded-full animate-spin" />
                  Authenticating...
                </>
              ) : 'Sign in'}
            </button>
          </form>
        </div>

        {/* <p className="text-center text-xs text-subtle mt-6 font-mono flex items-center
                      justify-center gap-1.5">
          <Terminal size={11} />
          SC212/0564/2022 · Charles Mwangi
        </p> */}
      </div>
    </div>
  )
}
