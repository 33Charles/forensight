import { useEffect, useState } from 'react'
import { UserPlus, Shield, Eye, Edit2, Trash2, X } from 'lucide-react'
import api from '../utils/api'
import { useAuth } from '../context/AuthContext'
import { PageHeader, Spinner, EmptyState } from '../components/ui'
import { formatTime } from '../utils/helpers'

const ROLE_COLORS = {
  admin:   'text-critical bg-critical/10 border-critical/20',
  analyst: 'text-accent bg-accent/10 border-accent/20',
  viewer:  'text-dim bg-muted border-border',
}

function CreateUserModal({ onClose, onCreated }) {
  const [form, setForm]     = useState({ username: '', password: '', role: 'viewer' })
  const [error, setError]   = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await api.post('/users', form)
      onCreated(data)
      onClose()
    } catch (err) {
      setError(err.response?.data?.error ?? 'Failed to create user')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-bg/80 backdrop-blur-sm flex items-center
                    justify-center z-50 animate-fade-in">
      <div className="card w-full max-w-md border-border/80 animate-slide-in">
        <div className="flex items-center justify-between mb-5">
          <h3 className="font-display font-bold text-text">Create User</h3>
          <button onClick={onClose} className="text-subtle hover:text-dim">
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dim font-mono uppercase
                              tracking-widest mb-1.5">Username</label>
            <input
              className="input"
              value={form.username}
              onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              placeholder="johndoe"
              autoFocus
            />
          </div>
          <div>
            <label className="block text-xs text-dim font-mono uppercase
                              tracking-widest mb-1.5">Password</label>
            <input
              className="input"
              type="password"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              placeholder="••••••••"
            />
          </div>
          <div>
            <label className="block text-xs text-dim font-mono uppercase
                              tracking-widest mb-1.5">Role</label>
            <select
              className="input"
              value={form.role}
              onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
            >
              <option value="viewer">Viewer — read only</option>
              <option value="analyst">Analyst — view + update events + ingest</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>

          {error && (
            <p className="text-xs text-critical bg-critical/10 border border-critical/20
                          rounded-lg px-3 py-2 font-mono">✗ {error}</p>
          )}

          <div className="flex gap-3 pt-1">
            <button type="button" onClick={onClose} className="btn-ghost flex-1">
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !form.username || !form.password}
              className="btn-primary flex-1"
            >
              {loading ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Users() {
  const [users,    setUsers]    = useState([])
  const [loading,  setLoading]  = useState(true)
  const [showForm, setShowForm] = useState(false)
  const { user: me }            = useAuth()

  useEffect(() => {
    api.get('/users')
      .then(r => setUsers(r.data))
      .finally(() => setLoading(false))
  }, [])

  const handleToggle = async (u) => {
    const { data } = await api.patch(`/users/${u.id}`, { is_active: !u.is_active })
    setUsers(prev => prev.map(x => x.id === data.id ? data : x))
  }

  const handleRoleChange = async (u, role) => {
    const { data } = await api.patch(`/users/${u.id}`, { role })
    setUsers(prev => prev.map(x => x.id === data.id ? data : x))
  }

  const handleDelete = async (u) => {
    if (!confirm(`Delete user '${u.username}'?`)) return
    await api.delete(`/users/${u.id}`)
    setUsers(prev => prev.filter(x => x.id !== u.id))
  }

  return (
    <div className="animate-fade-in">
      <PageHeader title="Users" subtitle={`${users.length} accounts`}>
        <button
          onClick={() => setShowForm(true)}
          className="btn-primary flex items-center gap-1.5"
        >
          <UserPlus size={13} />
          New User
        </button>
      </PageHeader>

      {showForm && (
        <CreateUserModal
          onClose={() => setShowForm(false)}
          onCreated={u => setUsers(prev => [u, ...prev])}
        />
      )}

      <div className="card p-0 overflow-hidden">
        {loading ? (
          <div className="flex justify-center py-16"><Spinner /></div>
        ) : users.length === 0 ? (
          <EmptyState icon={Shield} message="No users found" />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-surface/60">
                {['User','Role','Status','Created By','Last Login','Actions'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-mono
                                         text-subtle uppercase tracking-widest font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}
                    className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg bg-accent/15 flex items-center
                                      justify-center text-accent text-xs font-display
                                      font-bold uppercase">
                        {u.username[0]}
                      </div>
                      <div>
                        <p className="text-sm text-text font-medium">{u.username}</p>
                        {u.id === me?.id && (
                          <p className="text-xs text-subtle font-mono">you</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={u.role}
                      onChange={e => handleRoleChange(u, e.target.value)}
                      disabled={u.id === me?.id}
                      className={`badge border cursor-pointer bg-transparent
                                  disabled:cursor-default ${ROLE_COLORS[u.role]}`}
                    >
                      <option value="admin">admin</option>
                      <option value="analyst">analyst</option>
                      <option value="viewer">viewer</option>
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleToggle(u)}
                      disabled={u.id === me?.id}
                      className={`badge border transition-all disabled:cursor-default
                                  ${u.is_active
                                    ? 'text-low bg-low/10 border-low/20 hover:bg-critical/10 hover:text-critical hover:border-critical/20'
                                    : 'text-subtle bg-muted border-border hover:bg-low/10 hover:text-low hover:border-low/20'
                                  }`}
                    >
                      {u.is_active ? 'active' : 'inactive'}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-dim">
                    {u.created_by ?? '—'}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-subtle">
                    {u.last_login ? formatTime(u.last_login) : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    {u.id !== me?.id && (
                      <button
                        onClick={() => handleDelete(u)}
                        className="text-subtle hover:text-critical transition-colors p-1.5
                                   rounded hover:bg-critical/10"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
