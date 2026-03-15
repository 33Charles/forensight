import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import {
  LayoutDashboard, ShieldAlert, ScrollText,
  Monitor, Users, Settings, LogOut, Radio, Upload
} from 'lucide-react'

const NAV = [
  { to: '/',        icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/events',  icon: ShieldAlert,     label: 'Events'    },
  { to: '/logs',    icon: ScrollText,      label: 'Logs'      },
  { to: '/hosts',   icon: Monitor,         label: 'Hosts'     },
]

const ANALYST_NAV = [
  { to: '/ingest',  icon: Upload,   label: 'Ingest Logs' },
]

const ADMIN_NAV = [
  { to: '/users',   icon: Users,    label: 'Users'    },
  { to: '/rules',   icon: Settings, label: 'Rules'    },
]

export default function Sidebar({ liveCount }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate('/login') }

  const navLink = ({ to, icon: Icon, label }) => (
    <NavLink
      key={to}
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150
         ${isActive
           ? 'bg-accent/15 text-accent font-medium'
           : 'text-dim hover:text-text hover:bg-muted'}`
      }
    >
      <Icon size={16} />
      {label}
    </NavLink>
  )

  return (
    <aside className="fixed left-0 top-0 h-screen w-56 bg-surface border-r border-border
                      flex flex-col z-40">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 bg-accent rounded-lg flex items-center justify-center">
            <ShieldAlert size={15} className="text-white" />
          </div>
          <span className="font-display text-lg font-bold text-text tracking-tight">
            Forensight
          </span>
        </div>
        <div className="flex items-center gap-1.5 mt-3">
          <span className="w-1.5 h-1.5 rounded-full bg-low animate-pulse-slow" />
          <span className="text-xs text-dim font-mono">
            LIVE · {liveCount ?? 0} events
          </span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        <p className="text-xs text-subtle font-mono uppercase tracking-widest px-2 mb-2">
          Monitor
        </p>
        {NAV.map(navLink)}

        {(user?.role === 'analyst' || user?.role === 'admin') && (
          <>
            <p className="text-xs text-subtle font-mono uppercase tracking-widest px-2 mt-5 mb-2">
              Tools
            </p>
            {ANALYST_NAV.map(navLink)}
          </>
        )}

        {user?.role === 'admin' && (
          <>
            <p className="text-xs text-subtle font-mono uppercase tracking-widest px-2 mt-5 mb-2">
              Admin
            </p>
            {ADMIN_NAV.map(navLink)}
          </>
        )}
      </nav>

      {/* User */}
      <div className="px-3 py-4 border-t border-border">
        <div className="flex items-center gap-3 px-2 py-2 mb-1">
          <div className="w-7 h-7 rounded-lg bg-accent/20 flex items-center justify-center
                          text-accent text-xs font-display font-bold uppercase">
            {user?.username?.[0]}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm text-text font-medium truncate">{user?.username}</p>
            <p className="text-xs text-subtle capitalize">{user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 w-full px-3 py-2 text-sm text-dim
                     hover:text-critical hover:bg-critical/10 rounded-lg transition-all"
        >
          <LogOut size={14} />
          Sign out
        </button>
      </div>
    </aside>
  )
}
