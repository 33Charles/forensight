import { createContext, useContext, useState, useEffect } from 'react'
import { jwtDecode } from 'jwt-decode'
import api from '../utils/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser]   = useState(null)
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (token) {
      try {
        const decoded = jwtDecode(token)
        // Check expiry
        if (decoded.exp * 1000 < Date.now()) {
          logout()
        } else {
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`
          // Fetch current user info
          api.get('/auth/me')
            .then(r => setUser(r.data))
            .catch(() => logout())
            .finally(() => setLoading(false))
        }
      } catch {
        logout()
        setLoading(false)
      }
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (username, password) => {
    const { data } = await api.post('/auth/login', { username, password })
    localStorage.setItem('token', data.access_token)
    api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
    setToken(data.access_token)
    setUser(data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem('token')
    delete api.defaults.headers.common['Authorization']
    setToken(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
