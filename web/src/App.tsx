import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { VaultProvider } from './context/VaultContext'
import { ProtectedRoute } from './components/ProtectedRoute'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { VaultPage } from './pages/VaultPage'
import { VaultEntryPage } from './pages/VaultEntryPage'
import { VaultEntryForm } from './pages/VaultEntryForm'
import { SettingsPage } from './pages/SettingsPage'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route
            path="/*"
            element={
              <ProtectedRoute>
                <VaultProvider>
                  <Routes>
                    <Route element={<Layout />}>
                      <Route path="/vault" element={<VaultPage />} />
                      <Route path="/vault/new" element={<VaultEntryForm />} />
                      <Route path="/vault/:id" element={<VaultEntryPage />} />
                      <Route path="/settings" element={<SettingsPage />} />
                    </Route>
                    <Route path="*" element={<Navigate to="/vault" replace />} />
                  </Routes>
                </VaultProvider>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
