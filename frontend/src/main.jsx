/**
 * Snitch — React entry point.
 *
 * EN: Mounts the App inside StrictMode and wraps it in the I18nProvider so
 *     every component can call `useT()` for EN/FR translations.
 * FR: Monte l'App dans StrictMode et l'enveloppe dans l'I18nProvider pour que
 *     chaque composant puisse appeler `useT()` pour les traductions EN/FR.
 */
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { I18nProvider } from './i18n'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </React.StrictMode>
)
