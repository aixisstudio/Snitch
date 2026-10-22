/**
 * EN: Theme awareness for JS-driven visuals. Chrome styles paint through
 *     CSS vars (see index.html) and update for free; components that feed
 *     colours to non-CSS renderers (WebGL aurora, canvas probes) use
 *     `useTheme()` to re-render when the toggle flips data-theme.
 * FR: Conscience du thème pour les visuels pilotés en JS. Le chrome peint
 *     via les vars CSS (index.html) et se met à jour tout seul ; les
 *     composants qui alimentent des renderers non-CSS (aurore WebGL,
 *     sondes canvas) utilisent `useTheme()` pour re-render quand le toggle
 *     bascule data-theme.
 */
import { useState, useEffect } from 'react'

/** EN: Current theme ('dark' | 'light'), live.
 *  FR: Thème courant ('dark' | 'light'), en direct. */
export function currentTheme() {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'
}

/** EN: React hook — re-renders the component on every theme switch.
 *  FR: Hook React — re-render le composant à chaque bascule de thème. */
export function useTheme() {
  const [theme, setTheme] = useState(currentTheme)
  useEffect(() => {
    const onChange = () => setTheme(currentTheme())
    window.addEventListener('snitch-theme', onChange)
    return () => window.removeEventListener('snitch-theme', onChange)
  }, [])
  return theme
}

/** EN: Resolve a design token to a concrete colour for canvas/GL code that
 *     cannot consume var(--x). / FR: Résout un token en couleur concrète
 *     pour le code canvas/GL qui ne sait pas lire var(--x). */
export function token(name, fallback = '#000000') {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}
