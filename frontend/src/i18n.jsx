/**
 * Snitch — internationalization.
 *
 * EN: Tiny homemade i18n layer. Dictionaries live in isolated files under
 *     `src/locales/` — one per language — so the community can contribute
 *     translations with a simple pull request (see CONTRIBUTING.md).
 *     Values can be plain strings or functions for interpolation, e.g.
 *     t('lan_devices', 3). `useT()` returns { lang, t, setLang }.
 * FR: Petite couche i18n maison. Les dictionnaires vivent dans des fichiers
 *     isolés sous `src/locales/` — un par langue — pour que la communauté
 *     contribue des traductions par simple pull request (cf. CONTRIBUTING.md).
 *     Les valeurs sont des chaînes ou des fonctions d'interpolation, ex.
 *     t('lan_devices', 3). `useT()` renvoie { lang, t, setLang }.
 */
import { createContext, useContext, useState } from 'react'
import en from './locales/en'
import fr from './locales/fr'
import es from './locales/es'
import de from './locales/de'
import ru from './locales/ru'
import ja from './locales/ja'
import ptBR from './locales/pt-BR'
import zhCN from './locales/zh-CN'

// EN: Registry — code → dictionary. `LANGS` drives every language picker.
// FR: Registre — code → dictionnaire. `LANGS` pilote tous les sélecteurs.
export const LANGS = ['en', 'fr', 'es', 'de', 'ru', 'ja', 'pt-BR', 'zh-CN']
export const LANG_NAMES = {
  en: 'English', fr: 'Français', es: 'Español', de: 'Deutsch',
  ru: 'Русский', ja: '日本語', 'pt-BR': 'Português', 'zh-CN': '中文',
}
const DICTS = { en, fr, es, de, ru, ja, 'pt-BR': ptBR, 'zh-CN': zhCN }

// ── Context / Contexte ───────────────────────────────────────────────────────
const I18nContext = createContext(null)

/**
 * EN: Detect the browser language on first run — saved choice wins, then the
 *     browser's preferred language, then English. Region tags map to the
 *     closest supported locale (pt → pt-BR, zh → zh-CN, otherwise the bare
 *     language prefix).
 * FR: Détecter la langue du navigateur au premier lancement — le choix
 *     sauvegardé prime, puis la langue préférée du navigateur, puis l'anglais.
 *     Les tags de région mappent vers la locale la plus proche (pt → pt-BR,
 *     zh → zh-CN, sinon le préfixe de langue nu).
 */
function detectLang() {
  const saved = localStorage.getItem('snitch_lang')
  if (saved && DICTS[saved]) return saved
  const nav = (navigator.language || 'en')
  if (DICTS[nav]) return nav
  const bare = nav.split('-')[0]
  if (bare === 'pt') return 'pt-BR'
  if (bare === 'zh') return 'zh-CN'
  return DICTS[bare] ? bare : 'en'
}

/**
 * EN: Provides { lang, t, setLang } to the whole tree. `t(key, ...args)`
 *     resolves a dictionary entry — functions are called with args, strings
 *     returned as-is, missing keys fall back to the key itself.
 * FR: Fournit { lang, t, setLang } à tout l'arbre. `t(key, ...args)` résout une
 *     entrée du dictionnaire — les fonctions sont appelées avec args, les
 *     chaînes renvoyées telles quelles, les clés manquantes retombent sur la clé.
 */
export function I18nProvider({ children }) {
  // EN: Persisted language — survives restarts (localStorage, not just RAM).
  // FR: Langue persistée — survit aux redémarrages (localStorage, pas juste la RAM).
  const [lang, setLangState] = useState(detectLang)
  const setLang = (l) => {
    localStorage.setItem('snitch_lang', l)
    setLangState(l)
  }
  const dict = DICTS[lang] || en

  function t(key, ...args) {
    // EN: Own-property check — without it, keys like "constructor" would
    //     resolve to inherited Object members (which are callable).
    // FR: Vérification de propriété propre — sans elle, des clés comme
    //     « constructor » résoudraient vers les membres hérités d'Object
    //     (qui sont appelables).
    if (!Object.hasOwn(dict, key)) return key
    const val = dict[key]
    if (typeof val === 'function') return val(...args)
    return val
  }

  return (
    <I18nContext.Provider value={{ lang, t, setLang }}>
      {children}
    </I18nContext.Provider>
  )
}

export const useT = () => useContext(I18nContext)
