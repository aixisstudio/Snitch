/**
 * Snitch — generic dropdown component.
 *
 * EN: Reusable wrapper replacing the four copy-pasted "open state + outside
 *     click" blocks that used to live in App.jsx. `useClickOutside` is the
 *     extracted hook; `Dropdown` wires it together with a toggle button and
 *     an absolutely-positioned panel.
 *
 *     Usage:
 *       <Dropdown
 *         button={<button>…</button>}           // onClick injected via cloneElement
 *         panelStyle={{ padding: 12 }}          // overrides for the panel
 *       >
 *         {(close) => <div>…content…</div>}     // render-prop OR plain node
 *       </Dropdown>
 *
 * FR: Enveloppe réutilisable remplaçant les quatre blocs copiés-collés
 *     « état open + clic extérieur » qui vivaient dans App.jsx.
 *     `useClickOutside` est le hook extrait ; `Dropdown` le combine avec un
 *     bouton bascule et un panneau positionné en absolu.
 */
import { useState, useRef, useEffect, cloneElement } from 'react'

/**
 * EN: Call `onClose` when a mousedown lands outside `ref`.
 * FR: Appeler `onClose` quand un mousedown tombe en dehors de `ref`.
 */
export function useClickOutside(ref, onClose) {
  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) onClose()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [ref, onClose])
}

/**
 * EN: Self-contained dropdown — the button element's onClick is overridden to
 *     toggle open state; children render inside the floating panel and may be
 *     a render-prop receiving a `close()` callback.
 * FR: Menu déroulant autonome — le onClick du bouton est remplacé pour
 *     basculer l'état ; les enfants s'affichent dans le panneau flottant et
 *     peuvent être un render-prop recevant un callback `close()`.
 */
export default function Dropdown({ button, children, panelStyle }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useClickOutside(ref, () => setOpen(false))

  const close = () => setOpen(false)

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {cloneElement(button, { onClick: () => setOpen(v => !v) })}
      {open && (
        <div style={{
          position: 'absolute', top: '110%', right: 0, zIndex: 100,
          background: '#1e293b', border: '1px solid #334155',
          borderRadius: 10, minWidth: 180,
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          ...panelStyle,
        }}>
          {typeof children === 'function' ? children(close) : children}
        </div>
      )}
    </div>
  )
}
