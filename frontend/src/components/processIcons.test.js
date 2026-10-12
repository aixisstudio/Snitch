/**
 * Tests for processIcons — the process-name → Lucide icon matcher.
 *
 * EN: These run in the plain Node vitest environment (no DOM), so the tests
 *     assert on component identity, not on rendered output.
 * FR: Ces tests tournent dans l'environnement Node (pas de DOM) ; on
 *     vérifie l'identité du composant, pas le rendu.
 */
import { describe, it, expect } from 'vitest'
import {
  AppWindow,
  Boxes,
  Bot,
  Cpu,
  Gamepad,
  Globe,
  GitBranch,
  Music,
  SquareCode,
  Terminal,
  Video,
} from 'lucide-react'
import { processIcon } from './processIcons'

describe('processIcon', () => {
  it('matches case-insensitively', () => {
    expect(processIcon('SLACK')).toBe(processIcon('slack'))
    expect(processIcon('CODE')).toBe(SquareCode)
    expect(processIcon('code')).toBe(SquareCode)
  })

  it('matches on substrings of the raw process name', () => {
    expect(processIcon('Visual Studio Code')).toBe(SquareCode)
    expect(processIcon('firefox-esr')).toBe(Globe)
    expect(processIcon('dockerd')).toBe(Boxes)
  })

  it('falls back to AppWindow for unknown / empty / null names', () => {
    expect(processIcon('some-unknown-binary')).toBe(AppWindow)
    expect(processIcon('')).toBe(AppWindow)
    expect(processIcon(null)).toBe(AppWindow)
  })

  it('covers the icon families requested in issue #13', () => {
    expect(processIcon('steam')).toBe(Gamepad) // Steam / game launchers
    expect(processIcon('firefox')).toBe(Globe) // browsers
    expect(processIcon('code')).toBe(SquareCode) // VS Code
    expect(processIcon('ollama')).toBe(Bot) // AI runtimes
    expect(processIcon('git')).toBe(GitBranch) // version control
    expect(processIcon('python')).toBe(Cpu) // language runtimes
    expect(processIcon('spotify')).toBe(Music) // media
    expect(processIcon('zoom')).toBe(Video) // meeting apps
    expect(processIcon('powershell')).toBe(Terminal) // shells
  })
})
