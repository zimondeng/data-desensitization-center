export interface ChartPalette {
  textPrimary: string
  textMuted: string
  borderSubtle: string
  primary: string
  warning: string
}

const TOKEN_DEFAULTS: Record<string, string> = {
  '--ds-text-primary': 'rgb(15, 23, 42)',
  '--ds-text-muted': 'rgb(100, 116, 139)',
  '--ds-border-subtle': 'rgb(226, 232, 240)',
  '--ds-color-primary': 'rgb(22, 93, 255)',
  '--ds-color-warning': 'rgb(180, 83, 9)',
}

function readTokenColor(tokenName: string): string {
  const fallback = TOKEN_DEFAULTS[tokenName] ?? 'rgb(100, 116, 139)'
  if (typeof window === 'undefined' || !document?.documentElement) {
    return fallback
  }
  const value = getComputedStyle(document.documentElement)
    .getPropertyValue(tokenName)
    .trim()
  return value || fallback
}

export function resolveChartPalette(): ChartPalette {
  return {
    textPrimary: readTokenColor('--ds-text-primary'),
    textMuted: readTokenColor('--ds-text-muted'),
    borderSubtle: readTokenColor('--ds-border-subtle'),
    primary: readTokenColor('--ds-color-primary'),
    warning: readTokenColor('--ds-color-warning'),
  }
}
