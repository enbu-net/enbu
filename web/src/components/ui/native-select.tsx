import { type ComponentProps } from 'react'
import { ChevronDown } from 'lucide-react'
import { css } from 'styled-system/css'

const wrapperClass = css({
  position: 'relative',
  display: 'inline-flex',
  alignItems: 'center',
  color: 'fg.muted',
  _hover: { color: 'fg.default' },
})

const selectClass = css({
  appearance: 'none',
  w: 'full',
  h: '8',
  borderWidth: '1px',
  borderColor: 'border.default',
  borderRadius: 'md',
  ps: '3',
  // Room for the chevron, which shows that this opens a list.
  pe: '8',
  fontSize: 'sm',
  bg: 'bg.surface',
  color: 'fg.default',
  outline: 'none',
  cursor: 'pointer',
  _focus: { borderColor: 'colorPalette.8', outlineWidth: '1px', outlineColor: 'colorPalette.8' },
  _hover: { borderColor: 'border.strong' },
})

const chevronClass = css({
  position: 'absolute',
  insetEnd: '2.5',
  pointerEvents: 'none',
})

export type NativeSelectProps = ComponentProps<'select'>

/** A native select with a chevron; `style` sizes the whole control. */
export const NativeSelect = ({ className, style, ...props }: NativeSelectProps) => (
  <span className={wrapperClass} style={style}>
    <select className={`${selectClass}${className ? ` ${className}` : ''}`} {...props} />
    <ChevronDown size={14} aria-hidden="true" className={chevronClass} />
  </span>
)
