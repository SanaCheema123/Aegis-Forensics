import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
export const cn = (...values: ClassValue[]) => twMerge(clsx(values))
export function date(value: unknown) { return typeof value === 'string' && !Number.isNaN(Date.parse(value)) ? new Date(value).toLocaleString() : 'Not recorded' }
