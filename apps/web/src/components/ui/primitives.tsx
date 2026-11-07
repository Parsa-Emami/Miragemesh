import type { ComponentProps } from 'react';

export function Button({ className = '', variant = 'default', type = 'button', ...props }: ComponentProps<'button'> & { variant?: 'default' | 'outline' | 'ghost' }) {
  return <button data-slot="button" data-variant={variant} className={`ui-button ${className}`} type={type} {...props}/>;
}

export function Card({ className = '', ...props }: ComponentProps<'div'>) {
  return <div data-slot="card" className={`ui-card ${className}`} {...props}/>;
}

export function CardHeader({ className = '', ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-header" className={`ui-card-header ${className}`} {...props}/>;
}

export function CardTitle({ className = '', ...props }: ComponentProps<'h2'>) {
  return <h2 data-slot="card-title" className={`ui-card-title ${className}`} {...props}/>;
}

export function CardContent({ className = '', ...props }: ComponentProps<'div'>) {
  return <div data-slot="card-content" className={`ui-card-content ${className}`} {...props}/>;
}

export function Badge({ className = '', ...props }: ComponentProps<'span'>) {
  return <span data-slot="badge" className={`state ${className}`} {...props}/>;
}

export function Table({ className = '', ...props }: ComponentProps<'table'>) {
  return <table data-slot="table" className={`sensor-table ${className}`} {...props}/>;
}

export function Icon({ name, className = '' }: { name: string; className?: string }) {
  return <img className={`icon ${className}`} src={`${import.meta.env.BASE_URL}assets/icons/${name}.svg`} width="18" height="18" alt="" aria-hidden="true"/>;
}
