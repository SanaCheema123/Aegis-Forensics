import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { ErrorState, Empty, Loading, Pager, DataTable } from './index'
describe('Record states and controls',()=>{
 it('renders actionable errors without hiding them',()=>{render(<ErrorState error={new Error('Evidence integrity failed')}/>);expect(screen.getByRole('alert')).toHaveTextContent('Evidence integrity failed')})
 it('shows loading and empty states',()=>{render(<><Loading/><Empty title="No saved scan"/></>);expect(screen.getByRole('status')).toBeInTheDocument();expect(screen.getByText('No saved scan')).toBeInTheDocument()})
 it('bounds pagination and navigates to the next source page',()=>{const change=vi.fn();render(<Pager page={1} total={40} onChange={change}/>);expect(screen.getByRole('button',{name:'Previous page'})).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:'Next page'}));expect(change).toHaveBeenCalledWith(2)})
 it('escapes evidence text instead of executing markup',()=>{render(<DataTable rows={[{message:'<script>alert(1)</script>'}]}/>);expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument();expect(document.querySelector('script')).toBeNull()})
 it('sorts source rows numerically within the displayed page',()=>{render(<DataTable rows={[{record:10},{record:2}]}/>);fireEvent.click(screen.getByRole('button',{name:/record/}));const cells=screen.getAllByRole('cell');expect(cells[0]).toHaveTextContent('2')})
})
