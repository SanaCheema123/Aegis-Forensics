import { tokenizeSource } from '../../lib/ruleCatalog'
export function SourceCode({source}:{source:string}) {
  return <pre className="highlighted-source" tabIndex={0} aria-label="Complete API-provided YARA source"><code>{tokenizeSource(source).map((token,i)=><span key={i} className={'syntax-'+token.kind}>{token.text}</span>)}</code></pre>
}
