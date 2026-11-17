/** Display-only YARA lexer. Never compiles, executes, or rewrites a rule. */
export type RuleFile = { name: string; category: string; content: string }
export type SourceToken = { text: string; kind: string; start: number }
export type CatalogRule = {
  id: string; name: string; filename: string; type: string; description: string | null
  severity: string; metadata: Record<string, string | number | boolean>; tags: string[]
  source: string; definition: string; line: number; parsed: boolean
}
const keyword = /^(?:rule|private|global|meta|strings|condition|and|or|not|any|all|of|them|for|in|at|filesize|entrypoint|nocase|wide|ascii|fullword|xor|base64|true|false|import|include)$/
export function tokenizeSource(source: string): SourceToken[] {
  const pattern = /\/\/[^\r\n]*|\/\*[\s\S]*?(?:\*\/|$)|"(?:\\[\s\S]|[^"\\])*"|\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\r\n\\])+\/[is]*|\$[A-Za-z_][\w]*|[A-Za-z_][\w]*|(?:0x[\da-fA-F]+|\d+(?:\.\d+)?)|\s+|[^]/g
  return Array.from(source.matchAll(pattern), match => {
    const text = match[0]
    const kind = text.startsWith('//') || text.startsWith('/*') ? 'comment' : text.startsWith('"') ? 'string'
      : text.startsWith('/') && text.length > 1 ? 'regex' : text.startsWith('$') ? 'variable'
      : keyword.test(text) ? 'keyword' : /^\d/.test(text) ? 'number' : 'plain'
    return { text, kind, start: match.index! }
  })
}
function literal(token: SourceToken): string | number | boolean {
  if (token.kind === 'string') return token.text.slice(1, -1).replace(/\\(x[\da-fA-F]{2}|["\\nrt])/g, (_, escape: string) =>
    escape.startsWith('x') ? String.fromCharCode(parseInt(escape.slice(1),16)) : ({n:'\n',r:'\r',t:'\t','"':'"','\\':'\\'}[escape] ?? '\\'+escape))
  if (token.text === 'true' || token.text === 'false') return token.text === 'true'
  return token.kind === 'number' ? Number(token.text) : token.text
}
export function catalogRules(files: RuleFile[]): CatalogRule[] {
  return files.flatMap(file => {
    const tokens = tokenizeSource(file.content).filter(t=>t.kind !== 'comment' && t.text.trim())
    const rules: CatalogRule[] = []
    for (let i=0; i<tokens.length; i++) {
      if (tokens[i].text !== 'rule' || tokens[i].kind !== 'keyword' || !/^[A-Za-z_]\w*$/.test(tokens[i+1]?.text || '')) continue
      const name = tokens[i+1].text
      let open=i+2
      while (open<tokens.length && tokens[open].text!=='{') open++
      if (open===tokens.length) continue
      let end=open+1, depth=1
      for (; end<tokens.length && depth; end++) {
        if (tokens[end].kind==='plain' && tokens[end].text==='{') depth++
        if (tokens[end].kind==='plain' && tokens[end].text==='}') depth--
      }
      if (depth) continue
      const metadata: CatalogRule['metadata'] = {}
      let meta=tokens.findIndex((t,index)=>index>open && index<end && t.text==='meta' && tokens[index+1]?.text===':')
      if (meta>=0) {
        meta+=2
        while (meta<end && !['strings','condition'].includes(tokens[meta].text)) {
          if (/^[A-Za-z_]\w*$/.test(tokens[meta].text) && tokens[meta+1]?.text==='=') {
            const value=tokens[meta+2]
            if (value && (['string','number'].includes(value.kind)||['true','false'].includes(value.text))) {
              metadata[tokens[meta].text]=literal(value);meta+=3;continue
            }
            if (value?.text==='-' && tokens[meta+3]?.kind==='number') {
              metadata[tokens[meta].text]=-Number(tokens[meta+3].text);meta+=4;continue
            }
          }
          meta++
        }
      }
      const tagIndex=tokens.slice(i+2,open).findIndex(t=>t.text===':')
      const tags=tagIndex<0?[]:tokens.slice(i+3+tagIndex,open).map(t=>t.text)
      const rawSeverity=typeof metadata.severity==='string'?metadata.severity.trim():''
      const severity=['Critical','High','Medium','Low','Info'].find(s=>s.toLowerCase()===rawSeverity.toLowerCase()) || rawSeverity || 'Not specified'
      rules.push({id:file.name+':'+tokens[i].start,name,filename:file.name,type:file.category,
        description:typeof metadata.description==='string'?metadata.description:null,
        severity,metadata,tags,source:file.content,definition:file.content.slice(tokens[i].start,tokens[end-1].start+1),line:file.content.slice(0,tokens[i].start).split('\n').length,parsed:true})
      i=end-1
    }
    return rules.length?rules:[{id:file.name,name:file.name,filename:file.name,type:file.category,description:null,
      severity:'Not specified',metadata:{},tags:[],source:file.content,definition:file.content,line:1,parsed:false}]
  })
}
