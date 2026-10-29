// Emit CSP only into the server-rendered HTML. A reactive app.head entry would
// overwrite the finalizer's exact script/style hashes during client hydration.
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; upgrade-insecure-requests"

export default defineNitroPlugin((nitro) => {
  if (import.meta.dev) return
  nitro.hooks.hook('render:html', (html) => {
    html.head.unshift(`<meta http-equiv="Content-Security-Policy" content="${contentSecurityPolicy}">`)
  })
})
