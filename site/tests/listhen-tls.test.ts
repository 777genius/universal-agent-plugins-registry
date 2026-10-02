import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createPrivateKey, X509Certificate } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { after, before, test } from 'node:test'
import { listen, type Listener } from 'listhen'
import { generate } from 'selfsigned'

let directory: string
let fixture: Awaited<ReturnType<typeof generate>>
const password = 'disposable-tls-fixture'
const require = createRequire(import.meta.url)

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'uap-listhen-tls-'))
  fixture = await generate([{ shortName: 'CN', value: 'localhost' }], {
    algorithm: 'sha256',
    extensions: [
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, digitalSignature: true },
      { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
    ],
  })
  await writeFile(join(directory, 'key.pem'), fixture.private, { mode: 0o600 })
  await writeFile(join(directory, 'cert.pem'), fixture.cert)
  for (const [name, flags, passphrase] of [
    ['modern', [], password],
    ['unencrypted', [], ''],
    ['3des', ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES'], password],
    ['rc2', ['-legacy'], password],
  ] as const) {
    execFileSync('openssl', [
      'pkcs12', '-export', '-in', join(directory, 'cert.pem'),
      '-inkey', join(directory, 'key.pem'), '-out', join(directory, `${name}.p12`),
      '-passout', `pass:${passphrase}`, ...flags,
    ], { env: { ...process.env, HOME: directory }, stdio: 'pipe' })
  }
})

after(async () => {
  if (directory) await rm(directory, { recursive: true, force: true })
})

async function start(options: Record<string, unknown> = {}, implementation = listen) {
  return implementation((_request, response) => { response.end('tls-contract-ok') }, {
    hostname: '127.0.0.1', port: 0, isTest: true, autoClose: false,
    showURL: false, clipboard: false, qr: false, ...options,
  })
}

async function response(listener: Listener, ca?: string) {
  const client = listener.https ? https : http
  return new Promise<string>((resolve, reject) => {
    client.get(listener.url, ca ? { ca } : { rejectUnauthorized: false }, incoming => {
      let body = ''
      incoming.setEncoding('utf8')
      incoming.on('data', chunk => { body += chunk })
      incoming.on('end', () => resolve(body))
      incoming.on('error', reject)
    }).on('error', reject)
  })
}

test('ESM and CommonJS listeners keep ordinary HTTP behavior', async () => {
  for (const implementation of [listen, require('listhen').listen]) {
    const listener = await start({}, implementation)
    try {
      assert.equal(listener.https, false)
      assert.equal(await response(listener), 'tls-contract-ok')
    } finally { await listener.close() }
  }
})

test('generated HTTPS certificate has requested SANs, matching key, and a valid CA chain', async () => {
  const listener = await start({ https: { domains: ['localhost', '127.0.0.1', '::1'], validityDays: 2 } })
  try {
    assert.ok(listener.https)
    const certificates = listener.https.cert.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)!
    assert.equal(certificates.length, 2)
    const leaf = new X509Certificate(certificates[0]!)
    const ca = new X509Certificate(certificates[1]!)
    assert.equal(leaf.checkHost('localhost'), 'localhost')
    assert.equal(leaf.checkIP('127.0.0.1'), '127.0.0.1')
    assert.equal(leaf.checkIP('::1'), '::1')
    assert.ok(leaf.checkPrivateKey(createPrivateKey(listener.https.key)))
    assert.ok(leaf.verify(ca.publicKey))
    assert.ok(ca.ca)
    assert.equal(await response(listener, certificates[1]), 'tls-contract-ok')
  } finally { await listener.close() }
})

test('supplied CA and encrypted signing key retain a trusted HTTPS chain', async () => {
  const signingKey = createPrivateKey(fixture.private).export({
    format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: password,
  })
  const listener = await start({ https: {
    signingKey, signingKeyCert: fixture.cert, signingKeyPassphrase: password,
    domains: ['localhost', '127.0.0.1'], passphrase: password,
  } })
  try {
    assert.ok(listener.https)
    assert.match(listener.https.key, /ENCRYPTED PRIVATE KEY/)
    assert.equal(listener.https.passphrase, password)
    assert.equal(await response(listener, fixture.cert), 'tls-contract-ok')
  } finally { await listener.close() }
})

test('PEM files and inline encrypted PEM preserve HTTPS behavior', async () => {
  const encryptedKey = createPrivateKey(fixture.private).export({
    format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: password,
  })
  for (const options of [
    { key: join(directory, 'key.pem'), cert: join(directory, 'cert.pem') },
    { key: encryptedKey, cert: fixture.cert, passphrase: password },
  ]) {
    const listener = await start({ https: options })
    try { assert.equal(await response(listener, fixture.cert), 'tls-contract-ok') }
    finally { await listener.close() }
  }
})

test('native TLS accepts modern encrypted, empty-password, and legacy 3DES PFX', async () => {
  for (const name of ['modern', 'unencrypted', '3des']) {
    const listener = await start({ https: {
      pfx: join(directory, `${name}.p12`), passphrase: name === 'unencrypted' ? '' : password,
    } })
    try {
      assert.equal(await response(listener, fixture.cert), 'tls-contract-ok')
    } finally { await listener.close() }
  }
})

test('unreadable PFX and wrong passwords fail with actionable TLS errors', async () => {
  await assert.rejects(start({ https: { pfx: join(directory, 'modern.p12'), passphrase: 'wrong' } }), /Check the passphrase/)
  await writeFile(join(directory, 'malformed.p12'), 'invalid-pfx')
  await assert.rejects(start({ https: { pfx: join(directory, 'malformed.p12') } }), /Node TLS could not load the PFX/)
})

test('legacy RC2 PFX has an explicit re-export error when the native provider rejects it', async () => {
  await assert.rejects(start({ https: {
    pfx: join(directory, 'rc2.p12'), passphrase: password,
  } }), /re-export legacy RC2 PFX with modern AES encryption/)
})

test('returned PFX options work in the actual Vite HTTPS consumer', async () => {
  const listener = await start({ https: { pfx: join(directory, 'modern.p12'), passphrase: password } })
  try {
    const nuxtRequire = createRequire(import.meta.resolve('nuxt'))
    const builderRequire = createRequire(nuxtRequire.resolve('@nuxt/vite-builder'))
    const { createServer } = await import(pathToFileURL(builderRequire.resolve('vite')).href)
    assert.ok(listener.https)
    const server = await createServer({
      root: directory, configFile: false, appType: 'custom',
      server: { host: '127.0.0.1', port: 0, hmr: false, https: listener.https },
    })
    server.middlewares.use((_request: http.IncomingMessage, res: http.ServerResponse) => { res.end('vite-pfx-ok') })
    try {
      await server.listen()
      const address = server.httpServer!.address()
      assert.ok(address && typeof address === 'object')
      const body = await new Promise<string>((resolve, reject) => {
        https.get(`https://127.0.0.1:${address.port}/`, { ca: fixture.cert }, incoming => {
          let text = ''
          incoming.setEncoding('utf8')
          incoming.on('data', chunk => { text += chunk })
          incoming.on('end', () => resolve(text))
        }).on('error', reject)
      })
      assert.equal(body, 'vite-pfx-ok')
    } finally { await server.close() }
  } finally { await listener.close() }
})

test('configured certificate subjects preserve punctuation in attribute values', async () => {
  const listener = await start({ https: { organization: 'Acme, Inc. + Partners', organizationalUnit: 'A=B\\C', domains: ['127.0.0.1'] } })
  try {
    assert.ok(listener.https)
    const selfsignedRequire = createRequire(require.resolve('selfsigned'))
    const { X509Certificate: LibraryCertificate } = selfsignedRequire('@peculiar/x509')
    const cert = new LibraryCertificate(listener.https.cert)
    assert.deepEqual(cert.subjectName.getField('O'), ['Acme, Inc. + Partners'])
    assert.deepEqual(cert.subjectName.getField('OU'), ['A=B\\C'])
  } finally { await listener.close() }
})
