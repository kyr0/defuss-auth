"""defuss-vae deterministic project gates. Full upstream gate must actually run."""
CONFIG = {
    'coverage_min': 90, 'lint_command': None, 'test_command': None,
    'coverage_command': None, 'integration_commands': [], 'e2e_commands': [],
    'e2e_paths': [], 'timeout_s': 300, 'ci': None, 'layout': True,
    'strict': True, 'toolchain': True,
    'package': {'manager':'bun','type':'module','lint':'oxlint','library_build':'pkgroll'},
    # AGENTS.md: the plugin-managed defuss-vae block uses VAE-DIALECT, where → is the defined sequence operator.
    'prose': {'allow': {'AGENTS.md':'→'},'phrases': [],'html': []},
}
RULES = [
 {'id':'jwt.no-platform-dependencies','kind':'not_regex','path':'src/jwt.ts','pattern':r'from\s+["\'](?:node:|jose|defuss-)','claim':'JWT core uses native Web Crypto, not JOSE dependencies or platform modules'},
 {'id':'source.no-console','kind':'not_regex','glob':'src/*.ts','pattern':r'\bconsole\.(?:log|debug|info|warn|error|trace)\(','claim':'No logging credentials or raw exceptions from library'},
 {'id':'security.replay-test','kind':'contains','path':'tests/auth.test.mjs','text':'concurrent refresh replay revokes the whole session','claim':'Concurrent refresh replay regression stays covered'},
 {'id':'security.tenant-test','kind':'contains','path':'tests/auth.test.mjs','text':'many-to-many isolation','claim':'Tenant isolation regression stays covered'},
 {'id':'security.admin-race','kind':'contains','path':'tests/v02.test.mjs','text':'admin claim revocation during authorization callback prevents write','claim':'Administrative authorization races remain covered'},
 {'id':'security.client-cancel','kind':'contains','path':'tests/v02.test.mjs','text':'client captures original identity before response-body cancellation permits login','claim':'Client replay uses immutable credential context'},
 {'id':'storage.portable-key-names','kind':'contains','path':'tests/v02.test.mjs','text':'encrypted key files use portable lowercase storage names','claim':'Key-file names stay valid for defuss-storage FileStorage/OPFS'},
 {'id':'security.admin-tenant-binding','kind':'contains','path':'tests/v02.test.mjs','text':'admin service creation is authorized for the tenant it is created in','claim':'Admin HTTP handlers act on the authorized tenant'},
 {'id':'gate.coverage-nonempty','kind':'contains','path':'Makefile','text':'coverage measured no source module','claim':'Coverage gate fails closed when it measures no source module'},
 {'id':'package.declaration-emit','kind':'contains','path':'scripts/package-e2e.mjs','text':'declarationEmit:true','claim':'Packed artifact supports consumer declaration emit'},
 {'id':'http.empty-body','kind':'contains','path':'tests/v02.test.mjs','text':'HTTP mutations without payload accept the empty body stream Node adapters attach','claim':'Bodiless mutations work behind Node HTTP adapters'},
 {'id':'e2e.every-route','kind':'contains','path':'package.json','text':'"test:http": "node scripts/http-e2e.mjs && bun scripts/http-e2e.mjs"','claim':'make e2e drives every HTTP route over the built package on Node and Bun'},
 {'id':'e2e.hosted','kind':'contains','path':'package.json','text':'bun run test:host','claim':'make e2e runs the hosted deployment over real defuss-serve listeners, storage and browsers'},
 {'id':'security.host-forwarded-trust','kind':'contains','path':'tests/host.test.mjs','text':'host derives rate keys from the forwarded client of a credentialed proxy only','claim':'X-Forwarded-For becomes a rate key only behind the proxy credential'},
 {'id':'security.tenant-admin','kind':'contains','path':'tests/host.test.mjs','text':'tenantAdmin lets an administrator act only inside the tenant that holds the claim','claim':'tenantAdmin stays bound to the targeted tenant'},
 {'id':'storage.canonical-directory','kind':'contains','path':'tests/server.test.mjs','text':'native storage refuses symlinked, non-canonical and shared directories','claim':'Native storage keeps refusing symlinked ancestors and shared directories'},
 {'id':'validation.evidence','kind':'file_exists','path':'VALIDATION.md','claim':'Verification results distinguish executed and unexecuted gates'},
]
