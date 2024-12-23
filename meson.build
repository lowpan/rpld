project('rpld', 'c')
compiler = meson.get_compiler('c')

evdep = dependency('ev', required: false)
if evdep.found()
	evdep = [ libev ]
elif compiler.has_header('ev.h') and compiler.has_function('ev_time', args: ['-lev'])
	evdep = [ compiler.find_library('ev') ]
else
	error('Couldn\'t find libev header / library')
endif

foreach name : ['lua', 'lua5.3', 'lua-5.3', 'lua53']
	dep = dependency(name, version: '>=5.3', required: false)
	if dep.found()
		luadep = dep
	endif
endforeach
if not luadep.found()
	error('Couldn\'t find Lua.')
endif

mnldep = dependency('libmnl')

srcs = files(
	'rpld.c',
	'config.c',
	'socket.c',
	'buffer.c',
	'recv.c',
	'send.c',
	'helpers.c',
	'process.c',
	'netlink.c',
	'dag.c',
	'log.c',
	'crypto/aes/tiny-AES-c-master/aes.c',
	'crypto/kyber/ref/cbd.c',
	'crypto/kyber/ref/kem.c',
	'crypto/kyber/ref/fips202.c',
	'crypto/kyber/ref/indcpa.c',
	'crypto/kyber/ref/randombytes.c',
	'crypto/kyber/ref/ntt.c',
	'crypto/kyber/ref/poly.c',
	'crypto/kyber/ref/polyvec.c',
	'crypto/kyber/ref/reduce.c',
	'crypto/kyber/ref/symmetric-shake.c',
	'crypto/kyber/ref/verify.c',
)

executable('rpld', srcs, dependencies : [ evdep, luadep, mnldep ])

# vim: syntax=python
