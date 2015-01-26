EMCC=emcc -DED25519_DECLSPEC='__attribute__((used))'
# EMSCRIPTEN_KEEPALIVE

srcs= \
  src/add_scalar.c \
  src/ge.c \
  src/keypair.c \
  src/seed.c \
  src/sign.c \
  src/fe.c \
  src/key_exchange.c \
  src/sc.c \
  src/sha512.c \
  src/verify.c

bytecodes=$(foreach f,$(srcs),$(basename $(f)).bc)
objects=$(foreach f,$(srcs),$(basename $(f)).o)

all: ed25519.em.js ed25519.em0.js ed25519
.PHONY: all

clean:
	-$(RM) ed25519.em.js ed25519.em0.js src/*.bc
.PHONY: clean

ed25519: $(objects)

%.em.js: %.pre.js %.post.js $(bytecodes)
	$(EMCC) -02 -o $@ --pre-js $< --post-js $(word 2,$^) $(bytecodes)

%.em0.js: %.pre.js %.post.js $(bytecodes)
	$(EMCC) -g -O0 -o $@ --pre-js $< --post-js $(word 2,$^) $(bytecodes)

%.bc: %.c
	$(EMCC) -s LINKABLE=1 -c -o $@ $+
