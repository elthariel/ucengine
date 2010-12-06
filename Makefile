VERSION       = 0.0.1
CC            = erlc
EBIN          = ebin
CFLAGS        = -Iinclude +warn_unused_vars +warn_unused_import

DIRS          = ebin datas/files

ERL_FILES     = $(shell find src/models/behaviours src -type f -and -name "*.erl" -exec basename '{}' \;)
BEAM_TARGETS  = $(ERL_FILES:.erl=.beam)
BEAM_TARGETS := $(addprefix ebin/, $(BEAM_TARGETS))

APP_FILES     = $(shell find src -type f -and -name "*.app" -exec basename '{}' \;)
APP_TARGETS  := $(addprefix ebin/, $(APP_FILES))

export ERL_LIBS := $(ERL_LIBS):deps

all: compile

$(DIRS):
	mkdir -p $(DIRS)

###############################################################################
# Build
###############################################################################
compile: $(DIRS) $(BEAM_TARGETS) $(APP_TARGETS)
	(cd deps/emongo && make)

ebin/amqp_pubsub.beam: src/backends/pubsub/amqp/amqp_pubsub.erl
ifdef WITH_AMQP
	@echo "AMQP support enabled"
	erlc -pa ebin -W $(CFLAGS) -o ebin $<
else
	@echo "AMQP support disabled, set the WITH_AMQP environnement variable to 'yes' to enable it."
endif

ebin/%.beam: src/%.erl
	erlc -pa ebin -W $(CFLAGS) -o ebin $<
ebin/%.beam: src/*/%.erl
	erlc -pa ebin -W $(CFLAGS) -o ebin $<
ebin/%.beam: src/*/*/%.erl
	erlc -pa ebin -W $(CFLAGS) -o ebin $<
ebin/%.beam: src/*/*/*/%.erl
	erlc -pa ebin -W $(CFLAGS) -o ebin $<

ebin/%.app: src/%.app
	@cp -v $< $@
ebin/%.app: src/*/%.app
	@cp -v $< $@
ebin/%.app: src/*/*/%.app
	@cp -v $< $@


###############################################################################
# Usual targets
###############################################################################
run: compile
	bin/uce_ctl.sh run

start: compile
	bin/uce_ctl.sh start

stop:
	bin/uce_ctl.sh stop

restart:
	bin/uce_ctl.sh restart

tests: compile
	bin/uce_ctl.sh tests

###############################################################################
# Cleanup
###############################################################################
.PHONY: clean
.PHONY: deepclean
clean:
	-@rm -v tmp/* -fr
	-@rm -v datas/* -fr
	-@rm -v erl_crash.dump -f
deepclean: clean
	@rm -v ebin/* -fr

