CFLAGS += -std=c17 -Wall -DI18N -fpie -flto -Ofast
LFLAGS += -Wall -pie -flto -Ofast

all: checkmd5 i18n_mo
	strip checkmd5
clean:
	rm -f *.o
	rm -f checkmd5
	rm -rf i18n/mo

OBJS=checkmd5.o md5.o
checkmd5: $(OBJS) version.h
	$(CC) $(LFLAGS) $(OBJS) -o $@
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Internationalisation

LANGS = am ar bg ca cs da de el es et eu fa fi fr he_IL hi hr hu id is it ja kk
LANGS += ko lt mk mr nb nl pl pt pt_BR ro ru sk sl sq sr sv tr uk zh_CN zh_TW

i18n_mo: $(patsubst %, i18n/mo/%/checkmd5.mo, $(LANGS))
i18n/mo/%/checkmd5.mo: i18n/po/%.po
	@mkdir -p i18n/mo/$*
	msgfmt --output-file=$@ $<

i18n_po: $(patsubst %, i18n/po/%.po, $(LANGS))
i18n/po/%.po: i18n/checkmd5.pot
	@mkdir -p i18n/po
	@[ -f "$@" ] && msgmerge --update $@ $< || msginit --input=$< --no-translator --locale= --output=$@
i18n/checkmd5.pot: checkmd5.c
	@mkdir -p i18n
	xgettext --keyword=TR --language=C --add-comments --sort-output -o $@ checkmd5.c
