EXTRA_DIST = libsbase.spec rc.lechod rc.lechod.ini rc.xhttpd rc.xhttpd.ini ssl.sh rc.nowd rc.nowd.ini
install: install-ini

conftodir = "`echo $(sysconfdir)|sed -e 's|/usr/etc|/etc|'`"

initdir = "$(DESTDIR)$(conftodir)/init.d"

sysconftodir = "$(DESTDIR)$(conftodir)"

isubuntu = "`uname -v|grep Ubuntu`"

install-ini:
	@echo install xhttpd.ini lechod.ini to $(sysconftodir)
	@test -d $(sysconftodir)      || mkdir -p $(sysconftodir)
	@test -d $(initdir) || mkdir -p $(initdir)
	@test -f $(sysconftodir)/nowd.ini \
		|| cp -p $(top_srcdir)/doc/rc.nowd.ini $(sysconftodir)/nowd.ini
	@test -f $(sysconftodir)/lechod.ini \
		|| cp -p $(top_srcdir)/doc/rc.lechod.ini $(sysconftodir)/lechod.ini
	@test -f $(sysconftodir)/xhttpd.ini \
		|| cp -p $(top_srcdir)/doc/rc.xhttpd.ini $(sysconftodir)/xhttpd.ini
	@test -f $(initdir)/lechod \
		|| cp -p $(top_srcdir)/doc/rc.lechod $(initdir)/lechod
	@echo "install init scripts"
	@if [ $(isubuntu) != "" ]; \
		then \
			@test -f $(initdir)/xhttpd \
				|| cp -p $(top_srcdir)/doc/rc.xhttpd $(initdir)/xhttpd \
		else \
			@test -f $(initdir)/xhttpd \
				|| cp -p $(top_srcdir)/doc/xhttpd.init $(initdir)/xhttpd \
	fi
	@test -f $(initdir)/nowd \
		|| cp -p $(top_srcdir)/doc/rc.nowd $(initdir)/nowd
	@perl -i -p -e "s@/usr/local/sbin@$(prefix)/sbin@g" \
		$(initdir)/xhttpd $(initdir)/lechod $(initdir)/nowd
	@perl -i -p -e "s@/usr/local/etc@$(conftodir)@g" \
		$(initdir)/xhttpd  $(initdir)/lechod $(initdir)/nowd

