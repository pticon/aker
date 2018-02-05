man_MANS = aker.8 aker.conf.8
dist_doc_DATA = aker.8 aker.conf.8

install-data-hook:
	sed -e 's|@SYSCONFDIR@|$(sysconfdir)|g' aker.8 > aker.8.mdoc
	sed -e 's|@PREFIX@|$(prefix)|g' aker.8 > aker.8.mdoc
	sed -e 's|@SYSCONFDIR@|$(sysconfdir)|g' aker.conf.8 > aker.conf.8.mdoc
	sed -e 's|@PREFIX@|$(prefix)|g' aker.conf.8 > aker.conf.8.mdoc
	$(mkdir_p) $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) aker.8.mdoc $(DESTDIR)$(mandir)/man8/aker.8
	$(INSTALL_DATA) aker.conf.8.mdoc $(DESTDIR)$(mandir)/man8/aker.conf.8

clean-local:
	rm -f aker.conf.8.mdoc aker.8.mdoc
