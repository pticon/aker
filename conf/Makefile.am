dist_doc_DATA = aker.conf

install-data-hook:
	$(mkdir_p) $(DESTDIR)$(sysconfdir)/
	$(INSTALL_DATA) aker.conf $(DESTDIR)$(sysconfdir)/aker.conf

uninstall-local:
	rm -f $(DESTDIR)$(sysconfdir)/aker.conf
