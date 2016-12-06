PACKAGE = joinparty
VERSION = 0.0.3
SUBDIRS = src

dist_data_DATA = README.md build_joinparty.sh install_libbitcoin_explorer.sh

dist-hook:
	rm -f include/joinparty/sysconfdir.hpp
	cp -R include $(distdir)/
