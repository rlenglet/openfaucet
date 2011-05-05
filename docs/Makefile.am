# Copyright 2011 Midokura KK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makefile for Sphinx documentation.

dist_noinst_DATA = \
	index.rst \
	controller.rst \
	match.rst \
	config.rst \
	action.rst \
	error.rst

EXTRA_DIST = install.rst.in

SPHINXDATA = $(dist_noinst_DATA) \
	install.rst \
	news.rst \
	copying.rst

SPHINXOPTS     = -q -N
PAPEROPT       = -D latex_paper_size=a4
ALLSPHINXOPTS  = -d $(builddir) $(PAPEROPT) $(SPHINXOPTS)

installdirs-local: installdirs-html-local

HTMLDATA = \
	html/index.html \
	html/install.html \
	html/controller.html \
	html/match.html \
	html/config.html \
	html/action.html \
	html/error.html \
	html/news.html \
	html/copying.html \
	html/genindex.html \
	html/search.html \
	html/searchindex.js \
	html/_sources/index.txt \
	html/_sources/install.txt \
	html/_sources/controller.txt \
	html/_sources/match.txt \
	html/_sources/config.txt \
	html/_sources/action.txt \
	html/_sources/error.txt \
	html/_sources/news.txt \
	html/_sources/copying.txt \
	html/_static/pygments.css \
	html/_static/searchtools.js \
	html/_static/file.png \
	html/_static/basic.css \
	html/_static/doctools.js \
	html/_static/minus.png \
	html/_static/plus.png \
	html/_static/jquery.js \
	html/_static/default.css

CLEANFILES = \
	environment.pickle \
	index.doctree \
	install.doctree \
	controller.doctree \
	match.doctree \
	config.doctree \
	action.doctree \
	error.doctree \
	news.doctree \
	copying.doctree \
	news.rst \
	copying.rst

clean-local:
	-rm -rf $(builddir)/html

news.rst: ../NEWS
	echo "Release notes and copyright" > $@
	echo "===========================" >> $@
	echo "" >> $@
	sed -e 's/^/| /' $< >> $@

copying.rst: ../COPYING
	echo "Distribution license" > $@
	echo "====================" >> $@
	echo "" >> $@
	sed -e 's/^/| /' $< >> $@

# TODO(romain): Support the "dirhtml" and "singlehtml" builders in
# addition to "html".
html-local: conf.py $(SPHINXDATA)
	PYTHONPATH=$(builddir)/../src $(SPHINXBUILD) -b html $(ALLSPHINXOPTS) \
	  -c $(builddir) $(srcdir) html

installdirs-html-local:
	for dir in "$(DESTDIR)$(htmldir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done

# A standard Automake install for nobase_* targets.
install-html-local: html-local
	test -z "$(DESTDIR)$(htmldir)" || $(MKDIR_P) "$(DESTDIR)$(htmldir)"
	@list='$(HTMLDATA)'; test -n "$(DESTDIR)$(htmldir)" || list=; \
	$(am__nobase_list) | while read dir files; do \
	  xfiles=; for file in $$files; do \
	    if test -f "$$file"; then xfiles="$$xfiles $$file"; \
	    else xfiles="$$xfiles $(srcdir)/$$file"; fi; done; \
	  test -z "$$xfiles" || { \
	    test "x$$dir" = x. || { \
	      echo "$(MKDIR_P) '$(DESTDIR)$(htmldir)/$$dir'"; \
	      $(MKDIR_P) "$(DESTDIR)$(htmldir)/$$dir"; }; \
	    echo " $(INSTALL_DATA) $$xfiles '$(DESTDIR)$(htmldir)/$$dir'"; \
	    $(INSTALL_DATA) $$xfiles "$(DESTDIR)$(htmldir)/$$dir" || exit $$?; }; \
	done

# TODO(romain): Make this work properly, i.e. have make fail if any doctest
# fails.

#check-local:
#	$(SPHINXBUILD) -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
#	@echo "Testing of doctests in the sources finished, look at the " \
#	      "results in $(BUILDDIR)/doctest/output.txt."

am__install_max = 40
am__nobase_strip_setup = \
  srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*|]/\\\\&/g'`
am__nobase_strip = \
  for p in $$list; do echo "$$p"; done | sed -e "s|$$srcdirstrip/||"
am__nobase_list = $(am__nobase_strip_setup); \
  for p in $$list; do echo "$$p $$p"; done | \
  sed "s| $$srcdirstrip/| |;"' / .*\//!s/ .*/ ./; s,\( .*\)/[^/]*$$,\1,' | \
  $(AWK) 'BEGIN { files["."] = "" } { files[$$2] = files[$$2] " " $$1; \
    if (++n[$$2] == $(am__install_max)) \
      { print $$2, files[$$2]; n[$$2] = 0; files[$$2] = "" } } \
    END { for (dir in files) print dir, files[dir] }'
am__base_list = \
  sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
  sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
