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

AC_PREREQ(2.64)
AC_INIT(OpenFaucet, 0.1~pre1, romain.lenglet@berabera.info, openfaucet)
AC_COPYRIGHT([Copyright 2011 Midokura KK])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)

AM_INIT_AUTOMAKE

AM_PATH_PYTHON

OPENFAUCET_PYTHON_CHECK_IMPORT([twisted], [],
  [AC_MSG_WARN([the Twisted library is required])])

OPENFAUCET_PYTHON_CHECK_IMPORT([unittest2], [],
  [AC_MSG_WARN([the unittest2 library is required for tests])])

AC_PATH_PROGS([SPHINXBUILD], [sphinx-build-2.6, sphinx-build], [notfound])
AS_IF([test "x$ac_cv_path_SPHINXBUILD" = xnotfound],
      [AC_MSG_WARN([Sphinx is required to generate documentation])])

AC_PATH_PROG([LATEX], [latex], [notfound])
AS_IF([test "x$ac_cv_path_LATEX" = xnotfound],
      [AC_MSG_WARN([LaTeX is required to generate DVI documentation])])

AC_PATH_PROG([MAKEINDEX], [makeindex], [notfound])
AS_IF([test "x$ac_cv_path_MAKEINDEX" = xnotfound],
      [AC_MSG_WARN([LaTeX is required to generate DVI and PDF documentation])])

AC_PATH_PROG([PDFLATEX], [pdflatex], [notfound])
AS_IF([test "x$ac_cv_path_PDFLATEX" = xnotfound],
      [AC_MSG_WARN([PDFLaTeX is required to generate PDF documentation])])

AC_CONFIG_FILES([Makefile
docs/Makefile
docs/conf.py
src/Makefile])

AC_OUTPUT
