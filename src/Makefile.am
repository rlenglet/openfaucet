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

nobase_python_PYTHON = \
	openfaucet/__init__.py \
	openfaucet/buffer.py \
	openfaucet/ofaction.py \
	openfaucet/ofconfig.py \
	openfaucet/ofcontroller.py \
	openfaucet/oferror.py \
	openfaucet/ofmatch.py \
	openfaucet/ofproto.py \
	openfaucet/ofprotoops.py \
	openfaucet/ofstats.py \
	openfaucet/mock_ofcontroller.py \
	openfaucet/mock_ofproto.py \
	openfaucet/mock_twisted.py \
	openfaucet/mock_vendor.py

# Distribute unittests but don't install them.
UNITTESTS = \
	openfaucet/test_buffer.py \
	openfaucet/test_ofaction.py \
	openfaucet/test_ofconfig.py \
	openfaucet/test_ofcontroller.py \
	openfaucet/test_oferror.py \
	openfaucet/test_ofmatch.py \
	openfaucet/test_ofproto.py \
	openfaucet/test_ofprotoops.py \
	openfaucet/test_ofstats.py

# Instead of running every unittest module by setting
# TESTS = $(UNITTESTS), run them all as a single test suite.
TESTS = test_all.py
CLEANFILES = test_all.py
EXTRADIST = test_all.py.in
test_all.py: test_all.py.in $(UNITTESTS)
	@echo generating test suite $@
	@unittest_files="$(UNITTESTS)"; modules=;\
	for file in $$unittest_files; do\
	  module=`echo $$file | sed -e 's/\.py$$//' -e 'y/\//./'`;\
	  modules="$$modules '$$module',"; done;\
	sed -e 's/@UNITTEST_MODULES@/['"$$modules"']/'\
	  $(srcdir)/test_all.py.in > $@

# The command to run the test_all.py unittests.
TESTS_ENVIRONMENT = PYTHONPATH=$(srcdir):$(builddir) $(PYTHON) -B
