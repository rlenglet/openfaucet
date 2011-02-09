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
	openfaucet/ofstats.py

# Distribute but don't install unittests and mocks.
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

noinst_PYTHON = \
	$(UNITTESTS) \
	openfaucet/mock_twisted.py

check-local: $(UNITTESTS)
	@for unittest in $?; do \
	  echo PYTHON $$unittest; \
	  PYTHONPATH=$(srcdir):$(builddir) $(PYTHON) -B $$unittest; \
	done
