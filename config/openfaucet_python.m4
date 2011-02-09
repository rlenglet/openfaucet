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

# OPENFAUCET_PYTHON_CHECK_IMPORT([MODULE], [ACTION-IF-FOUND],
#                                [ACTION_IF_NOT_FOUND])
# -----------------------------------------------------------
AC_DEFUN([OPENFAUCET_PYTHON_CHECK_IMPORT],[
  AC_CACHE_CHECK([for python import $1],
    [AS_TR_SH([openfaucet_cv_python_import_$1])],
    [AS_IF(["$PYTHON" -c "import [$1]" 2>&AS_MESSAGE_LOG_FD],
           [AS_VAR_SET([AS_TR_SH([openfaucet_cv_python_import_$1])], [yes])],
           [AS_VAR_SET([AS_TR_SH([openfaucet_cv_python_import_$1])], [no])])])
  AS_VAR_IF([AS_TR_SH([openfaucet_cv_python_import_$1])], [yes], [$2], [$3])
])

