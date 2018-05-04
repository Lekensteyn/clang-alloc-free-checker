#!/bin/bash
# Works around packaging issue in Clang packaging that breaks locating Clang.
# https://bugs.llvm.org/show_bug.cgi?id=37128
# https://salsa.debian.org/pkg-llvm-team/llvm-toolchain/merge_requests/2
set -eux

# If it does not exist, assume it is already fixed.
[ -e /usr/share/llvm-${CLANG_VERSION}/cmake ] || exit

mv /usr/share/llvm-${CLANG_VERSION}/cmake /usr/lib/llvm-${CLANG_VERSION}/lib/cmake/clang
sed -i 's|.*_IMPORT_CHECK_FILES_FOR_.*/bin/.*)|#&|' /usr/lib/llvm-${CLANG_VERSION}/lib/cmake/clang/ClangTargets-*.cmake
mkdir -p /usr/lib/cmake
ln -s /usr/lib/llvm-${CLANG_VERSION}/lib/cmake/clang /usr/lib/cmake/clang-${CLANG_VERSION}
# Replace "PATH" by "REALPATH" and duplicate the next line that strips a directory
sed -i '/CMAKE_CURRENT_LIST_FILE/{s/ PATH/ REALPATH/;n;p}' /usr/lib/llvm-${CLANG_VERSION}/lib/cmake/clang/ClangConfig.cmake
