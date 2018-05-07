[![Build Status](https://travis-ci.org/Lekensteyn/clang-alloc-free-checker.svg?branch=master)](https://travis-ci.org/Lekensteyn/clang-alloc-free-checker)

# Clang Static Analyzer plugin for memory issues
[Clang Static Analyzer](https://clang-analyzer.llvm.org/) is a source code
analysis tool that can spot bugs in C and C++ projects such as Wireshark. This
repository contains a plugin that tries to detect additional domain-specific
issues.

A secondary reason to write this plugin is to learn how to extend the Clang
static analyzer. See below for developer resources if you want to do the same!

Tested with Clang 6.0.0 on Arch Linux.

## Usage
Building the plugin requires LLVM and Clang development headers to be installed.
To build this plugin (`AllocFreePlugin.so`) and validate correctness:

    mkdir build && cd build
    cmake -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
    ninja
    ninja check

To test the Wireshark source tree (at `/tmp/wireshark`) with this plugin:

    mkdir /tmp/wsbuild && cd /tmp/wsbuild
    cmake -GNinja -DCMAKE_C_COMPILER=/usr/lib/clang/ccc-analyzer -DCMAKE_CXX_COMPILER=/usr/lib/clang/c++-analyzer \
        -DCMAKE_BUILD_TYPE=None /tmp/wireshark -DCMAKE_BUILD_WITH_INSTALL_RPATH=1
    CCC_CC=clang CCC_CXX=clang++ \
    scan-build -load-plugin path/to/AllocFreePlugin.so -enable-checker alpha.AllocFree ninja

Check an individual file:

    clang -cc1 -analyze -load ./AllocFreePlugin.so -analyzer-checker=alpha.AllocFree ../test/Analysis/wmem-alloc.c

Check an individual file and write a HTML report to the directory `htmldir`.

    clang -cc1 -analyze -load ./AllocFreePlugin.so -analyzer-checker=alpha.AllocFree -analyzer-output=html -o htmldir ../test/Analysis/wmem-alloc.c

To check a specific file within a project without having to specify all of its
compile options (such as macros and include directories) using a compilation
database:

    # Create compilation database (compile_commands.json) in build directory
    cmake [other options here] -DCMAKE_EXPORT_COMPILE_COMMANDS=1
    clang-check -analyze -extra-arg=-Xanalyzer -extra-arg=-load -extra-arg=-Xanalyzer -extra-arg=path/to/AllocFreePlugin.so -extra-arg=-Xanalyzer -extra-arg=-analyzer-checker=alpha.AllocFree /tmp/wireshark/dumpcap.c

## Features
Detects issues such as:
- Mismatch between allocation functions. Using `g_free` to release `g_strsplit`
  memory will result in a memory leak. Combining `wmem_free` with `g_malloc` is
  could result in crashes in the future.
- Mismatch between wmem allocation scopes. Use of `p = wmem_alloc(NULL, 1)` with
  `wmem_free(wmem_file_scope(), p)` will result in memory corruption.

Helpful features:
- Mark code in a bug report with `Memory is allocated` and `Memory is released`.

The checker is by far not complete. The default `unix.Malloc` checker is much
more sophisticated. Limitations of the plugin include:
- False positives for memory leaks.
- The reported path for memory leaks could be helpful, currently the end of the
  path sometimes point to arbitrary code while the real memory leak happens when
  the function returns. Search for `Memory is allocated` to see the original
  leaked memory.
- If memory is passed as non-constant pointer to some other function, memory
  leaks can no longer be tracked in the same function.

## Developer Resources
If you are interested in writing your own checker, be sure to read the [Checker
Developer Manual](https://clang-analyzer.llvm.org/checker_dev_manual.html) and
watch the *Building a Checker in 24 Hours* talk
([slides](https://llvm.org/devmtg/2012-11/Zaks-Rose-Checker24Hours.pdf),
[video](https://youtu.be/kdxlsP5QVPw)). The sample mentioned in that material
has been updated in mean time, be sure to check the Clang [Git
history](https://llvm.org/docs/GettingStarted.html#git-mirror) of
[lib/StaticAnalyzer/Checkers/SimpleStreamChecker.cpp](https://github.com/llvm-mirror/clang/blob/master/lib/StaticAnalyzer/Checkers/SimpleStreamChecker.cpp)
for changes and the reasoning behind them. In particular, a new PointerEscape
check was added that makes it possible to ignore false positive memory leaks.

Another rich source of information are other checkers in that directory, such as
[MallocChecker.cpp](https://github.com/llvm-mirror/clang/blob/master/lib/StaticAnalyzer/Checkers/MallocChecker.cpp).

While it is not always very detailed, the Doxygen documentation provides a
useful overview of methods that can be used:
- [BugReport](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1BugReport.html)
- [BugReporterVisitor](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1BugReporterVisitor.html)
- [CallEvent](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1CallEvent.html)
- [CheckerContext](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1CheckerContext.html)
- [ProgramState](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1ProgramState.html)
- [Stmt](https://clang.llvm.org/doxygen/classclang_1_1Stmt.html)
- [SVal](https://clang.llvm.org/doxygen/classclang_1_1ento_1_1SVal.html)

Other potentially helpful links:
- [\[cfe-dev\] Checking if a ParmVarDecl is null in a Checker](https://lists.llvm.org/pipermail/cfe-dev/2018-April/057757.html)
- That thread linked to this [Checker Developer's Guide (PDF)](https://github.com/haoNoQ/clang-analyzer-guide/releases/download/v0.1/clang-analyzer-guide-v0.1.pdf).
- [StaticAnalyzer/README.txt](https://github.com/llvm-mirror/clang/blob/master/lib/StaticAnalyzer/README.txt) (note: not updated since 2011)

Random hints:
- The command `clang -cc1 -analyze -analyzer-checker=debug.ViewExplodedGraph`
  (or equivalently, `clang -cc1 -analyze -analyzer-viz-egraph-graphviz`)
  requires Clang to be built in debug mode or nothing appears to happen.
