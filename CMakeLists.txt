cmake_minimum_required(VERSION 3.4.3)

project(AllocFreeChecker CXX)

find_package(LLVM REQUIRED)
set(CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
include(AddLLVM)

#set(LLVM_EXPORTED_SYMBOL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/AllocFreePlugin.exports)
add_llvm_loadable_module(AllocFreePlugin AllocFreeChecker.cpp PLUGIN_TOOL clang)

if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  target_link_libraries(AllocFreePlugin PRIVATE
    clangAnalysis
    clangAST
    clangStaticAnalyzerCore
    LLVMSupport
    )
endif()

add_custom_target(check-AllocFreePlugin
    COMMAND
        clang -cc1 -analyze
        -load $<TARGET_FILE:AllocFreePlugin>
        -analyzer-checker=core,alpha.AllocFree
        -verify ${CMAKE_CURRENT_SOURCE_DIR}/test/Analysis/alloc-free-checker.c
    DEPENDS AllocFreePlugin
    )
add_custom_target(check DEPENDS check-AllocFreePlugin)

# Somehow does not work...
# Needs llvm-lit, set via -DLLVM_EXTERNAL_LIT=.../llvm-lit.py
#add_lit_testsuites(CHECKER ${CMAKE_CURRENT_SOURCE_DIR}/test)

## Copied from LLVM.
## Add a global check rule now that all subdirectories have been traversed
## and we know the total set of lit testsuites.
#get_property(LLVM_LIT_TESTSUITES GLOBAL PROPERTY LLVM_LIT_TESTSUITES)
#get_property(LLVM_LIT_PARAMS GLOBAL PROPERTY LLVM_LIT_PARAMS)
#get_property(LLVM_LIT_DEPENDS GLOBAL PROPERTY LLVM_LIT_DEPENDS)
#get_property(LLVM_LIT_EXTRA_ARGS GLOBAL PROPERTY LLVM_LIT_EXTRA_ARGS)
#add_lit_target(check-all
#  "Running all regression tests"
#  ${LLVM_LIT_TESTSUITES}
#  PARAMS ${LLVM_LIT_PARAMS}
#  DEPENDS ${LLVM_LIT_DEPENDS}
#  ARGS ${LLVM_LIT_EXTRA_ARGS}
#  )
