cmake_minimum_required(VERSION 3.4.3)

project(AllocFreeChecker CXX)
set(CMAKE_CXX_STANDARD 11)

find_package(LLVM REQUIRED CONFIG)
set(CMAKE_MODULE_PATH ${LLVM_CMAKE_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_CMAKE_DIR}")
include(AddLLVM)

find_package(Clang REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
message(STATUS "LLVM_DEFINITIONS:   ${LLVM_DEFINITIONS}")
message(STATUS "LLVM_INCLUDE_DIRS:  ${LLVM_INCLUDE_DIRS}")
message(STATUS "CLANG_INCLUDE_DIRS: ${CLANG_INCLUDE_DIRS}")

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

set(tests
  alloc-free-checker
  glib-array
  wmem-alloc
  wmem-scope
)
add_custom_target(check-AllocFreePlugin)
foreach(_test ${tests})
  add_custom_target(check-${_test}
    COMMAND
        ${LLVM_TOOLS_BINARY_DIR}/clang -cc1 -analyze
        -load $<TARGET_FILE:AllocFreePlugin>
        -analyzer-checker=core,alpha.AllocFree
        -verify ${CMAKE_CURRENT_SOURCE_DIR}/test/Analysis/${_test}.c
    DEPENDS AllocFreePlugin
    )
  add_dependencies(check-AllocFreePlugin check-${_test})
endforeach()
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
