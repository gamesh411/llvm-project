set(LLVM_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(LLVM_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/../..")
set(LLVM_BUILD_MODE "%(build_mode)s")
set(LLVM_TOOLS_DIR "${LLVM_BINARY_DIR}/%(build_config)s/bin")
set(LLVM_LIBS_DIR "${LLVM_BINARY_DIR}/%(build_config)s/lib")

llvm_canonicalize_cmake_booleans(
  LLVM_BUILD_EXAMPLES
  LLVM_ENABLE_PLUGINS
  )

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
  )

add_lit_testsuite(check-clang-exception-scan "Running clang-exception-scan tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS clang-exception-scan
  ) 