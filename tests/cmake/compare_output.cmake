# Usage: cmake -DTOOL=<exe> -DEXPECTED=<file> -P compare_output.cmake
execute_process(COMMAND ${TOOL} OUTPUT_VARIABLE actual RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "${TOOL} exited with ${rc}")
endif()
file(READ ${EXPECTED} expected)
if(NOT actual STREQUAL expected)
  message(FATAL_ERROR "Output of ${TOOL} differs from ${EXPECTED}; regenerate it with the tool and review the diff")
endif()
