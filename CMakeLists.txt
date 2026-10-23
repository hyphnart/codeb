cmake_minimum_required(VERSION 3.21)
project(YASBinaryLabX VERSION 1.7 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Widgets Concurrent)
qt_add_executable(YASBinaryLabX
    src/main.cpp
    src/MainWindow.h src/MainWindow.cpp
    src/TaskRunner.h
    src/HexView.h src/HexView.cpp
    src/BinaryFile.h src/BinaryFile.cpp
    src/SplitEngine.h src/SplitEngine.cpp
    src/AnalysisEngine.h src/AnalysisEngine.cpp
    src/PEInspector.h src/PEInspector.cpp
    src/DiffEngine.h src/DiffEngine.cpp
    src/DisassemblyEngine.h src/DisassemblyEngine.cpp
    src/ControlFlowEngine.h src/ControlFlowEngine.cpp
    src/FlowGraphView.h src/FlowGraphView.cpp
    src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp
    src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp
)
target_link_libraries(YASBinaryLabX PRIVATE Qt6::Core Qt6::Widgets Qt6::Concurrent)
set_target_properties(YASBinaryLabX PROPERTIES WIN32_EXECUTABLE TRUE)

# Optional Capstone disassembler: the application still builds without it.
find_path(CAPSTONE_INCLUDE_DIR NAMES capstone/capstone.h)
find_library(CAPSTONE_LIBRARY NAMES capstone)
if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
    target_include_directories(YASBinaryLabX PRIVATE "${CAPSTONE_INCLUDE_DIR}")
    target_link_libraries(YASBinaryLabX PRIVATE "${CAPSTONE_LIBRARY}")
    target_compile_definitions(YASBinaryLabX PRIVATE YAS_HAS_CAPSTONE=1)
    message(STATUS "Capstone enabled")
else()
    message(STATUS "Capstone not found: disassembly action will explain installation")
endif()


include(CTest)
if(BUILD_TESTING)
    add_executable(YASCoreTests
        tests/core_tests.cpp
        src/SplitEngine.h src/SplitEngine.cpp
        src/DiffEngine.h src/DiffEngine.cpp
    )
    target_include_directories(YASCoreTests PRIVATE src)
    target_link_libraries(YASCoreTests PRIVATE Qt6::Core)
    add_test(NAME YASCoreTests COMMAND YASCoreTests)
endif()

if(BUILD_TESTING)
    add_executable(YASXrefTests tests/xref_tests.cpp src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp
    src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp)
    target_include_directories(YASXrefTests PRIVATE src)
    target_link_libraries(YASXrefTests PRIVATE Qt6::Core)
    add_test(NAME YASXrefTests COMMAND YASXrefTests)
endif()

if(BUILD_TESTING)
    add_executable(YASFunctionTests tests/function_tests.cpp
        src/FunctionAnalysisEngine.h src/FunctionAnalysisEngine.cpp
        src/CrossReferenceEngine.h src/CrossReferenceEngine.cpp)
    target_include_directories(YASFunctionTests PRIVATE src)
    target_link_libraries(YASFunctionTests PRIVATE Qt6::Core)
    add_test(NAME YASFunctionTests COMMAND YASFunctionTests)
endif()
