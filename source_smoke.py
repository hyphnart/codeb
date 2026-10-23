from pathlib import Path
root=Path(__file__).resolve().parents[1]
cmake=(root/'CMakeLists.txt').read_text()
main=(root/'src/MainWindow.cpp').read_text()
tasks=(root/'src/TaskRunner.h').read_text()
checks={
 'CMake version 1.7':'VERSION 1.7' in cmake,
 'Visual call graph':'VisualCallGraphDock' in main,
 'Graph function regions':'functionAnalysis.regions' in main,
 'Graph call edges':'callGraph.edges.append' in main,
 'Graph navigation':'visualCallView,&FlowGraphView::addressActivated' in main,
 'Task counter':'yas.activeTasks' in tasks,
 'Shutdown guard':'Background tasks running' in main,
 'Hash shutdown guard':'HashWorker' in main,
 'Existing CFG':'ControlFlowEngine::build(report)' in main,
 'Core C++ tests':(root/'tests/core_tests.cpp').exists(),
 'Function C++ tests':(root/'tests/function_tests.cpp').exists(),
}
for key,value in checks.items():print(('PASS' if value else 'FAIL')+': '+key)
assert all(checks.values())
