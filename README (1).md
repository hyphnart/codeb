# YAS BinaryLab X V1.7 — Visual Function Call Graph + Task Shutdown Guard

Changes:
- Visual Function Call Graph dock using the existing QGraphicsView node renderer. Nodes represent heuristic function regions, direct CALL edges connect regions. Ctrl+wheel zoom and pan supported.
- Double-click a node to navigate the active matching binary; external addresses outside the decoded window are not safely navigable.
- TaskRunner counts active split/join/diff tasks on the main window. Closing while those workers or the SHA-256 worker run is blocked to avoid use-after-free in callbacks.
- Existing disassembly, CFG, XREF, PE inspection, split/join, binary diff, hex selection, session tabs and hashing are preserved.

Known limitations:
- Function regions are heuristic; call graph is not a complete interprocedural CFG. Indirect CALL targets are unresolved.
- Call graph shares the grid-based visual renderer; dense graphs can have overlapping/crossing lines.
- Analysis panels are reused across files rather than independently cached per tab.
- Closing is blocked during active work rather than performing automatic graceful cancellation; users can cancel task dialogs then close after the worker exits.
- Qt6 toolchain is unavailable here, so Windows compilation and Qt runtime tests remain unverified.

Build (Qt6 Core/Widgets/Concurrent, MSVC):
```
cmake -S . -B build -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64" -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python tests/source_smoke.py
```
