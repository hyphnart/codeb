#include "MainWindow.h"
#include "HexView.h"
#include "SplitEngine.h"
#include "AnalysisEngine.h"
#include "PEInspector.h"
#include "DiffEngine.h"
#include "DisassemblyEngine.h"
#include "ControlFlowEngine.h"
#include "FlowGraphView.h"
#include "CrossReferenceEngine.h"
#include "FunctionAnalysisEngine.h"
#include "TaskRunner.h"
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QSpinBox>
#include <QTextEdit>
#include <QtConcurrent/QtConcurrentRun>
#include <QFutureWatcher>
#include <QTimer>
#include <QPointer>
#include <QTabWidget>
#include <QFileInfo>
#include <QSignalBlocker>
#include <QSet>
#include <QVBoxLayout>
#include <QPushButton>
#include <QMutex>
#include <functional>
#include <QSettings>
#include <QCloseEvent>
#include <atomic>
#include <QDockWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QHeaderView>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QLabel>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QApplication>
#include <QProgressDialog>
#include <QRegularExpression>
#include <algorithm>
#include <limits>
MainWindow::MainWindow() {
    setWindowTitle("YAS BinaryLab X — V1.7");
    resize(1200,760);
    QSettings settings("YAS", "BinaryLabX");
    restoreGeometry(settings.value("window/geometry").toByteArray());
    setStyleSheet("QMainWindow{background:#0b1220;} QMenuBar,QMenu,QToolBar,QStatusBar{background:#1e293b;color:#e2e8f0;} QMenu::item:selected{background:#334155;}");
    tabs_=new QTabWidget(this);
    tabs_->setTabsClosable(true);
    tabs_->setMovable(true);
    tabs_->setDocumentMode(true);
    setCentralWidget(tabs_);
    connect(tabs_,&QTabWidget::currentChanged,this,[this](int i){activateTab(i);});
    connect(tabs_,&QTabWidget::tabCloseRequested,this,[this](int i){closeTab(i);});
    auto *fileMenu=menuBar()->addMenu("File");
    auto *tools=menuBar()->addMenu("Tools");
    auto *toolbar=addToolBar("Main");
    auto add=[&](QMenu *menu,const QString &title,const QKeySequence &shortcut,auto callback) {
        QAction *a=menu->addAction(title);
        a->setShortcut(shortcut);
        connect(a,&QAction::triggered,this,callback);
        toolbar->addAction(a);
    };
    add(fileMenu,"Open",QKeySequence::Open,[this]{openFile();});
    add(tools,"Copy Selected Hex",QKeySequence::Copy,[this]{if(hex_)hex_->copySelectedHex();});
    add(tools,"Copy Selected ASCII",QKeySequence("Ctrl+Shift+C"),[this]{if(hex_)hex_->copySelectedAscii();});
    add(tools,"Go to Offset",QKeySequence("Ctrl+G"),[this]{jumpToOffset();});
    add(tools,"Find Hex",QKeySequence::Find,[this]{findHex();});
    add(tools,"SHA-256",QKeySequence("Ctrl+H"),[this]{calculateHash();});
    add(tools,"Split File",QKeySequence("Ctrl+Shift+S"),[this]{splitFile();});
    add(tools,"Join Parts",QKeySequence("Ctrl+Shift+J"),[this]{joinFile();});
    add(tools,"Analyze File",QKeySequence("Ctrl+Shift+A"),[this]{analyzeFile();});
    add(tools,"Inspect PE",QKeySequence("Ctrl+Shift+P"),[this]{inspectPE();});
    add(tools,"Compare Files",QKeySequence("Ctrl+Shift+D"),[this]{compareFiles();});
    add(tools,"Disassemble",QKeySequence("Ctrl+Shift+I"),[this]{disassembleFile();});
    add(tools,"Disassemble PE Entry",QKeySequence("Ctrl+Shift+E"),[this]{disassemblePEEntry();});
    status_=new QLabel("Ready",this);
    statusBar()->addWidget(status_,1);
    restoreSession();
}
void MainWindow::openFile() {
    QString path=QFileDialog::getOpenFileName(this,"Open binary file");
    if(!path.isEmpty()) openPath(path);
}
bool MainWindow::openPath(const QString &path) {
    const QString canonical=QFileInfo(path).canonicalFilePath();
    if(canonical.isEmpty()) return false;
    for(int i=0;i<tabs_->count();++i) {
        auto *view=qobject_cast<HexView*>(tabs_->widget(i));
        if(view && view->property("filePath").toString()==canonical) {
            tabs_->setCurrentIndex(i);
            return true;
        }
    }
    auto candidate=std::make_shared<BinaryFile>();
    if(!candidate->open(canonical)) {
        QMessageBox::warning(this,"Open failed","Cannot read selected file.");
        return false;
    }
    auto *view=new HexView(tabs_);
    view->setProperty("filePath",canonical);
    view->setDocument(candidate);
    const int index=tabs_->addTab(view,QFileInfo(canonical).fileName());
    tabs_->setTabToolTip(index,canonical);
    tabs_->setCurrentIndex(index);
    QSettings("YAS","BinaryLabX").setValue("recent/lastFile",canonical);
    return true;
}
void MainWindow::activateTab(int index) {
    hex_=index>=0 ? qobject_cast<HexView*>(tabs_->widget(index)) : nullptr;
    if(!hex_) {
        doc_.reset();
        status_->setText("Ready — Open a file");
        return;
    }
    const QString path=hex_->property("filePath").toString();
    // Each view owns its own document. Reopen a read-only handle for the active commands.
    auto candidate=std::make_shared<BinaryFile>();
    if(!candidate->open(path)) {
        doc_.reset();
        status_->setText("File is no longer readable: "+path);
        return;
    }
    doc_=std::move(candidate);
    // Show only analysis docks associated with this file.
    for(auto *dock:findChildren<QDockWidget*>()) {
        if(dock->property("analysisPath").isValid())
            dock->setVisible(dock->property("analysisPath").toString()==path);
    }
    status_->setText(QString("%1 | %2 bytes | Read-only").arg(path).arg(doc_->size()));
}
void MainWindow::closeTab(int index) {
    if(index<0 || index>=tabs_->count())return;
    QWidget *page=tabs_->widget(index);
    const QString closingPath=page->property("filePath").toString();
    for(auto *dock:findChildren<QDockWidget*>()) {
        if(dock->property("analysisPath").toString()==closingPath) {
            dock->hide();
            dock->setProperty("analysisPath",QVariant());
        }
    }
    tabs_->removeTab(index);
    page->deleteLater();
    if(tabs_->count()==0) activateTab(-1);
}
void MainWindow::saveSession() {
    QStringList paths;
    QStringList offsets;
    for(int i=0;i<tabs_->count();++i) {
        auto *view=qobject_cast<HexView*>(tabs_->widget(i));
        if(!view)continue;
        paths.append(view->property("filePath").toString());
        offsets.append(QString::number(view->currentOffset()));
    }
    QSettings settings("YAS","BinaryLabX");
    settings.setValue("session/paths",paths);
    settings.setValue("session/offsets",offsets);
    settings.setValue("session/currentIndex",tabs_->currentIndex());
}
void MainWindow::restoreSession() {
    QSettings settings("YAS","BinaryLabX");
    const QStringList paths=settings.value("session/paths").toStringList();
    const QStringList offsets=settings.value("session/offsets").toStringList();
    QSignalBlocker blocker(tabs_);
    for(int i=0;i<paths.size() && i<32;++i) {
        if(!QFileInfo::exists(paths[i]))continue;
        if(!openPath(paths[i]))continue;
        auto *view=qobject_cast<HexView*>(tabs_->currentWidget());
        if(view && i<offsets.size()) {
            bool ok=false;
            const qint64 offset=offsets[i].toLongLong(&ok);
            if(ok && offset>=0)view->jumpTo(offset);
        }
    }
    blocker.unblock();
    if(tabs_->count()>0) {
        const int selected=std::clamp(settings.value("session/currentIndex",0).toInt(),0,tabs_->count()-1);
        tabs_->setCurrentIndex(selected);
        activateTab(selected);
    }
}
void MainWindow::jumpToOffset() {
    if(!doc_) return;
    bool ok=false;
    QString text=QInputDialog::getText(this,"Go to Offset","Hex offset (e.g. 0x1000):",QLineEdit::Normal,"0x0",&ok).trimmed();
    if(!ok || text.isEmpty()) return;
    if(text.startsWith("0x",Qt::CaseInsensitive)) text=text.mid(2);
    qulonglong value=text.toULongLong(&ok,16);
    if(!ok || value>static_cast<qulonglong>(std::numeric_limits<qint64>::max())) {
        QMessageBox::warning(this,"Invalid offset","Enter a valid hexadecimal offset."); return;
    }
    hex_->jumpTo(static_cast<qint64>(value));
}
void MainWindow::calculateHash() {
    if(!doc_) return;
    if(findChild<QFutureWatcher<QString>*>("HashWorker")) {
        QMessageBox::information(this,"SHA-256","A hash calculation is already running.");
        return;
    }
    const QString path=doc_->path();
    auto *dialog=new QProgressDialog("Computing SHA-256 in background...","",0,0,this);
    dialog->setCancelButton(nullptr);
    dialog->setWindowModality(Qt::NonModal);
    dialog->setMinimumDuration(0);
    auto *watcher=new QFutureWatcher<QString>(this);
    watcher->setObjectName("HashWorker");
    connect(watcher,&QFutureWatcher<QString>::finished,this,[this,watcher,dialog,path](){
        const QString value=watcher->result();
        dialog->hide();
        dialog->deleteLater();
        watcher->deleteLater();
        if(value.startsWith("ERROR:"))
            QMessageBox::warning(this,"SHA-256",value.mid(6));
        else QMessageBox::information(this,"SHA-256 — "+path,value);
    });
    dialog->show();
    watcher->setFuture(QtConcurrent::run([path](){
        BinaryFile file;
        if(!file.open(path))return QString("ERROR:Cannot open file.");
        QString error;
        QString hash=file.sha256(&error);
        return hash.isEmpty()?QString("ERROR:")+error:hash;
    }));
}
void MainWindow::findHex() {
    if(!doc_) return;
    bool ok=false;
    QString input=QInputDialog::getText(this,"Find Hex","Hex bytes (e.g. 4D 5A):",QLineEdit::Normal,{},&ok);
    if(!ok) return;
    input.remove(QRegularExpression("\\s+"));
    if(input.isEmpty() || input.size()%2 || !QRegularExpression("^[0-9A-Fa-f]+$").match(input).hasMatch()) {
        QMessageBox::warning(this,"Invalid pattern","Enter complete hexadecimal bytes."); return;
    }
    QByteArray pattern=QByteArray::fromHex(input.toLatin1());
    const qint64 chunkSize=1024*1024;
    qint64 offset=std::min(doc_->size(),hex_->currentOffset()+16);
    QByteArray carry;
    QProgressDialog progress("Searching...","Cancel",0,1000,this);
    progress.setWindowModality(Qt::WindowModal);
    while(offset<doc_->size()) {
        if(progress.wasCanceled()) return;
        QByteArray block=doc_->read(offset,chunkSize);
        if(block.isEmpty()) break;
        QByteArray combined=carry+block;
        qsizetype index=combined.indexOf(pattern);
        if(index>=0) {
            qint64 found=offset-carry.size()+index;
            hex_->jumpTo(found);
            status_->setText(QString("Found at 0x%1").arg(static_cast<qulonglong>(found),0,16));
            return;
        }
        carry=combined.right(std::min<qsizetype>(pattern.size()-1,combined.size()));
        offset+=block.size();
        progress.setValue(static_cast<int>(offset*1000/std::max<qint64>(1,doc_->size())));
        QApplication::processEvents();
    }
    QMessageBox::information(this,"Find Hex","Pattern not found after current offset.");
}

void MainWindow::splitFile() {
    QString source=QFileDialog::getOpenFileName(this,"Select file to split");
    if(source.isEmpty()) return;
    QString dest=QFileDialog::getExistingDirectory(this,"Choose output directory");
    if(dest.isEmpty()) return;
    bool ok=false;
    int sizeMb=QInputDialog::getInt(this,"Part Size","Size per part (MiB):",100,1,2048,1,&ok);
    if(!ok) return;
    struct Outcome { bool success=false; QString error; };
    startBackgroundTask<Outcome>(this,"Splitting file...",
        [source,dest,sizeMb](const auto &progress){
            Outcome result;
            result.success=SplitEngine::split(source,dest,static_cast<qint64>(sizeMb)*1024*1024,progress,result.error);
            return result;
        },[this](Outcome result){
            if(result.success) QMessageBox::information(this,"Split complete","Parts and manifest created.");
            else if(result.error!="Cancelled.") QMessageBox::warning(this,"Split failed",result.error+
                "\nCompleted parts may remain in the output folder.");
            status_->setText(result.success?"Split complete":"Split stopped");
        });
}
void MainWindow::joinFile() {
    QString manifest=QFileDialog::getOpenFileName(this,"Select YAS manifest",{},"YAS Manifest (*.yasmanifest.json);;JSON (*.json)");
    if(manifest.isEmpty()) return;
    QString dest=QFileDialog::getExistingDirectory(this,"Choose output directory");
    if(dest.isEmpty()) return;
    struct Outcome { bool success=false; QString error; };
    startBackgroundTask<Outcome>(this,"Joining and verifying parts...",
        [manifest,dest](const auto &progress){
            Outcome result;
            result.success=SplitEngine::join(manifest,dest,progress,result.error);
            return result;
        },[this](Outcome result){
            if(result.success) QMessageBox::information(this,"Join complete","Reconstructed file verified.");
            else if(result.error!="Cancelled.") QMessageBox::warning(this,"Join failed",result.error);
            status_->setText(result.success?"Join complete":"Join stopped");
        });
}

void MainWindow::analyzeFile() {
    if(!doc_) {
        QMessageBox::information(this,"Analysis","Open a file first.");return;
    }
    if(findChild<QFutureWatcher<AnalysisReport>*>("AnalysisWorker")) {
        QMessageBox::information(this,"Analysis","An analysis is already running.");
        return;
    }
    const QString path=doc_->path();
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    auto processed=std::make_shared<std::atomic<qint64>>(0);
    auto total=std::make_shared<std::atomic<qint64>>(0);
    auto *progress=new QProgressDialog("Analyzing signature, entropy and strings...","Cancel",0,1000,this);
    progress->setAttribute(Qt::WA_DeleteOnClose,false);
    progress->setWindowModality(Qt::NonModal);
    progress->setMinimumDuration(0);
    progress->setAutoClose(false);
    progress->setAutoReset(false);
    connect(progress,&QProgressDialog::canceled,this,[cancelled](){cancelled->store(true);});
    auto *watcher=new QFutureWatcher<AnalysisReport>(this);
    watcher->setObjectName("AnalysisWorker");
    auto *timer=new QTimer(watcher);
    timer->setInterval(80);
    connect(timer,&QTimer::timeout,this,[progress,processed,total](){
        const qint64 t=total->load();
        const qint64 n=processed->load();
        if(t>0) progress->setValue(static_cast<int>(1000.0*n/t));
    });
    connect(watcher,&QFutureWatcher<AnalysisReport>::finished,this,[this,watcher,timer,progress,path](){
        timer->stop();
        AnalysisReport report=watcher->result();
        progress->hide();
        progress->deleteLater();
        watcher->deleteLater();
        if(!report.error.isEmpty()) {
            if(!report.cancelled) QMessageBox::warning(this,"Analysis failed",report.error);
            return;
        }
        if(!doc_ || doc_->path()!=path) {
            status_->setText("Analysis finished for a file no longer open.");
            return;
        }
        showAnalysis(report);
    });
    progress->show();
    timer->start();
    watcher->setFuture(QtConcurrent::run([path,cancelled,processed,total](){
        return AnalysisEngine::analyze(path,[cancelled,processed,total](qint64 n,qint64 t){
            processed->store(n);
            total->store(t);
            return !cancelled->load();
        });
    }));
}
void MainWindow::showAnalysis(const AnalysisReport &report) {
    // Rebuild dedicated docks so repeated analyses never duplicate widgets.
    for(const QString &name : {QString("FileIntelligenceDock"),QString("EntropyDock"),QString("StringsDock")}) {
        if(auto *dock=findChild<QDockWidget*>(name)) {
            removeDockWidget(dock);
            delete dock;
        }
    }
    auto *structureDock=new QDockWidget("File Intelligence",this);
    structureDock->setObjectName("FileIntelligenceDock");
    auto *tree=new QTreeWidget(structureDock);
    tree->setHeaderLabels({"Property","Value"});
    auto add=[&](const QString &key,const QString &value){
        auto *item=new QTreeWidgetItem(tree);
        item->setText(0,key);item->setText(1,value);
    };
    add("Detected type",report.fileType);
    add("Magic bytes",report.signature.isEmpty()?"No known signature":report.signature);
    add("File size",QString::number(report.fileSize)+" bytes");
    add("Entropy windows",QString::number(report.entropy.size()));
    add("Extracted strings",QString::number(report.strings.size()));
    tree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    structureDock->setWidget(tree);
    addDockWidget(Qt::LeftDockWidgetArea,structureDock);
    auto *entropyDock=new QDockWidget("Entropy Map (256 KiB windows)",this);
    entropyDock->setObjectName("EntropyDock");
    auto *entropyTable=new QTableWidget(entropyDock);
    entropyTable->setColumnCount(3);
    entropyTable->setHorizontalHeaderLabels({"Offset (hex)","Bytes","Bits / byte"});
    const int entropyRows=std::min<int>(report.entropy.size(),20000);
    entropyTable->setRowCount(entropyRows);
    for(int i=0;i<entropyRows;++i) {
        const auto &e=report.entropy[i];
        entropyTable->setItem(i,0,new QTableWidgetItem(QString::number(e.offset,16).toUpper()));
        entropyTable->setItem(i,1,new QTableWidgetItem(QString::number(e.size)));
        entropyTable->setItem(i,2,new QTableWidgetItem(QString::number(e.bitsPerByte,'f',3)));
    }
    entropyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    entropyTable->horizontalHeader()->setStretchLastSection(true);
    connect(entropyTable,&QTableWidget::cellDoubleClicked,this,[this,report](int row,int){
        if(row>=0 && row<report.entropy.size()) hex_->jumpTo(report.entropy[row].offset);
    });
    entropyDock->setWidget(entropyTable);
    addDockWidget(Qt::RightDockWidgetArea,entropyDock);
    auto *stringsDock=new QDockWidget("Extracted Strings",this);
    stringsDock->setObjectName("StringsDock");
    auto *stringsTable=new QTableWidget(stringsDock);
    stringsTable->setColumnCount(3);
    stringsTable->setHorizontalHeaderLabels({"Offset (hex)","Encoding","String"});
    stringsTable->setRowCount(static_cast<int>(report.strings.size()));
    for(int i=0;i<report.strings.size();++i) {
        const auto &item=report.strings[i];
        stringsTable->setItem(i,0,new QTableWidgetItem(QString::number(item.offset,16).toUpper()));
        stringsTable->setItem(i,1,new QTableWidgetItem(item.encoding));
        stringsTable->setItem(i,2,new QTableWidgetItem(item.value));
    }
    stringsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stringsTable->horizontalHeader()->setStretchLastSection(true);
    connect(stringsTable,&QTableWidget::cellDoubleClicked,this,[this,report](int row,int){
        if(row>=0 && row<report.strings.size()) hex_->jumpTo(report.strings[row].offset);
    });
    stringsDock->setWidget(stringsTable);
    addDockWidget(Qt::BottomDockWidgetArea,stringsDock);
    resizeDocks({structureDock,entropyDock},{280,350},Qt::Horizontal);
    resizeDocks({stringsDock},{220},Qt::Vertical);
    status_->setText("Analysis completed: "+report.fileType);
}

void MainWindow::inspectPE() {
    if(!doc_) {QMessageBox::information(this,"PE Inspector","Open a file first.");return;}
    PEReport report=PEInspector::inspect(doc_->path());
    if(!report.valid) {QMessageBox::warning(this,"PE Inspector",report.error);return;}
    auto *dock=findChild<QDockWidget*>("PEDock");
    if(!dock) {
        dock=new QDockWidget("PE Structure",this);
        dock->setObjectName("PEDock");
        addDockWidget(Qt::RightDockWidgetArea,dock);
    }
    auto *table=new QTreeWidget(dock);
    table->setHeaderLabels({"PE field","Value"});
    auto item=[&](const QString &k,const QString &v) {
        auto *row=new QTreeWidgetItem(table);
        row->setText(0,k);row->setText(1,v);
    };
    item("Architecture",report.architecture);
    item("Sections",QString::number(report.sectionCount));
    item("Image base",QString("0x%1").arg(report.imageBase,0,16));
    item("Entry RVA",QString("0x%1").arg(report.entryPointRva,0,16));
    item("Imported DLLs",QString::number(report.imports.size()));
    if(!report.importWarning.isEmpty()) item("Import warning",report.importWarning);
    for(const auto &imp:report.imports) {
        auto *dll=new QTreeWidgetItem(table);
        dll->setText(0,imp.dll);
        dll->setText(1,QString("%1 symbols").arg(imp.functions.size()));
        for(const auto &symbol:imp.functions) {
            auto *fn=new QTreeWidgetItem(dll);
            fn->setText(0,symbol);
        }
    }
    for(const auto &section:report.sections) {
        item(section.name,QString("RVA 0x%1 | Raw 0x%2 | %3 bytes")
            .arg(section.virtualAddress,0,16).arg(section.rawOffset,0,16).arg(section.rawSize));
    }
    table->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
}
void MainWindow::compareFiles() {
    QString left=QFileDialog::getOpenFileName(this,"Select first file");
    if(left.isEmpty()) return;
    QString right=QFileDialog::getOpenFileName(this,"Select second file");
    if(right.isEmpty()) return;
    startBackgroundTask<DiffReport>(this,"Comparing binary files...",
        [left,right](const auto &progress){
            return DiffEngine::compare(left,right,progress);
        },[this](DiffReport report){
            if(!report.error.isEmpty()) {
                if(!report.cancelled) QMessageBox::warning(this,"Diff error",report.error);
                return;
            }
    auto *dock=findChild<QDockWidget*>("DiffDock");
    if(!dock) {
        dock=new QDockWidget("Binary Diff",this);
        dock->setObjectName("DiffDock");
        addDockWidget(Qt::BottomDockWidgetArea,dock);
    }
    auto *table=new QTableWidget(dock);
    table->setColumnCount(2);
    table->setHorizontalHeaderLabels({"Changed offset (hex)","Length (bytes)"});
    table->setRowCount(report.ranges.size());
    for(int i=0;i<report.ranges.size();++i) {
        table->setItem(i,0,new QTableWidgetItem(QString::number(report.ranges[i].offset,16).toUpper()));
        table->setItem(i,1,new QTableWidgetItem(QString::number(report.ranges[i].length)));
    }
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
    status_->setText(QString("Diff: %1 changed bytes, %2 ranges%3")
        .arg(report.changedBytes).arg(report.ranges.size()).arg(report.truncated?" (range list capped)":""));
    });
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if(property("yas.activeTasks").toInt()>0 || findChild<QFutureWatcher<QString>*>("HashWorker")) {
        QMessageBox::information(this,"Background tasks running",
            "Wait for active tasks to finish or cancel them before closing. "
            "This prevents worker callbacks from accessing destroyed UI objects.");
        event->ignore();
        return;
    }
    QSettings settings("YAS","BinaryLabX");
    settings.setValue("window/geometry",saveGeometry());
    settings.setValue("window/dockState",saveState());
    saveSession();
    QMainWindow::closeEvent(event);
}

void MainWindow::disassembleFile() {
    if(!doc_) {QMessageBox::information(this,"Disassembly","Open a binary file first.");return;}
    QDialog dialog(this);
    dialog.setWindowTitle("Disassembly settings");
    QFormLayout layout(&dialog);
    QLineEdit offsetInput(QString("0x%1").arg(hex_->currentOffset(),0,16),&dialog);
    QLineEdit addressInput(QString("0x%1").arg(hex_->currentOffset(),0,16),&dialog);
    QComboBox architecture(&dialog);
    architecture.addItems({"x86-64","x86 (32-bit)"});
    QSpinBox count(&dialog);
    count.setRange(1,2000);count.setValue(300);
    layout.addRow("File offset (hex)",&offsetInput);
    layout.addRow("Virtual address (hex)",&addressInput);
    layout.addRow("Architecture",&architecture);
    layout.addRow("Maximum instructions",&count);
    QDialogButtonBox buttons(QDialogButtonBox::Ok|QDialogButtonBox::Cancel,&dialog);
    layout.addRow(&buttons);
    connect(&buttons,&QDialogButtonBox::accepted,&dialog,&QDialog::accept);
    connect(&buttons,&QDialogButtonBox::rejected,&dialog,&QDialog::reject);
    if(dialog.exec()!=QDialog::Accepted)return;
    auto parseHex=[](QString text,bool &ok)->quint64 {
        text=text.trimmed();if(text.startsWith("0x",Qt::CaseInsensitive))text=text.mid(2);
        return text.toULongLong(&ok,16);
    };
    bool okOffset=false,okAddress=false;
    quint64 offset=parseHex(offsetInput.text(),okOffset);
    quint64 address=parseHex(addressInput.text(),okAddress);
    if(!okOffset||!okAddress||offset>=static_cast<quint64>(doc_->size())) {
        QMessageBox::warning(this,"Invalid offset","Enter valid hexadecimal offsets.");return;
    }
    DisassemblyReport report=DisassemblyEngine::decode(doc_->path(),offset,address,
        architecture.currentIndex()==0,count.value());
    if(!report.error.isEmpty()) {
        QMessageBox::warning(this,"Disassembly",report.error);return;
    }
    displayDisassembly(report,offset,address);
}
void MainWindow::disassemblePEEntry() {
    if(!doc_) {QMessageBox::information(this,"PE Entry","Open an EXE or DLL first.");return;}
    const PEReport pe=PEInspector::inspect(doc_->path());
    if(!pe.valid) {QMessageBox::warning(this,"PE Entry",pe.error);return;}
    if(pe.architecture!="x86" && pe.architecture!="x86-64") {
        QMessageBox::warning(this,"Unsupported architecture","Entry point disassembly currently supports x86 and x86-64 only.");return;
    }
    quint64 fileOffset=0;
    if(!PEInspector::rvaToFileOffset(pe,pe.entryPointRva,static_cast<quint64>(doc_->size()),fileOffset)) {
        QMessageBox::warning(this,"PE Entry","Entry RVA does not map to file-backed section bytes.");return;
    }
    if(pe.imageBase>UINT64_MAX-static_cast<quint64>(pe.entryPointRva)) {
        QMessageBox::warning(this,"PE Entry","Virtual address overflow.");return;
    }
    const quint64 address=pe.imageBase+pe.entryPointRva;
    DisassemblyReport report=DisassemblyEngine::decode(doc_->path(),fileOffset,address,
                                                       pe.architecture=="x86-64",300);
    if(!report.error.isEmpty()) {QMessageBox::warning(this,"PE Entry",report.error);return;}
    displayDisassembly(report,fileOffset,address);
}
void MainWindow::displayDisassembly(const DisassemblyReport &report,quint64 offset,quint64 address) {
    auto *dock=findChild<QDockWidget*>("DisassemblyDock");
    if(!dock) {
        dock=new QDockWidget("Disassembly",this);
        dock->setObjectName("DisassemblyDock");
        addDockWidget(Qt::BottomDockWidgetArea,dock);
    }
    auto *table=new QTableWidget(dock);
    table->setColumnCount(4);
    table->setHorizontalHeaderLabels({"Address","Bytes","Instruction","Operands"});
    table->setRowCount(report.instructions.size());
    for(int i=0;i<report.instructions.size();++i) {
        const Instruction &ins=report.instructions[i];
        table->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ins.address,0,16)));
        table->setItem(i,1,new QTableWidgetItem(ins.bytes));
        table->setItem(i,2,new QTableWidgetItem(ins.mnemonic));
        table->setItem(i,3,new QTableWidgetItem(ins.operands));
    }
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);
    connect(table,&QTableWidget::cellDoubleClicked,this,[this,report,offset,address,sourcePath=doc_?doc_->path():QString()](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath)return;
        if(row<0||row>=report.instructions.size())return;
        quint64 va=report.instructions[row].address;
        if(va<address)return;
        quint64 delta=va-address;
        if(delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    dock->setWidget(table);
    dock->setProperty("analysisPath",doc_?doc_->path():QString());
    dock->show();
    // Direct control-flow references only: does not infer functions or indirect targets.
    auto *branches=findChild<QDockWidget*>("BranchReferencesDock");
    if(!branches) {
        branches=new QDockWidget("Direct Branch References",this);
        branches->setObjectName("BranchReferencesDock");
        addDockWidget(Qt::RightDockWidgetArea,branches);
    }
    auto *refs=new QTableWidget(branches);
    refs->setColumnCount(3);
    refs->setHorizontalHeaderLabels({"From","Branch","Target"});
    QVector<int> branchRows;
    for(int i=0;i<report.instructions.size();++i) {
        const auto &ins=report.instructions[i];
        const QString op=ins.mnemonic.toLower();
        if(op=="call" || op=="jmp" || op.startsWith('j') || op=="loop" || op=="loope" || op=="loopne")
            branchRows.append(i);
    }
    refs->setRowCount(branchRows.size());
    for(int i=0;i<branchRows.size();++i) {
        const auto &ins=report.instructions[branchRows[i]];
        refs->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ins.address,0,16)));
        refs->setItem(i,1,new QTableWidgetItem(ins.mnemonic));
        refs->setItem(i,2,new QTableWidgetItem(ins.operands));
    }
    refs->setEditTriggers(QAbstractItemView::NoEditTriggers);
    refs->horizontalHeader()->setStretchLastSection(true);
    branches->setWidget(refs);
    branches->setProperty("analysisPath",doc_?doc_->path():QString());
    branches->show();
    // Control flow from the decoded instruction window; not full program recovery.
    const FlowReport flowReport=ControlFlowEngine::build(report);
    auto *flowDock=findChild<QDockWidget*>("ControlFlowDock");
    if(!flowDock) {
        flowDock=new QDockWidget("Control Flow — Basic Blocks",this);
        flowDock->setObjectName("ControlFlowDock");
        addDockWidget(Qt::RightDockWidgetArea,flowDock);
    }
    auto *flowTree=new QTreeWidget(flowDock);
    flowTree->setHeaderLabels({"Block / edge","Target","Classification"});
    for(const auto &block:flowReport.blocks) {
        auto *parent=new QTreeWidgetItem(flowTree);
        parent->setText(0,QString("Block %1").arg(block.firstInstruction));
        parent->setText(1,QString("0x%1").arg(block.start,0,16));
        parent->setText(2,QString("%1 instructions").arg(block.lastInstruction-block.firstInstruction+1));
        parent->setData(0,Qt::UserRole,QVariant::fromValue(static_cast<qulonglong>(block.start)));
        for(const auto &edge:flowReport.edges) {
            if(edge.from!=block.start)continue;
            auto *child=new QTreeWidgetItem(parent);
            child->setText(0,edge.kind);
            child->setText(1,edge.kind.startsWith("indirect")?"Unresolved":
                           QString("0x%1").arg(edge.to,0,16));
            child->setText(2,edge.targetDecoded?"Decoded":"External / unknown");
            if(edge.targetDecoded)
                child->setData(0,Qt::UserRole,QVariant::fromValue(static_cast<qulonglong>(edge.to)));
        }
    }
    connect(flowTree,&QTreeWidget::itemDoubleClicked,this,[this,offset,address,sourcePath=doc_?doc_->path():QString()](QTreeWidgetItem *item,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath)return;
        if(!item->data(0,Qt::UserRole).isValid())return;
        quint64 va=item->data(0,Qt::UserRole).toULongLong();
        if(va<address)return;
        quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    flowTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    flowDock->setWidget(flowTree);
    flowDock->setProperty("analysisPath",doc_?doc_->path():QString());
    flowDock->show();
    auto *graphDock=findChild<QDockWidget*>("FlowGraphDock");
    if(!graphDock) {
        graphDock=new QDockWidget("Visual Control Flow Graph",this);
        graphDock->setObjectName("FlowGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,graphDock);
    }
    auto *graphView=new FlowGraphView(graphDock);
    graphView->setReport(flowReport);
    const QString sourcePath=doc_?doc_->path():QString();
    connect(graphView,&FlowGraphView::addressActivated,this,[this,sourcePath,offset,address](quint64 va){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath || va<address)return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    graphDock->setWidget(graphView);
    graphDock->setProperty("analysisPath",sourcePath);
    graphDock->show();
    const CrossReferenceReport crossRefs=CrossReferenceEngine::analyze(report);
    auto *xrefDock=findChild<QDockWidget*>("CrossReferenceDock");
    if(!xrefDock) {
        xrefDock=new QDockWidget("Direct Cross References",this);
        xrefDock->setObjectName("CrossReferenceDock");
        addDockWidget(Qt::RightDockWidgetArea,xrefDock);
    }
    auto *xrefTable=new QTableWidget(xrefDock);
    xrefTable->setColumnCount(4);
    xrefTable->setHorizontalHeaderLabels({"Source","Target","Instruction","Scope"});
    xrefTable->setRowCount(crossRefs.references.size());
    for(int i=0;i<crossRefs.references.size();++i) {
        const auto &ref=crossRefs.references[i];
        xrefTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(ref.from,0,16)));
        xrefTable->setItem(i,1,new QTableWidgetItem(QString("0x%1").arg(ref.to,0,16)));
        xrefTable->setItem(i,2,new QTableWidgetItem(ref.mnemonic));
        xrefTable->setItem(i,3,new QTableWidgetItem(ref.targetInWindow?"Decoded":"Outside window"));
    }
    xrefTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    xrefTable->horizontalHeader()->setStretchLastSection(true);
    connect(xrefTable,&QTableWidget::cellDoubleClicked,this,
            [this,crossRefs,sourcePath,offset,address](int row,int column){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=crossRefs.references.size())return;
        const auto &ref=crossRefs.references[row];
        const quint64 va=column==0?ref.from:ref.to;
        if(va<address || (column!=0 && !ref.targetInWindow))return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    xrefDock->setWidget(xrefTable);
    xrefDock->setProperty("analysisPath",sourcePath);
    xrefDock->show();
    auto *functionDock=findChild<QDockWidget*>("FunctionCandidatesDock");
    if(!functionDock) {
        functionDock=new QDockWidget("Function Candidates — Direct Calls",this);
        functionDock->setObjectName("FunctionCandidatesDock");
        addDockWidget(Qt::RightDockWidgetArea,functionDock);
    }
    auto *functionTable=new QTableWidget(functionDock);
    functionTable->setColumnCount(3);
    functionTable->setHorizontalHeaderLabels({"Candidate entry","Direct callers","Scope"});
    functionTable->setRowCount(crossRefs.functions.size());
    for(int i=0;i<crossRefs.functions.size();++i) {
        const auto &f=crossRefs.functions[i];
        functionTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(f.entry,0,16)));
        functionTable->setItem(i,1,new QTableWidgetItem(QString::number(f.callCount)));
        functionTable->setItem(i,2,new QTableWidgetItem(f.inWindow?"Decoded":"Outside window"));
    }
    functionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    functionTable->horizontalHeader()->setStretchLastSection(true);
    connect(functionTable,&QTableWidget::cellDoubleClicked,this,
            [this,crossRefs,sourcePath,offset,address](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=crossRefs.functions.size())return;
        const auto &f=crossRefs.functions[row];
        if(!f.inWindow || f.entry<address)return;
        const quint64 delta=f.entry-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    functionDock->setWidget(functionTable);
    functionDock->setProperty("analysisPath",sourcePath);
    functionDock->show();
    const FunctionAnalysisReport functionAnalysis=FunctionAnalysisEngine::analyze(report);
    auto *regionDock=findChild<QDockWidget*>("FunctionRegionsDock");
    if(!regionDock) {
        regionDock=new QDockWidget("Function Regions (Heuristic)",this);
        regionDock->setObjectName("FunctionRegionsDock");
        addDockWidget(Qt::RightDockWidgetArea,regionDock);
    }
    auto *regionTable=new QTableWidget(regionDock);
    regionTable->setColumnCount(5);
    regionTable->setHorizontalHeaderLabels({"Entry","Last decoded","Instructions","Callers","End / Scope"});
    regionTable->setRowCount(functionAnalysis.regions.size());
    for(int i=0;i<functionAnalysis.regions.size();++i) {
        const auto &f=functionAnalysis.regions[i];
        regionTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(f.entry,0,16)));
        regionTable->setItem(i,1,new QTableWidgetItem(f.entryInWindow?QString("0x%1").arg(f.lastAddress,0,16):"—"));
        regionTable->setItem(i,2,new QTableWidgetItem(QString::number(f.instructionCount)));
        regionTable->setItem(i,3,new QTableWidgetItem(QString::number(f.directCallers)));
        regionTable->setItem(i,4,new QTableWidgetItem(!f.entryInWindow?"External":f.terminatesWithReturn?"RET":"Uncertain"));
    }
    regionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    regionTable->horizontalHeader()->setStretchLastSection(true);
    connect(regionTable,&QTableWidget::cellDoubleClicked,this,
            [this,functionAnalysis,sourcePath,offset,address](int row,int){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=functionAnalysis.regions.size())return;
        const auto &region=functionAnalysis.regions[row];
        if(!region.entryInWindow || region.entry<address)return;
        const quint64 delta=region.entry-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    regionDock->setWidget(regionTable);
    regionDock->setProperty("analysisPath",sourcePath);
    regionDock->show();
    auto *callDock=findChild<QDockWidget*>("CallGraphDock");
    if(!callDock) {
        callDock=new QDockWidget("Direct Call Graph — Edges",this);
        callDock->setObjectName("CallGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,callDock);
    }
    auto *callTable=new QTableWidget(callDock);
    callTable->setColumnCount(4);
    callTable->setHorizontalHeaderLabels({"Caller region","Call site","Target","Scope"});
    callTable->setRowCount(functionAnalysis.calls.size());
    for(int i=0;i<functionAnalysis.calls.size();++i) {
        const auto &edge=functionAnalysis.calls[i];
        callTable->setItem(i,0,new QTableWidgetItem(QString("0x%1").arg(edge.callerRegion,0,16)));
        callTable->setItem(i,1,new QTableWidgetItem(QString("0x%1").arg(edge.instructionAddress,0,16)));
        callTable->setItem(i,2,new QTableWidgetItem(QString("0x%1").arg(edge.target,0,16)));
        callTable->setItem(i,3,new QTableWidgetItem(edge.targetInWindow?"Decoded":"External"));
    }
    callTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    callTable->horizontalHeader()->setStretchLastSection(true);
    connect(callTable,&QTableWidget::cellDoubleClicked,this,
            [this,functionAnalysis,sourcePath,offset,address](int row,int column){
        if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
           row<0 || row>=functionAnalysis.calls.size())return;
        const auto &edge=functionAnalysis.calls[row];
        if(column==2 && !edge.targetInWindow)return;
        const quint64 va=column==0?edge.callerRegion:column==2?edge.target:edge.instructionAddress;
        if(va<address)return;
        const quint64 delta=va-address;
        if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
           delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
        hex_->jumpTo(static_cast<qint64>(offset+delta));
    });
    callDock->setWidget(callTable);
    callDock->setProperty("analysisPath",sourcePath);
    callDock->show();
    // Visual call graph: nodes are heuristic function regions, not proven functions.
    FlowReport callGraph;
    QSet<quint64> functionAddresses;
    for(const auto &region:functionAnalysis.regions) {
        if(functionAddresses.contains(region.entry))continue;
        functionAddresses.insert(region.entry);
        FlowBlock block;
        block.start=region.entry;
        block.endExclusive=region.lastAddress;
        block.firstInstruction=0;
        block.lastInstruction=std::max(0,region.instructionCount-1);
        callGraph.blocks.append(block);
    }
    for(const auto &call:functionAnalysis.calls) {
        if(!functionAddresses.contains(call.callerRegion))continue;
        callGraph.edges.append({call.callerRegion,call.target,"call",
            functionAddresses.contains(call.target)});
    }
    auto *visualCallDock=findChild<QDockWidget*>("VisualCallGraphDock");
    if(!visualCallDock) {
        visualCallDock=new QDockWidget("Visual Function Call Graph",this);
        visualCallDock->setObjectName("VisualCallGraphDock");
        addDockWidget(Qt::RightDockWidgetArea,visualCallDock);
    }
    auto *visualCallView=new FlowGraphView(visualCallDock);
    visualCallView->setReport(callGraph);
    connect(visualCallView,&FlowGraphView::addressActivated,this,
        [this,sourcePath,offset,address,functionAddresses](quint64 va){
            if(!hex_ || hex_->property("filePath").toString()!=sourcePath ||
               !functionAddresses.contains(va) || va<address)return;
            const quint64 delta=va-address;
            if(offset>static_cast<quint64>(std::numeric_limits<qint64>::max()) ||
               delta>static_cast<quint64>(std::numeric_limits<qint64>::max())-offset)return;
            hex_->jumpTo(static_cast<qint64>(offset+delta));
        });
    visualCallDock->setWidget(visualCallView);
    visualCallDock->setProperty("analysisPath",sourcePath);
    visualCallDock->show();
    status_->setText(QString("Disassembled %1 instructions; %2 branch instructions")
        .arg(report.instructions.size()).arg(branchRows.size()));
}
