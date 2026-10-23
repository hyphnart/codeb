#include "SplitEngine.h"
#include "DiffEngine.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <QCryptographicHash>
#include <cstdlib>
static void require(bool pass,const char *message) {
    if(!pass) {qCritical()<<"FAIL:"<<message;std::exit(1);}
}
static QByteArray contents(const QString &path) {
    QFile file(path);
    require(file.open(QIODevice::ReadOnly),"open test file");
    return file.readAll();
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    QTemporaryDir temp;
    require(temp.isValid(),"create temporary directory");
    const QString input=temp.filePath("sample.bin");
    QByteArray data;
    for(int i=0;i<300001;++i) data.append(static_cast<char>(i%251));
    {
        QFile file(input);
        require(file.open(QIODevice::WriteOnly),"create input");
        require(file.write(data)==data.size(),"write input");
    }
    const QString parts=temp.filePath("parts");
    QString error;
    require(SplitEngine::split(input,parts,65536,{},error),"split file");
    const QString manifest=QDir(parts).filePath("sample.bin.yasmanifest.json");
    require(QFile::exists(manifest),"manifest created");
    const QString rebuilt=temp.filePath("rebuilt");
    require(SplitEngine::join(manifest,rebuilt,{},error),"join file");
    const QString output=QDir(rebuilt).filePath("sample.bin");
    require(contents(output)==data,"byte-for-byte reconstruction");
    DiffReport identical=DiffEngine::compare(input,output);
    require(identical.error.isEmpty() && identical.changedBytes==0,"identical diff");
    {
        QFile file(output);
        require(file.open(QIODevice::ReadWrite),"open rebuilt file for mutation");
        require(file.seek(12345),"seek");
        require(file.write("X",1)==1,"mutate");
    }
    DiffReport changed=DiffEngine::compare(input,output);
    require(changed.error.isEmpty() && changed.changedBytes==1,"one-byte diff");
    // Empty file round trip.
    const QString empty=temp.filePath("empty.bin");
    {QFile file(empty);require(file.open(QIODevice::WriteOnly),"create empty file");}
    const QString emptyParts=temp.filePath("empty-parts");
    require(SplitEngine::split(empty,emptyParts,64,{},error),"split empty");
    require(SplitEngine::join(QDir(emptyParts).filePath("empty.bin.yasmanifest.json"),
        temp.filePath("empty-rebuilt"),{},error),"join empty");
    require(contents(temp.filePath("empty-rebuilt/empty.bin")).isEmpty(),"empty output");
    qInfo()<<"PASS: split, rebuild, diff, empty file";
    return 0;
}
