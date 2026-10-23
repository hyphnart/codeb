#include "SplitEngine.h"
#include <QFile>
#include <QSaveFile>
#include <QDir>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <algorithm>
#include <limits>

namespace {
constexpr qint64 bufferSize=1024*1024;
QString digest(const QByteArray &data) {
    return QString::fromLatin1(QCryptographicHash::hash(data,QCryptographicHash::Sha256).toHex());
}
bool writeAll(QIODevice &out,const QByteArray &data) {
    qint64 offset=0;
    while(offset<data.size()) {
        qint64 written=out.write(data.constData()+offset,data.size()-offset);
        if(written<=0) return false;
        offset+=written;
    }
    return true;
}
QString hashResult(QCryptographicHash &h) {
    return QString::fromLatin1(h.result().toHex());
}
bool safeName(const QString &name) {
    return !name.isEmpty() && name!="." && name!=".." &&
        !name.contains('/') && !name.contains('\\') && !name.contains(':');
}
}
bool SplitEngine::split(const QString &source,const QString &destination,
                        qint64 partSize,const Progress &progress,QString &error) {
    if(partSize<=0) {error="Part size must be positive.";return false;}
    QFile in(source);
    if(!in.open(QIODevice::ReadOnly)) {error=in.errorString();return false;}
    QDir dir(destination);
    if(!dir.exists() && !QDir().mkpath(destination)) {error="Cannot create output directory.";return false;}
    QString base=QFileInfo(source).fileName();
    if(!safeName(base)) {error="Invalid source filename.";return false;}
    QString manifestPath=dir.filePath(base+".yasmanifest.json");
    if(QFileInfo::exists(manifestPath)) {error="Manifest already exists. Choose another output directory.";return false;}
    const qint64 total=in.size();
    QJsonArray parts;
    QCryptographicHash whole(QCryptographicHash::Sha256);
    qint64 done=0;
    int index=0;
    while(done<total) {
        ++index;
        QString name=QString("%1.part%2").arg(base).arg(index,6,10,QLatin1Char('0'));
        QString partPath=dir.filePath(name);
        if(QFileInfo::exists(partPath)) {error="Output part already exists: "+name;return false;}
        QSaveFile out(partPath);
        if(!out.open(QIODevice::WriteOnly)) {error=out.errorString();return false;}
        QCryptographicHash partHash(QCryptographicHash::Sha256);
        qint64 partWritten=0;
        const qint64 target=std::min(partSize,total-done);
        while(partWritten<target) {
            if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
            QByteArray block=in.read(std::min(bufferSize,target-partWritten));
            if(block.isEmpty()) {out.cancelWriting();error="Source read failed or source changed.";return false;}
            if(!writeAll(out,block)) {out.cancelWriting();error="Part write failed.";return false;}
            partHash.addData(block);whole.addData(block);
            partWritten+=block.size();done+=block.size();
        }
        if(!out.commit()) {error="Cannot commit part: "+name;return false;}
        QJsonObject p; p["name"]=name;p["size"]=QString::number(partWritten);p["sha256"]=hashResult(partHash);
        parts.append(p);
    }
    if(in.size()!=total) {error="Source size changed during operation.";return false;}
    QJsonObject meta;
    meta["format"]="YAS-SPLIT-1";meta["originalName"]=base;
    meta["originalSize"]=QString::number(total);
    meta["sha256"]=hashResult(whole);
    meta["partSize"]=QString::number(partSize);
    meta["parts"]=parts;
    QSaveFile manifest(manifestPath);
    if(!manifest.open(QIODevice::WriteOnly)) {error=manifest.errorString();return false;}
    if(!writeAll(manifest,QJsonDocument(meta).toJson(QJsonDocument::Indented)) || !manifest.commit()) {
        error="Could not write manifest.";return false;
    }
    if(progress) progress(total,total);
    return true;
}
bool SplitEngine::join(const QString &manifestPath,const QString &destination,
                       const Progress &progress,QString &error) {
    QFile manifest(manifestPath);
    if(!manifest.open(QIODevice::ReadOnly)) {error=manifest.errorString();return false;}
    QJsonParseError parse;
    QJsonDocument doc=QJsonDocument::fromJson(manifest.readAll(),&parse);
    if(parse.error!=QJsonParseError::NoError || !doc.isObject()) {error="Invalid manifest JSON.";return false;}
    QJsonObject meta=doc.object();
    if(meta.value("format").toString()!="YAS-SPLIT-1") {error="Unsupported manifest format.";return false;}
    bool ok=false;
    qint64 total=meta.value("originalSize").toString().toLongLong(&ok);
    if(!ok || total<0) {error="Invalid original size.";return false;}
    QString originalName=meta.value("originalName").toString();
    if(!safeName(originalName)) {error="Unsafe original filename.";return false;}
    QJsonArray parts=meta.value("parts").toArray();
    if((total>0 && parts.isEmpty()) || parts.size()>1000000) {error="Invalid part count.";return false;}
    QDir inputDir=QFileInfo(manifestPath).absoluteDir();
    QDir outputDir(destination);
    if(!outputDir.exists() && !QDir().mkpath(destination)) {error="Cannot create output directory.";return false;}
    QString target=outputDir.filePath(originalName);
    if(QFileInfo::exists(target)) {error="Output file already exists.";return false;}
    QSaveFile out(target);
    if(!out.open(QIODevice::WriteOnly)) {error=out.errorString();return false;}
    QCryptographicHash whole(QCryptographicHash::Sha256);
    qint64 done=0;
    for(const QJsonValue &v:parts) {
        if(!v.isObject()) {out.cancelWriting();error="Invalid part record.";return false;}
        QJsonObject p=v.toObject();
        QString name=p.value("name").toString();
        if(!safeName(name)) {out.cancelWriting();error="Unsafe part filename.";return false;}
        qint64 expected=p.value("size").toString().toLongLong(&ok);
        if(!ok || expected<0 || expected>total-done) {out.cancelWriting();error="Invalid part size.";return false;}
        QFile in(inputDir.filePath(name));
        if(!in.open(QIODevice::ReadOnly) || in.size()!=expected) {
            out.cancelWriting();error="Missing or invalid part: "+name;return false;
        }
        QCryptographicHash partHash(QCryptographicHash::Sha256);
        qint64 readCount=0;
        while(readCount<expected) {
            if(progress && !progress(done,total)) {out.cancelWriting();error="Cancelled.";return false;}
            QByteArray block=in.read(std::min(bufferSize,expected-readCount));
            if(block.isEmpty() || !writeAll(out,block)) {
                out.cancelWriting();error="Read/write error in: "+name;return false;
            }
            partHash.addData(block);whole.addData(block);
            readCount+=block.size();done+=block.size();
        }
        if(hashResult(partHash).compare(p.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
            out.cancelWriting();error="Part hash mismatch: "+name;return false;
        }
    }
    if(done!=total || hashResult(whole).compare(meta.value("sha256").toString(),Qt::CaseInsensitive)!=0) {
        out.cancelWriting();error="Original file checksum mismatch.";return false;
    }
    if(!out.commit()) {error="Cannot commit reconstructed file.";return false;}
    if(progress) progress(total,total);
    return true;
}
