#pragma once
#include <QGraphicsView>
#include "ControlFlowEngine.h"
class QGraphicsScene;
class QWheelEvent;
class FlowGraphView : public QGraphicsView {
    Q_OBJECT
public:
    explicit FlowGraphView(QWidget *parent=nullptr);
    void setReport(const FlowReport &report);
signals:
    void addressActivated(quint64 address);
protected:
    void wheelEvent(QWheelEvent *event) override;
private:
    QGraphicsScene *scene_;
};
