#ifndef HACKPROCESSWINDOW_H
#define HACKPROCESSWINDOW_H

#include "Backend_files\stllist.h"
#include <QDialog>
#include <QtWidgets>

namespace Ui {
class HackProcessWindow;
}

class HackProcessWindow : public QDialog
{
    Q_OBJECT

public:
    explicit HackProcessWindow(QWidget *parent = nullptr);
    ~HackProcessWindow();

private:
    Ui::HackProcessWindow *ui;

public:
    QLineEdit* processName;

    QComboBox* integrityLevel;

    QTableWidget* libTable;

    list <info> ::iterator processNode;

private slots:
    void on_integrityLevelComboBox_currentIndexChanged(const QString &IntegrityLevelStr);
};

#endif // HACKPROCESSWINDOW_H
