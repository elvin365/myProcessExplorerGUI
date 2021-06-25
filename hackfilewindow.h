#ifndef HACKFILEWINDOW_H
#define HACKFILEWINDOW_H

#include <QDialog>
#include <QtWidgets>

namespace Ui {
class HackFileWindow;
}

class HackFileWindow : public QDialog
{
    Q_OBJECT

public:
    explicit HackFileWindow(QWidget *parent = nullptr);
    ~HackFileWindow();

private slots:
    void on_comboBox_currentIndexChanged(const QString &integrityLevelStr);
    void on_ownerComboBox_currentIndexChanged(const QString &ownerStr);

    void on_aclTable_cellActivated(int row, int column);

    void on_aclTable_cellClicked(int row, int column);

    void on_aclTable_itemClicked(QTableWidgetItem *item);

    void on_integrityLevelComboBox_currentIndexChanged(const QString &arg1);

private:
    Ui::HackFileWindow *ui;



public:
    QComboBox* integrityLevel;

    QLineEdit* owner;
    QLineEdit* fileName;
    QLineEdit* pathToFile;
    QLineEdit* ownerSid;

    QTableWidget* aclTable;

    bool isInitiated;
};

#endif // HACKFILEWINDOW_H
