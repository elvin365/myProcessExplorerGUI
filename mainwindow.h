#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtWidgets>

#include <Backend_files\stllist.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void SetUpToolBar();

private:
    void HackProcess();
    void HackFile();

    void RefreshTable();
    void UploadTable();
    void ClearTable();
    void FillProcInfoList(std::list<info>& procInfoList);

private:
    Ui::MainWindow *ui;

    QTableWidget* procInfoTable;



};
#endif // MAINWINDOW_H
