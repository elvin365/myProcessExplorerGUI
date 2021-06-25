QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.

DEFINES -= UNICODE
DEFINES += \
    _MBCS \
    QT_DEPRECATED_WARNINGS



# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    Backend_files/123.cpp \
    Backend_files/32_64_bit.cpp \
    Backend_files/DEPandASLR.cpp \
    Backend_files/NameOfUserSID.cpp \
    Backend_files/acl.cpp \
    Backend_files/integrity_level_file.cpp \
    Backend_files/interglvl.cpp \
    Backend_files/parents.cpp \
    Backend_files/useful_functions.cpp \
    hackfilewindow.cpp \
    hackprocesswindow.cpp \
    main.cpp \
    mainwindow.cpp

RESOURCES     = application.qrc

HEADERS += \
    Backend_files/stllist.h \
    hackfilewindow.h \
    hackprocesswindow.h \
    mainwindow.h

FORMS += \
    hackfilewindow.ui \
    hackprocesswindow.ui \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES +=

