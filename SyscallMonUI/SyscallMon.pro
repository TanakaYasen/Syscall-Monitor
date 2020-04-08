#-------------------------------------------------
#
# Project created by QtCreator 2016-11-03T13:34:52
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SyscallMon
TEMPLATE = app

contains(QT_ARCH, i386) {
    DESTDIR = ../bin32
} else {
    DESTDIR = ../bin64
}

SOURCES += main.cpp\
        mainwindow.cpp \
    syscallmon.cpp \
    driverloader.cpp \
    util.cpp \
    EventFilter.cpp \
    EventMgr.cpp \
    ProcessMgr.cpp \
    DriverWrapper.cpp \
    Encode.cpp \
    Message.cpp \
    nt.cpp \
    ps.cpp \
    Image.cpp \
    eventtable.cpp \
    filterdialog.cpp \
    filtertable.cpp \
    filterloadingdialog.cpp \
    eventinfodialog.cpp \
    StringMgr.cpp \
    callstacktable.cpp \
    symloaddialog.cpp \
    ProcessTree.cpp \
    ModuleMgr.cpp \
    Event.cpp \
    registry.cpp \
    minidump.cpp \
    processinfodialog.cpp \
    clickablelineedit.cpp \
    dlmalloc.c \
    lua/lapi.c \
    lua/lauxlib.c \
    lua/lbaselib.c \
    lua/lbitlib.c \
    lua/lcode.c \
    lua/lcorolib.c \
    lua/lctype.c \
    lua/ldblib.c \
    lua/ldebug.c \
    lua/ldo.c \
    lua/ldump.c \
    lua/lfunc.c \
    lua/lgc.c \
    lua/linit.c \
    lua/liolib.c \
    lua/llex.c \
    lua/lmathlib.c \
    lua/lmem.c \
    lua/loadlib.c \
    lua/lobject.c \
    lua/lopcodes.c \
    lua/loslib.c \
    lua/lparser.c \
    lua/lstate.c \
    lua/lstring.c \
    lua/lstrlib.c \
    lua/ltable.c \
    lua/ltablib.c \
    lua/ltm.c \
    lua/lundump.c \
    lua/lutf8lib.c \
    lua/lvm.c \
    lua/lzio.c

HEADERS  += mainwindow.h \
    driverloader.h \
    syscallmon.h \
    util.h \
    EventFilter.h \
    EventMgr.h \
    ProcessMgr.h \
    DriverWrapper.h \
    Encode.h \
    nt.h \
    ps.h \
    filterdialog.h \
    filtertable.h \
    filterloadingdialog.h \
    eventinfodialog.h \
    StringMgr.h \
    ModuleMgr.h \
    callstacktable.h \
    symloaddialog.h \
    ProcessTree.h \
    EventTable.h \
    registry.h \
    processinfodialog.h \
    clickablelineedit.h \
    lua/lapi.h \
    lua/lauxlib.h \
    lua/lcode.h \
    lua/lctype.h \
    lua/ldebug.h \
    lua/ldo.h \
    lua/lfunc.h \
    lua/lgc.h \
    lua/llex.h \
    lua/llimits.h \
    lua/lmem.h \
    lua/lobject.h \
    lua/lopcodes.h \
    lua/lparser.h \
    lua/lprefix.h \
    lua/lstate.h \
    lua/lstring.h \
    lua/ltable.h \
    lua/ltm.h \
    lua/lua.h \
    lua/lua.hpp \
    lua/luaconf.h \
    lua/lualib.h \
    lua/lundump.h \
    lua/lvm.h \
    lua/lzio.h

FORMS    += mainwindow.ui \
    filterdialog.ui \
    filterloadingdialog.ui \
    eventinfodialog.ui \
    symloaddialog.ui \
    processinfodialog.ui

RESOURCES += resource.qrc

RC_FILE += SyscallMon.rc

QMAKE_LFLAGS += /MANIFESTUAC:\"level=\'requireAdministrator\' uiAccess=\'false\'\"
QMAKE_CXXFLAGS += /MP /Gm-
QMAKE_CFLAGS += /MP /Gm-

QMAKE_LFLAGS_RELEASE += ''

QMAKE_CXXFLAGS += /Zi
QMAKE_LFLAGS += /DEBUG

TRANSLATIONS+=cn.ts

LIBS += -lgdi32\
-ladvapi32\
-luser32\
-lshlwapi\
-lole32

INCLUDEPATH += $$PWD/../boost
DEPENDPATH += $$PWD/../boost
