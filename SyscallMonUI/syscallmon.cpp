#include <QMessageBox>
#include <QTranslator>

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <shlwapi.h>
#include <evntrace.h>
#include <evntcons.h>

#include "syscallmon.h"
#include "driverloader.h"
#include "DriverWrapper.h"
#include "ProcessMgr.h"
#include "EventMgr.h"
#include "ModuleMgr.h"
#include "StringMgr.h"
#include "util.h"
#include "../Shared/Protocol.h"
#include "symloaddialog.h"

#define STATUS_HV_FEATURE_UNAVAILABLE    ((NTSTATUS)0xC035001EL)

CSyscallMon *m_SyscallMon;

static TCHAR SessionName[] = TEXT("SysMonSession");

static TRACEHANDLE g_tracehandle = INVALID_PROCESSTRACE_HANDLE;

static GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};


static VOID
WINAPI
TraceEventCallback(
    _In_ PEVENT_RECORD EventRecord
)
{
    if (!EventRecord->UserData)
    {
        return;
    }

    CMonitorWorker *pcMW = (CMonitorWorker *)EventRecord->UserContext;
    PUCHAR buf = (PUCHAR)EventRecord->UserData;
    PUCHAR dataBuf = buf;
    pcMW->ParseMessage(dataBuf);
}

VOID TraceStop(VOID)
{
    BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
    RtlZeroMemory(Buffer, sizeof(Buffer));

    PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
    EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

    StopTrace(0, SessionName, EventTraceProperties);
}

//controller
VOID TraceSessionEnable(VOID)
{
    ULONG ErrorCode;

    TRACEHANDLE TraceSessionHandle = INVALID_PROCESSTRACE_HANDLE;

    BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
    RtlZeroMemory(Buffer, sizeof(Buffer));

    TraceStop();

    PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
    EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
    EventTraceProperties->Wnode.ClientContext = 1; // Use QueryPerformanceCounter, see MSDN
    EventTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    EventTraceProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;
    EventTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ErrorCode = StartTrace(&TraceSessionHandle, SessionName, EventTraceProperties);
    if (ErrorCode != ERROR_SUCCESS)
    {
        goto Exit;
    }

    ErrorCode = EnableTrace(TRUE, 0, 0, &ProviderGuid, TraceSessionHandle);
    if (ErrorCode != ERROR_SUCCESS)
    {
        goto Exit;
    }
    g_tracehandle = TraceSessionHandle;
    return;

Exit:
    if (TraceSessionHandle)
    {
        CloseTrace(TraceSessionHandle);
    }

    RtlZeroMemory(Buffer, sizeof(Buffer));
    EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);
    StopTrace(0, SessionName, EventTraceProperties);
}

//consumer
static DWORD TraceStart (PVOID pContext)
{
    ULONG ErrorCode;
    TRACEHANDLE TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    EVENT_TRACE_LOGFILE TraceLogfile = { 0 };

    TraceLogfile.LoggerName = SessionName;
    TraceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    TraceLogfile.EventRecordCallback = &TraceEventCallback;
    TraceLogfile.Context = pContext;

    TraceHandle = OpenTrace(&TraceLogfile);
    if (TraceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        ErrorCode = GetLastError();
        goto Exit;
    }

    ErrorCode = ProcessTrace(&TraceHandle, 1, NULL, NULL);

Exit:

    if (ErrorCode != ERROR_SUCCESS)
    {
    }

    return ErrorCode;
}

CMonitorWorker::CMonitorWorker(QObject *parent) : QThread(parent)
{
    m_hQuitEvent = NULL;
}

void CMonitorWorker::Quit(void)
{
    //StopTrace(0, SessionName, EventTraceProperties);
    TraceStop();
    ULONG ErrorCode = EnableTrace(FALSE, 0, 0, &ProviderGuid, g_tracehandle);
    if (g_tracehandle)
    {
        CloseTrace(g_tracehandle);
        g_tracehandle = NULL;
    }

    if (m_hQuitEvent != NULL) {
        SetEvent(m_hQuitEvent);
    }
}

void CMonitorWorker::run(void)
{
    HANDLE hEvents[2];
    static UCHAR buf[0x4000];

    setPriority(HighestPriority);

    hEvents[0] = m_ProcessMgr->m_hReadyEvent;
    hEvents[1] = m_EventMgr->m_hReadyEvent;
    WaitForMultipleObjects(2, hEvents, TRUE, INFINITE);

    OVERLAPPED ovlp;
    ovlp.hEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
    ovlp.Internal = 0;
    ovlp.InternalHigh = 0;
    ovlp.Pointer = 0;
    ovlp.Offset = 0;
    ovlp.OffsetHigh = 0;

    hEvents[0] = ovlp.hEvent;
    hEvents[1] = m_hQuitEvent;

#if 0
    while (1)
    {
        if (WaitForSingleObject(m_hQuitEvent, 0) == WAIT_OBJECT_0)
            break;

        memset(buf, 0, 0x4000);
        HRESULT hres = m_Driver.Read(buf, 0x4000, &ovlp);
        if (hres == HRESULT_FROM_WIN32(ERROR_IO_PENDING) || hres == S_OK)
        {
            DWORD signal = WAIT_OBJECT_0;
            if (hres == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
            {
                DWORD signal = WaitForMultipleObjects(2, hEvents, FALSE, 1000);
                if (signal == (WAIT_OBJECT_0 + 1))//time to quit
                    break;
            }

            if(signal == WAIT_OBJECT_0){
                PUCHAR dataBuf = buf + 16;
                ParseMessage(dataBuf);
            }
        }
        else//if driver errors, wait and try again
        {
            if (WaitForSingleObject(m_hQuitEvent, 100) == WAIT_OBJECT_0)
                break;
        }
    }

    CloseHandle(ovlp.hEvent);
#else
    TraceSessionEnable();
    TraceStart(this);
#endif
}

CSyscallMon::CSyscallMon(QObject *parent) : QObject(parent)
{
    m_hMutex = NULL;

    new CEventMgr(this);
    new CProcessMgr(this);
    new CModuleMgr(this);
    new CStringMgr(this);
}

bool CSyscallMon::Initialize(void)
{
    m_hMutex = CreateMutex(NULL, TRUE, L"SyscallMonitorMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(m_hMutex);
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Syscall Monitor is already running!"), QMessageBox::Yes);
        return false;
    }

    if (!AdjustPrivilege(SE_DEBUG_NAME))
    {
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to get SE_DEBUG_NAME privilege!"), QMessageBox::Yes);
        return false;
    }

    if (!AdjustPrivilege(SE_LOAD_DRIVER_NAME))
    {
        QMessageBox::critical(NULL, tr("Fatal Error"), tr("Failed to get SE_LOAD_DRIVER_NAME privilege!"), QMessageBox::Yes);
        return false;
    }

    TCHAR szDirectory[MAX_PATH];
    GetModuleFilePath(NULL, szDirectory, MAX_PATH);

    QString drvFileName = IsAMD64() ? "SyscallMon64.sys" : "SyscallMon32.sys";
    QString drvFilePath = QString("%1\\%2").arg(QString::fromWCharArray(szDirectory), drvFileName);

    if (!PathFileExists((LPCWSTR)drvFilePath.utf16()))
    {
        QString err = QString(tr("Could not found %1!")).arg(drvFilePath);
        QMessageBox::critical(NULL, tr("Fatal Error"), err, QMessageBox::Yes);
        return false;
    }

    m_ModuleMgr->Initialize();

    SymLoadDialog *symLoadDialog = new SymLoadDialog();
    if(symLoadDialog->exec() != QDialog::Accepted)
        return false;

    //Load driver later...

    QString drvSymLink = QString("\\??\\%1").arg(drvFilePath);

    conn_context_data conn;
    conn.txsb = 'TXSB';
    conn.ver = 1;

    if (!m_Driver.Connect(L"\\SyscallMonPort", &conn, sizeof(conn)))
    {
        if (!m_Driver.Install((LPCWSTR)drvSymLink.utf16(), L"SyscallMon", L"SyscallMon"))
        {
            if(STATUS_HV_FEATURE_UNAVAILABLE == m_Driver.m_ErrorCode)
            {
                QMessageBox::critical(NULL, tr("Fatal Error"), tr("Intel VT-x/EPT is not support or not enabled in your system!"), QMessageBox::Yes);
                return false;
            }

            QMessageBox::critical(NULL, tr("Fatal Error"), QString::fromWCharArray(m_Driver.m_szErrorInfo), QMessageBox::Yes);
            return false;
        }
        if (!m_Driver.Connect(L"\\SyscallMonPort", &conn, sizeof(conn)))
        {
            QMessageBox::critical(NULL, tr("Fatal Error"), QString::fromWCharArray(m_Driver.m_szErrorInfo), QMessageBox::Yes);
            return false;
        }
    }
    else
    {
        wcscpy(m_Driver.m_pServiceName, L"SyscallMon");
        wcscpy(m_Driver.m_pDisplayName, L"SyscallMon");
    }

    m_MonitorWorker.Initialize();
    m_MonitorWorker.start();

    SetCaptureEnable(true);

    m_ProcessMgr->Initialize();
    m_EventMgr->Initialize();

    return true;
}

void CSyscallMon::Uninitialize(void)
{
    m_MonitorWorker.Quit();
    m_MonitorWorker.wait();
    m_MonitorWorker.Uninitialize();

    m_Driver.Disconnect();
    m_Driver.Uninstall();

    m_ModuleMgr->Uninitialize();
    m_EventMgr->Uninitialize();
    m_ProcessMgr->Uninitialize();

    if(m_hMutex != INVALID_HANDLE_VALUE)
        CloseHandle(m_hMutex);
}
