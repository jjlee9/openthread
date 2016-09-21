// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <windows.h>
#include <winnt.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <mstcpip.h>
#include <IcmpAPI.h>
#include <rpc.h>
#include <rpcdce.h>
#include <new>
#include <vector>
#include <tuple>

// Define to export necessary functions
#define OTDLL
#define OTNODEAPI EXTERN_C __declspec(dllexport)

#include <openthread.h>
#include <commissioning/commissioner.h>
#include <commissioning/joiner.h>
#include <platform/logging-windows.h>
#include <otNode.h>

void Unload();
