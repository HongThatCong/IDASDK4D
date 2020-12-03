library IDAPlg4D;

uses
  Windows,
  dbfix;

{$E plw}

const
  IDP_INTERFACE_VERSION = 76;

  PLUGIN_MOD = $000;        // Plugin changes the database.
                            // IDA won't call the plugin if
                            // the processor prohibited any changes
                            // by setting PR_NOCHANGES in processor_t.
  PLUGIN_DRAW = $0002;      // IDA should redraw everything after calling
                            // the plugin
  PLUGIN_SEG = $0004;       // Plugin may be applied only if the
                            // current address belongs to a segment
  PLUGIN_UNL = $0008;       // Unload the plugin immediately after
                            // calling 'run'.
                            // This flag may be set anytime.
                            // The kernel checks it after each call to 'run'
                            // The main purpose of this flag is to ease
                            // the debugging of new plugins.
  PLUGIN_HIDE = $0010;      // Plugin should not appear in the Edit, Plugins menu
                            // This flag is checked at the start
  PLUGIN_DBG = $0020;       // A debugger plugin. init() should put
                            // the address of debugger_t to dbg
                            // See idd.hpp for details
  PLUGIN_PROC = $0040;      // Load plugin when a processor module is loaded and keep it
                            // until the processor module is unloaded
  PLUGIN_FIX = $0080;       // Load plugin when IDA starts and keep it in the
                            // memory until IDA stops
  PLUGIN_SCRIPTED = $8000;  // Scripted plugin. Should not be used by plugins,
                            // the kernel sets it automatically.
  PLUGIN_SKIP = 0;          // Plugin doesn't want to be loaded
  PLUGIN_OK = 1;            // Plugin agrees to work with the current database
                            // It will be loaded as soon as the user presses the hotkey
  PLUGIN_KEEP = 2;          // Plugin agrees to work with the current database
                            // and wants to stay in the memory

type
  plugin_t = packed record
    version: Integer;
    flags: Integer;
    init: function: Integer; stdcall;
    term: procedure; stdcall;
    run: procedure(arg: Integer); stdcall;
    comment: PAnsiChar;
    help: PAnsiChar;
    wanted_name: PAnsiChar;
    wanted_hotkey: PAnsiChar;
  end;

function IDAP_init: Integer; stdcall;
begin
  Result := PLUGIN_KEEP;
end;

procedure IDAP_term; stdcall;
begin
end;

procedure IDAP_run(arg: Integer); stdcall;
begin
end;

const
  SZ_ZERO = #0;
  PLUGIN_NAME = 'IDAPlg4D';

var
  plugin: plugin_t;
  IDAP_name: PAnsiChar = 'IDA plugin - power by Delphi';
  IDAP_comment: PAnsiChar = SZ_ZERO;
  IDAP_help: PAnsiChar = SZ_ZERO;
  IDAP_hotkey: PAnsiChar = SZ_ZERO;

procedure DLLMain(dwReason: DWORD);
begin
  case dwReason of
    DLL_PROCESS_ATTACH:
      begin
        OutputDebugString(PChar(PLUGIN_NAME + ' loaded by DLL_PROCESS_ATTACH'));
        DisableThreadLibraryCalls(HInstance);
        Patch;
      end;

    DLL_PROCESS_DETACH:
      OutputDebugString(PChar(PLUGIN_NAME + ' unloaded by DLL_PROCESS_DETACH'));
  end;
end;

exports
  plugin name 'PLUGIN';

begin
  with plugin do
  begin
    version := IDP_INTERFACE_VERSION;
    flags := PLUGIN_FIX or PLUGIN_HIDE;
    init := IDAP_init;
    term := nil;
    run := nil;
    comment := SZ_ZERO;
    help := SZ_ZERO;
    wanted_name := SZ_ZERO;
    wanted_hotkey := SZ_ZERO;
  end;

  DllProc := @DLLMain;
  DllProc(DLL_PROCESS_ATTACH);
end.
