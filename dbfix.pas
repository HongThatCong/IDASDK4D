unit dbfix;

interface

uses
  Windows, ImageHlp;

type
  TPattern = packed record
    old_bytes: PAnsiChar;
    new_bytes: PAnsiChar;
  end;

  TSearchPattern = record
    m_size: DWORD;
    m_pattern: array[0..1023] of SmallInt;
    procedure SetPattern(pattern: PAnsiChar);
    function FindPattern(const ptr: PByte; cbSize: DWORD): DWORD;
    function CopyPattern(const ptr: PByte; cbSize: DWORD): Boolean;
  end;

function IsHex(hc: Integer): Boolean;
function Hex2Int(hc: Integer): Integer;

function Patch: Boolean;

implementation

const
  SEARCH_NOT_FOUND = DWORD(-1);

  patch_61: array[0..3] of TPattern = (
    // is_on_blacklist
    (old_bytes: '8B4C2474 5F 5E 5B 33CC B001 E8........ 83 C4 6C';
     new_bytes: '8B4C2474 5F 5E 5B 33CC B000 E8........ 83 C4 6C'),

    // check_original_user
    (old_bytes: '5E 32C0 5B 8B8C24A0000000 33CC E8........ 81C4A4000000 C3';
     new_bytes: '5E B001 5B 8B8C24A0000000 33CC E8........ 81C4A4000000 C3'),

    // wrong_user_credentials
    (old_bytes: '3C20 7308 3C0A 0F85........ 8A4101';
     new_bytes: '3C20 EB08 3C0A 0F85........ 8A4101'),

     // private version
    (old_bytes: '8B0D........ 81F900800000 7D22 B801000000 33D2 E8........';
     new_bytes: '8B0D........ 81F900800000 EB22 B801000000 33D2 E8........'));


function IsHex(hc: Integer): Boolean; inline;
begin
  Result := ((hc >= $30) and (hc <= $39)) or ((hc >= $41) and (hc <= $46)) or ((hc >= $61) and (hc <= $66));
end;

function Hex2Int(hc: Integer): Integer; inline;
begin
  if (hc >= $30) and (hc <= $39) then
    Result := hc - $30
  else
  begin
    if (hc >= $61) and (hc <= $66) then
      Dec(hc, $20);
    Result := hc - $37;
  end;
end;

{ TSearchPattern }

procedure TSearchPattern.SetPattern(pattern: PAnsiChar);
var
  w1, w2: Word;
  val: SmallInt;
begin
  m_size := 0;
  ZeroMemory(@m_pattern, SizeOf(m_pattern));

  while (pattern^ <> #0) do
  begin
    val := -1;

    w1 := PByte(pattern)^;
    Inc(pattern);
    if (w1 = $20) then
      continue;

    w2 := PByte(pattern)^;
    Inc(pattern);

    if (IsHex(w1) and IsHex(w2)) then
    begin
      w1 := Hex2Int(w1);
      w2 := Hex2Int(w2);
      val := w2 or (w1 shl 4);
    end;

    m_pattern[m_size] := val;
    Inc(m_size);
  end;
end;

function TSearchPattern.FindPattern(const ptr: PByte; cbSize: DWORD): DWORD;
var
  I, J: Cardinal;
begin
  if (cbSize < m_size) then
    Exit(SEARCH_NOT_FOUND);

  for I := 0 to cbSize - m_size - 1 do
  begin
    if (ptr[I] = m_pattern[0]) then
    begin
      for J := 1 to m_size - 1 do
        if (m_pattern[J] >= 0) and (m_pattern[J] <> ptr[I + J ]) then
          break;
      if (J = m_size) then
        Exit(I);
    end;
  end;

  Result := SEARCH_NOT_FOUND;
end;

function TSearchPattern.CopyPattern(const ptr: PByte; cbSize: DWORD): Boolean;
var
  I: Integer;
begin
  if (cbSize < m_size) then
    Exit(False);

  for I := 0 to m_size - 1 do
    if m_pattern[I] >= 0 then
      ptr[I] := Byte(m_pattern[I]);

  Result := True;
end;

function Patch: Boolean;
var
  hMutex: THandle;
  szMutexName: array[0..255] of Char;
  dwPID, dwSize, dwVA: DWORD;
  wNumberOfSections: WORD;
  hWll: HMODULE;
  pNtHdr: PImageNtHeaders;
  pSec: PImageSectionHeader;
  spo, spn: TSearchPattern;
  I: Integer;
  paddr: PByte;
  dwPos, dwOld, dwTemp: DWORD;
begin
  dwSize := 0;
  dwVA := 0;

  dwPID := GetCurrentProcessId;
  wvsprintf(szMutexName, 'IDAPRO.DATABASE.FIX.%08X', @dwPID);
  hMutex := CreateMutex(nil, FALSE, szMutexName);
  if ((0 = hMutex) or (ERROR_ALREADY_EXISTS = GetLastError)) then
  begin
    OutputDebugString('IDA was already patched.');
    Exit(False);
  end;

  hWll := GetModuleHandle('ida.wll');
  if (0 = hWll) then
    hWll := GetModuleHandle('ida64.wll');
  if (0 = hWll) then
  begin
    OutputDebugString('Couldn''t find ida.wll nor ida64.wll,');
    Exit(False);
  end;

  pNtHdr := ImageNtHeader(Pointer(hWll));
  wNumberOfSections := pNtHdr^.FileHeader.NumberOfSections;
  pSec := PImageSectionHeader(DWORD(pNtHdr) + SizeOf(TImageNtHeaders));
  while DWORD(pSec) < DWORD(pNtHdr) + SizeOf(TImageNtHeaders) + wNumberOfSections * SizeOf(IMAGE_SECTION_HEADER) do
  begin
    if (0 = lstrcmpiA(PAnsiChar(@pSec^.Name), PAnsiChar('.text'))) then
    begin
      dwVA := pSec^.VirtualAddress + hWll;
      dwSize := pSec^.Misc.VirtualSize;
      Break;
    end;
    Inc(pSec);
  end;

  if (0 = dwSize) or (0 = dwVA) then
  begin
    OutputDebugString('Couldn''t find ida.wll/ida64.wll ".text" section');
    Exit(False);
  end;

  for I := Low(patch_61) to High(patch_61) do
  begin
    spo.SetPattern(patch_61[I].old_bytes);
    spn.SetPattern(patch_61[I].new_bytes);

    paddr := nil;
    dwPos := spo.FindPattern(PByte(dwVA), dwSize);
    if (dwPos <> SEARCH_NOT_FOUND) then
    begin
      paddr := PByte(dwVA + dwPos);
      dwPos := spo.FindPattern(PByte(dwVA + dwPos + 1), dwSize - dwPos - 1);
      if (dwPos <> SEARCH_NOT_FOUND) then
        paddr := nil;
    end;

    if (paddr <> nil) then
    begin
      VirtualProtect(paddr, spn.m_size, PAGE_READWRITE, dwOld);
      spn.CopyPattern(paddr, spn.m_size);
      VirtualProtect(paddr, spn.m_size, dwOld, dwTemp);
    end
    else
    begin
        OutputDebugString('Unknown version of IDA Pro.');
        Exit(False);
    end;
  end;

  FlushInstructionCache(GetCurrentProcess, Pointer(dwVA), dwSize);
  Result := True;
end;

end.
