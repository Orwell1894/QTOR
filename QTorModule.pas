unit QTorModule;

interface

Uses
    System.Classes, System.Variants, System.SysUtils,
    idHTTP, IdSSL, IdSSLOpenSSL, IdCookieManager,
    IdCustomTransparentProxy, IdSocks, IdTCPClient,
    Vcl.Controls, Vcl.Forms, Winapi.Windows, SyncObjs,
    RegularExpressions, tlhelp32, PsApi, ShellApi;

//Регулярные Выражения
Const
//  Pat1 = '(?ism-x)(([0-9]{1,3}\.){3}([0-9]{1,3}))(.*?)((\d){1,5})';
//  Pat2 = '([0-9]{1,3}\.){3}([0-9]{1,3})';
//  RE_GL1 = '(?ims-x)(<body)(.+?)</body>';
//  RE_GL2 = '(?ism-x)(<h3)(.*?)((http|https)(.*?)(?=&amp;))';
  RE_GL2 = '(?ism-x)(<h3)(.*?)((http|https)(.*?)(?=&amp;))';
  RE_GL5 = '(http|https)(.*)\w';
  RE_GL4 = '(?ism-x)(([0-9]{1,3}\.){3}([0-9]{1,3}))(.*?)((\d){2,5})';
  RE_GL_IP = '(?ism-x)(([0-9]{1,3}\.){3}([0-9]{1,3}))';
  RE_GL_PORT = '(?sim-x)[0-9]{2,5}$';

Const
  TOR_exe = 'TorBrowser\Tor\Tor.exe';

//Строка поиска по носкам
Const google_search = 'https://www.google.com/search?q=free+socks5+proxy&start=';
      check_url = 'https://google.com';
      inc_word = 'google';

//Тип для поиска по процессам
type TPROC = record
    h,h1:THandle;
    pe:TProcessEntry32;
    path: array[0..MAX_PATH - 1] of char;
end;

//Тип регулярных выражений
type TRegExp = record
  RegEx: TRegEx;
  Option: TRegExOptions;
  Pattern: String;
  RMath: TMatch;
  RMathes: TMatchCollection;
end;

//Парсер на основе Indy
type TParser = Class(TObject)
  var
    FHTTP: TIdHTTP;
    FSSL: TIdSSLIOHandlerSocketOpenSSL;
    FCookie: TIdCookieManager;
    RegExp: TRegExp;
  constructor Create;
  destructor Destroy; override;
  function AsHTML(Url: String): String;
end;

//Тип Прокси
type TSocks = record
  ID: Integer;
  IP, PORT, STYPE, LOGIN, PASSW: String;
  Parent: Pointer;
  function InStrings: TStrings;
end;

//Объек ссылка с прокси
type TLink = Class(TObject)
  private

    Parser: TParser;
    R: TRegExp;
  public
    Url: String;
    Sockses: Array of TSocks;
    DeadSockses, LiveSockses, LiveTime: Cardinal;
    function ParseSocks: Boolean;
    procedure SocksRandomize;
    procedure AddS(IP,PORT: String; STYPE: String=''; LOGIN: String=''; PASSW: String=''); overload;
    procedure AddS(Socks: TSocks); overload;
    procedure DelS; overload;
    constructor Create(Sender: TObject);
    Destructor Destroy; override;
End;

type TSearchThread = Class(TThread)
  type PLink = ^TLink;
  private
    { Private declarations }
  protected
    procedure Execute; override;
  public

End;

procedure AddResult(Live: Boolean);


type TCheckThread = Class(TThread)
  type PLink = ^TLink;
  private
    { Private declarations }
  protected
    procedure Execute; override;
  public

End;

//Объект в котором все ссылки для поиска прокси и сами прокси
type TLinks = Class(TObject)
  Var
    Items: array of TLink;
    ItemIndex: Integer;
    n_google: Integer;
    Parser: TParser;
    R: TRegExp;
    Enable: Boolean;
  public
    function ParseLinks: Boolean;
    procedure AddL(Url: String); overload;
    procedure AddL(ALink: array of TLink); overload;
    procedure DelL; overload;
    constructor Create;
    destructor Destroy; override;
End;

//Объект включающий в себя парсер, ссылки, прокси, БД
type TQTor = Class(TObject)
  private
    inSearch: Boolean;
    Searching : TSearchThread;
  public
  Var
    Links: TLinks;
    FindParam: Integer;
    constructor Create;
    destructor Destroy; override;
    procedure ChangeSocks(dSocks: TSocks);
    function FindSocks(FindParam: Integer=0): TSocks;
    function CheckSocks: Boolean;
    procedure StartSearching(Enable: Boolean);
    property Start: boolean read inSearch write StartSearching;
End;

function UpDir(S: String; level: byte=1): String;
function CheckSocks(var Socks: TSocks): Boolean;
function Pathproc(NameExe: String; Kill: Boolean=False): String;
function FindProcTorOrFF: String;
function FindProc(ProcName: String): Boolean;
procedure ParserLinks_Start;
procedure ParserLink_Start;
procedure FindWorkSocks_Start;
procedure InstallSocks_Start;
procedure RunCheck_Start;
procedure SetWindow(Index: Integer);
procedure FindTorDir_Start;
procedure LoadParam;
procedure SaveParam;

Var SEvent: TEvent;
    SThread: TSearchThread;
    SParser: TParser;
    Links: TLinks;
    n_google: Integer = 0;
    IndexLink: Integer = 0;
    IndexSocks: Integer = 0;
    DelayFindSocks: Integer = 0;
    LinksWithSocks: TStrings;
    FindTorDir, FindingTorDir: Boolean;
    ParsedLinks, ParsingLinks, ParsedLink, ParsingLink, NeedSocks,
    FindedSocks, FindingSocks, InstalledSocks, InstallingSocks,
    RunChecking, InRunChecking, FindSocksEnable, InstallSocksEnable: Boolean;
    TorDir, torrc: String;
    Link: TLink;

//Преременные пути к TOR
Var
  tor_dir, tor_browser: String;

implementation
uses QTorUnit;


procedure RunCheck_Start;
begin
  InRunChecking :=True;
  TThread.CreateAnonymousThread(procedure
        Var SocksInfo: TIdSocksInfo;
        Resp,Old_IP: String;
        Live: Boolean;
        Count: Integer;
    begin
      Live :=False;
      Old_IP :=Link.Sockses[IndexSocks].IP;
      Sleep(30000);
      if Old_IP=Link.Sockses[IndexSocks].IP then
      begin
      With QTorWindow do
        begin
          SocksInfo_IP.Caption :=Link.Sockses[IndexSocks].IP;
          SocksInfo_PORT.Caption :=Link.Sockses[IndexSocks].PORT;
          SocksInfo_Status.Caption :='In Checking';
        end;
      Count :=0;
      With SParser do
        While (Count<2) and (not Live) do
        try
          inc(Count);
          if Count=2 then Sleep(2000);
          FHTTP.Disconnect;
          SocksInfo :=TIdSocksInfo.Create();
            With SocksInfo do
              try
                Enabled :=True;
                Host :=Link.Sockses[IndexSocks].IP;
                Port :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Authentication :=saNoAuthentication;
              except
              end;
          If Link.Sockses[IndexSocks].STYPE='SOCKS5' then
            try
              SocksInfo.Version :=svSocks5;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
             except
              Live :=False;
             end else
          If Link.Sockses[IndexSocks].STYPE='SOCKS4' then
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          If Link.Sockses[IndexSocks].STYPE='HTTPS' then
            try
              FHTTP.IOHandler :=nil;
              FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
              FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          try
            SocksInfo.Version :=svSocks5;
            FSSL.TransparentProxy :=SocksInfo;
            FHTTP.IOHandler :=FSSL;
            Resp :=FHTTP.Get(check_url);
            If Pos(inc_word,Resp)>0 then
              begin
                Link.Sockses[IndexSocks].STYPE :='SOCKS5';
                Live :=True;
              end;
          except
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then
                begin
                  Link.Sockses[IndexSocks].STYPE :='SOCKS4';
                  Live :=True;
                end;
            except
              try
                FHTTP.IOHandler :=nil;
                FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
                FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Resp :=FHTTP.Get(check_url);
                If Pos(inc_word,Resp)>0 then
                  begin
                    Link.Sockses[IndexSocks].STYPE :='HTTPS';
                    Live :=True;
                  end;
              except
                Live :=False;
              end;
            end;
          end;
          SocksInfo.Free;
          if FHTTP.Connected then FHTTP.Disconnect;
          FHTTP.ProxyParams.ProxyServer :='';
          FHTTP.ProxyParams.ProxyPort :=0;
        finally
        end;
      If Live then
        begin
          QTorWindow.SocksInfo_Status.Caption :='LIVE';
          FindedSocks :=True;
        end else
        begin
          QTorWindow.SocksInfo_Status.Caption :='DEAD';
          Link.DelS;
          RunLevel :=4;
          FindedSocks :=False;
          FindingSocks :=False;
          QTorWindow.TrayQTorIcon.IconIndex :=0;
          QTorWindow.Icon :=QTorWindow.TrayQTorIcon.Icon;
          QTorWindow.ShowHind('QTOR [ Прокси мертв','IP:PORT '+Link.Sockses[IndexSocks].IP+
          ':'+Link.Sockses[IndexSocks].PORT+' ]','Прокси мертв - '+Link.Sockses[IndexSocks].IP+':'+Link.Sockses[IndexSocks].PORT);
        end;
      end;
      InRunChecking :=False;
    end).Start;
end;

procedure InstallSocks_Start;
begin
  InstallingSocks :=True;
  TThread.CreateAnonymousThread(procedure
    Var Storrc: TStrings;
        i: Integer;
    begin
      if torrc<>'' then
      try
        If FileExists(torrc) then
          try
            Storrc :=TStringList.Create;
            Storrc.LoadFromFile(torrc);
            i:=0;
            While i<Storrc.Count do
              begin
              if (Pos('Socks4Proxy',Storrc[i])>0) or (Pos('Socks5Proxy',Storrc[i])>0) or
                  (Pos('Socks5ProxyUsername',Storrc[i])>0) or (Pos('Socks5ProxyPassword',Storrc[i])>0)
                  or (Pos('HTTPSProxy',Storrc[i])>0) or (Pos('HTTPSProxyAuthenticator',Storrc[i])>0) then
                    Storrc.Delete(i) else inc(i);
              end;
            if Link.Sockses[IndexSocks].IP<>'' then
              Storrc.AddStrings(Link.Sockses[IndexSocks].InStrings);
            Storrc.SaveToFile(torrc);
            Storrc.Free;
            if Link.Sockses[IndexSocks].IP<>'' then
              TThread.CreateAnonymousThread(procedure
                Var j: Integer;
                begin
                  j :=0;
                  If Findproc('tor.exe') then
                    begin
                      While (FindWindow('MozillaDialogClass',nil)=0) and (j<40) do
                        begin
                          Sleep(100);
                          inc(j);
                        end;
                      SetForegroundWindow(FindWindow('MozillaDialogClass',nil));
                      keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0), 0, 0);
                      keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0),KEYEVENTF_KEYUP , 0);
                    end;
                end).Start;
          except
          end;
        Sleep(10000);
        QTorWindow.ShowHind('QTOR [ Прокси Установлен','IP:PORT '+Link.Sockses[IndexSocks].IP+
          ':'+Link.Sockses[IndexSocks].PORT+' ]','Прокси Установлен - '+Link.Sockses[IndexSocks].IP+':'+Link.Sockses[IndexSocks].PORT);
        InstalledSocks :=True;
        InstallingSocks :=False;
      except
      end;
    end).Start;
end;

procedure FindWorkSocks_Start;
begin
  FindingSocks :=True;
  TThread.CreateAnonymousThread(procedure
    Var SocksInfo: TIdSocksInfo;
        Resp: String;
        Live: Boolean;
    begin
      Live :=False;
      With QTorWindow do
        begin
          SocksInfo_IP.Caption :=Link.Sockses[IndexSocks].IP;
          SocksInfo_PORT.Caption :=Link.Sockses[IndexSocks].PORT;
          SocksInfo_Status.Caption :='In Checking';
        end;
      With SParser do
        try
          FHTTP.Disconnect;
          SocksInfo :=TIdSocksInfo.Create();
            With SocksInfo do
              try
                Enabled :=True;
                Host :=Link.Sockses[IndexSocks].IP;
                Port :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Authentication :=saNoAuthentication;
              except
              end;
          If Link.Sockses[IndexSocks].STYPE='SOCKS5' then
            try
              SocksInfo.Version :=svSocks5;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
             except
              Live :=False;
             end else
          If Link.Sockses[IndexSocks].STYPE='SOCKS4' then
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          If Link.Sockses[IndexSocks].STYPE='HTTPS' then
            try
              FHTTP.IOHandler :=nil;
              FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
              FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          try
            SocksInfo.Version :=svSocks5;
            FSSL.TransparentProxy :=SocksInfo;
            FHTTP.IOHandler :=FSSL;
            Resp :=FHTTP.Get(check_url);
            If Pos(inc_word,Resp)>0 then
              begin
                Link.Sockses[IndexSocks].STYPE :='SOCKS5';
                Live :=True;
              end;
          except
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then
                begin
                  Link.Sockses[IndexSocks].STYPE :='SOCKS4';
                  Live :=True;
                end;
            except
              try
                FHTTP.IOHandler :=nil;
                FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
                FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Resp :=FHTTP.Get(check_url);
                If Pos(inc_word,Resp)>0 then
                  begin
                    Link.Sockses[IndexSocks].STYPE :='HTTPS';
                    Live :=True;
                  end;
              except
                Live :=False;
              end;
            end;
          end;
          SocksInfo.Free;
          if FHTTP.Connected then FHTTP.Disconnect;
          FHTTP.ProxyParams.ProxyServer :='';
          FHTTP.ProxyParams.ProxyPort :=0;
        finally
        end;
      If Live then
        begin
          QTorWindow.SocksInfo_Status.Caption :='LIVE';
          FindedSocks :=True;
        end else
        begin
          QTorWindow.SocksInfo_Status.Caption :='DEAD';
          Link.DelS;
        end;
      FindingSocks :=False;
    end).Start;
end;

procedure ParserLink_Start;
begin
  ParsingLink :=True;
  TThread.CreateAnonymousThread(procedure
    Var i: Word;
        R: TRegExp;
        Parser: TParser;
        dSocks: TSocks;
    begin
      Parser :=TParser.Create;
      SetLength(Link.Sockses,0);
      With R do
        try
          RMathes :=RegEx.Matches(Parser.AsHTML(LinksWithSocks[IndexLink]),RE_GL4);
          if RMathes.Count>0 then
            begin
              For i:=0 to RMathes.Count-1 do
                begin
                  dSocks.IP :=RegEx.Match(RMathes[i].Value,RE_GL_IP).Value;
                  dSocks.PORT :=RegEx.Match(RMathes[i].Value,RE_GL_PORT).Value;
                  Link.AddS(dSocks);
                end;
              ParsedLink :=True;
            end else LinksWithSocks.Delete(IndexLink);
        except
        end;
      Link.SocksRandomize;
      IndexSocks :=0;
      ParsingLink :=False;
      Parser.Free;
    end).Start;
end;

procedure ParserLinks_Start;
begin
  ParsingLinks :=True;
  TThread.CreateAnonymousThread(procedure
    Var i: Word;
        dS: String;
        R: TRegExp;
        Parser: TParser;
    begin
      Parser :=TParser.Create;
      With R do
        try
          RMathes :=RegEx.Matches(Parser.AsHTML(google_search+IntToStr(n_google)),RE_GL2);
          For i:=0 to RMathes.Count-1 do
            begin
              dS :=RMathes.Item[i].Value;
              LinksWithSocks.Add(RegEx.Match(dS,(RE_GL5)).Value);
            end;
        except
        end;
      inc(n_google);
      Parser.Free;
      ParsedLinks :=True;
      ParsingLinks :=False;
    end).Start;
end;

procedure LoadParam;
Var S: TStrings;
begin
  S :=TStringList.Create;
  if FileExists('param.qtr') then
    begin
      S.LoadFromFile('param.qtr');
      try
        If FileExists(S[0]+TOR_exe) then
          begin
            TorDir :=S[0];
            torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
            FindTorDir :=True;
          end else FindTorDir :=False;
        If S[1]='0' then QTorWindow.AutoSeachProxy.Checked :=False;
        If S[2]='0' then QTorWindow.AutoInstallProxy.Checked :=False;
      except
        FindTorDir :=False;
      end;
    end;
end;
procedure SaveParam;
Var S: TStrings;
begin
  S :=TStringList.Create;
  S.Add(TorDir);
  With QTorWindow do
    begin
      if AutoSeachProxy.Checked then S.Add('1') else S.Add('0');
      If AutoInstallProxy.Checked then S.Add('1') else S.Add('0');
    end;
  S.SaveToFile('param.qtr');
end;

procedure SetWindow(Index: Integer);
begin
  With QTorWindow do case Index of
    0: begin
        PanelControlSocks.Visible :=False;
        QTorWindow.ClientHeight :=90;
        PanelFindTor.Visible :=True;
    end;
    1: begin
        PanelFindTor.Visible :=False;
        QTorWindow.ClientHeight :=185;
        PanelControlSocks.Visible :=True;
    end;
  end;
end;

//Запуск потока поиска TOR папки
procedure FindTorDir_Start;
Var TorDirPath: String;
begin
  FindingTorDir :=True;
  TorDirPath :=FindProcTorOrFF;
  If TorDirPath='' then
    begin
      SetWindow(0);
      TThread.CreateAnonymousThread(procedure
        Var TorDirPath: String;
        begin
          While TorDirPath='' do
            begin
              Sleep(2000);
              TorDirPath :=FindProcTorOrFF;
            end;
          TorDir :=TorDirPath;
          torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
          FindTorDir :=True;
          FindingTorDir :=False;
          SetWindow(1);
        end).Start;
    end else
    begin
      TorDir :=TorDirPath;
      torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
      FindTorDir :=True;
      FindingTorDir :=False;
    end;
end;

procedure AddResult(Live: Boolean);
begin
//  If Live then QTorWindow.Event.Caption :='LIVE '+SocksToCheck.IP+':'+SocksToCheck.PORT else
//    QTorWindow.Event.Caption :='DEAD '+SocksToCheck.IP+':'+SocksToCheck.PORT;
end;

function TQTor.CheckSocks: Boolean;
Var Resp: String;
    SocksInfo :TIdSocksInfo;
    Live, Checked: Boolean;
begin
  Checked :=False;

//  While not Checked do Sleep(1000);
end;
procedure TQTor.StartSearching(Enable: Boolean);
begin
  If Enable then
    begin
      if Searching<>nil then
        begin

        end else
        begin
          Searching :=TSearchThread.Create;

        end;
    end;
end;

procedure TSearchThread.Execute;
begin
//      SEvent.WaitFor(INFINITE);

//      inc(incV);
//      QTorWindow.Event.Caption :=inttoStr(incV);
//      Free;
//      Terminate;
//      SEvent.SetEvent;
//    end;
end;

procedure TCheckThread.Execute;
Var Resp: String;
    SocksInfo :TIdSocksInfo;
    i: Word;
begin
end;
//Возвращает строку с уровнем директории выше
function UpDir(S: String; level: byte=1): String;
Var i,j: byte;
begin
  i :=Length(S);
  For j:=1 to level do
  try
    While S[i]<>'\' do
    try
      Delete(S,i,1);
      dec(i);
    except
    end;
    Delete(S,i,1);
  except
  end;
  Result :=S+'\';
end;

//Узнает тип прокси и проверяет его доступность
function CheckSocks(var Socks: TSocks): Boolean;
Var Resp: String;
    SocksInfo :TIdSocksInfo;
    Parser: TParser;
begin
  Parser :=TParser.Create;
  With Parser do
  try
    SocksInfo :=TIdSocksInfo.Create();
      With SocksInfo do
        try
          Enabled :=True;
          Host :=Socks.IP;
          Port :=StrToInt(Socks.PORT);
          Authentication :=saNoAuthentication;
        except
        end;
    If Socks.STYPE='SOCKS5' then
      try
        SocksInfo.Version :=svSocks5;
        FSSL.TransparentProxy :=SocksInfo;
        FHTTP.IOHandler :=FSSL;
        Resp :=FHTTP.Get(check_url);
        If Pos(inc_word,Resp)>0 then Result :=True;
       except
        Result :=False;
       end else
    If Socks.STYPE='SOCKS4' then
      try
        SocksInfo.Version :=svSocks4;
        FSSL.TransparentProxy :=SocksInfo;
        FHTTP.IOHandler :=FSSL;
        Resp :=FHTTP.Get(check_url);
        If Pos(inc_word,Resp)>0 then Result :=True;
      except
        Result :=False;
      end else
    If Socks.STYPE='HTTPS' then
      try
        FHTTP.IOHandler :=nil;
        FHTTP.ProxyParams.ProxyServer :=Socks.IP;
        FHTTP.ProxyParams.ProxyPort :=StrToInt(Socks.PORT);
        Resp :=FHTTP.Get(check_url);
        If Pos(inc_word,Resp)>0 then Result :=True;
      except
        Result :=False;
      end else
    try
      SocksInfo.Version :=svSocks5;
      FSSL.TransparentProxy :=SocksInfo;
      FHTTP.IOHandler :=FSSL;
      Resp :=FHTTP.Get(check_url);
      If Pos(inc_word,Resp)>0 then
        begin
          Socks.STYPE :='SOCKS5';
          Result :=True;
        end;
    except
      try
        SocksInfo.Version :=svSocks4;
        FSSL.TransparentProxy :=SocksInfo;
        FHTTP.IOHandler :=FSSL;
        Resp :=FHTTP.Get(check_url);
        If Pos(inc_word,Resp)>0 then
          begin
            Socks.STYPE :='SOCKS4';
            Result :=True;
          end;
      except
        try
          FHTTP.IOHandler :=nil;
          FHTTP.ProxyParams.ProxyServer :=Socks.IP;
          FHTTP.ProxyParams.ProxyPort :=StrToInt(Socks.PORT);
          Resp :=FHTTP.Get(check_url);
          If Pos(inc_word,Resp)>0 then
            begin
              Socks.STYPE :='HTTPS';
              Result :=True;
            end;
        except
          Result :=False;
        end;
      end;
    end;
    SocksInfo.Free;
    if FHTTP.Connected then FHTTP.Disconnect;
    FHTTP.ProxyParams.ProxyServer :='';
    FHTTP.ProxyParams.ProxyPort :=0;
  finally
    Parser.Free;
  end;
//    S:=FHTTP.Get('http://api.ipify.org');
end;

//Находит путь к папке с TOR
function FindProcTorOrFF: String;
const
  PROCESS_TERMINATE = $0001;
var proc:TPROC;
    dS: String;
begin
  With proc do
    try
      pe.dwSize:=SizeOf(pe);
      h:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
      If Process32First(h,pe) then
        While Process32Next(h,pe) do
          begin
          if (ExtractFileName(pe.szExeFile)='firefox.exe') or (ExtractFileName(pe.szExeFile)='tor.exe') then
            begin
              h1 := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or PROCESS_TERMINATE, false, pe.th32ProcessID);
              GetModuleFileNameEx(h1, 0, path, MAX_PATH);
              dS :=UpDir(path,1);
              if ExtractFileName(pe.szExeFile)='firefox.exe' then
                if FileExists(dS+TOR_exe) then
                  begin
                    Result :=dS;
                    Break;
                  end;
              If ExtractFileName(pe.szExeFile)='tor.exe' then
                begin
                  Result :=UpDir(dS,3);
                  Break;
                end;
              CloseHandle(h1);
            end;
          end;
  finally
    CloseHandle(h);
  end;
end;
function FindProc(ProcName: String): Boolean;
const
  PROCESS_TERMINATE = $0001;
var proc:TPROC;
    dS: String;
begin
  Result :=False;
  With proc do
    try
      pe.dwSize:=SizeOf(pe);
      h:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
      If Process32First(h,pe) then
        While Process32Next(h,pe) do
          begin
          if ExtractFileName(pe.szExeFile)=ProcName then
            begin
              h1 := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or PROCESS_TERMINATE, false, pe.th32ProcessID);
              GetModuleFileNameEx(h1, 0, path, MAX_PATH);
              TerminateProcess(h1,4);
              CloseHandle(h1);
              Result :=True;
              break;
            end;
          end;
  finally
    CloseHandle(h);
  end;
end;
//Находит путь к процессу, если Kill - то убивает его
function Pathproc(NameExe: String; Kill: Boolean=False): String;
const
  PROCESS_TERMINATE = $0001;
var proc:TPROC;
  dS: String;
  ProcessHandle : THandle;
  ProcessID: Integer;
  TheWindow : HWND;
begin
  With proc do try
    pe.dwSize:=SizeOf(pe);
    h:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    If Process32First(h,pe) then
      While Process32Next(h,pe) do
        begin
        dS :=ExtractFileName(pe.szExeFile);
        if ExtractFileName(pe.szExeFile)=NameExe then
          begin
            h1 := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or PROCESS_TERMINATE, false, pe.th32ProcessID);
            GetModuleFileNameEx(h1, 0, path, MAX_PATH);
            if NameExe='tor.exe' then
            begin
              Result :=path;
              if Kill then TerminateProcess(h1,4);
              CloseHandle(h1);
              exit;
            end else
            if NameExe='firefox.exe' then
            begin
              tor_browser :=path;
              dS :=UpDir(path,1)+'TorBrowser\Tor\tor.exe';
              If FileExists(dS) then
                begin
                  Result :=path;
                  if Kill then TerminateProcess(h1,4);
                  CloseHandle(h1);
                  exit;
                end;
            end;
          end;
        end;
    CloseHandle(h);
  except
  end;
end;

{ TParser }
constructor TParser.Create;
Var Res: String;
begin
  inherited;
  FSSL :=TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  FSSL.ConnectTimeout:=5000;
  FSSL.ReadTimeout:=5000;
  FHTTP :=TIdHTTP.Create(nil);
  FCookie := TIdCookieManager.Create(nil);
  FHTTP.CookieManager :=FCookie;
  FHTTP.IOHandler :=FSSL;
  FHTTP.HandleRedirects :=True;
  FHTTP.AllowCookies :=True;
  FHTTP.ReadTimeout:=5000;
  FHTTP.ConnectTimeout :=5000;
end;
destructor TParser.Destroy;
begin
  FCookie.Free;
  FHTTP.Free;
  FSSL.Free;
  inherited;
end;
//Получаем ответ по Url запросу в String
function TParser.AsHTML(Url: string): String;
begin
  try
  Result :=FHTTP.Get(Url);
  FHTTP.Disconnect;
  except
  end;
end;

{ TSocks }
//Представляем прокси в виде строки для записи в torrc
function TSocks.InStrings;
begin
  Result :=TStringList.Create;
  if STYPE = 'SOCKS4' then
    begin
      Result.Add('Socks4Proxy '+IP+':'+PORT);
    end else
  if STYPE = 'SOCKS5' then
    begin
      Result.Add('Socks5Proxy '+IP+':'+PORT);
      if Login<>'' then
        begin
          Result.Add('Socks5ProxyUsername '+Login);
          Result.Add('Socks5ProxyPassword '+Passw);
        end;
    end else
  if STYPE = 'HTTPS' then
    begin
      Result.Add('HTTPSProxy '+IP+':'+PORT);
      if Login<>'' then Result.Add('HTTPSProxyAuthenticator '+Login+':'+Passw);
    end;
end;

{ TLink }
constructor TLink.Create(Sender: TObject);
begin
  Parser :=TParser.Create;
  Url :='';
  DeadSockses :=0; LiveSockses :=0; LiveTime :=0;
end;
destructor TLink.Destroy;
begin
  Parser.Free;
  SetLength(Sockses,0);
end;
//Добавляем запись прокси в ссылку
procedure TLink.AddS(IP,PORT: String; STYPE: String=''; LOGIN: String=''; PASSW: String='');
begin
  SetLength(Sockses, Length(Sockses)+1);
  Sockses[Length(Sockses)-1].IP :=IP;
  Sockses[Length(Sockses)-1].PORT :=PORT;
  Sockses[Length(Sockses)-1].STYPE :=STYPE;
  Sockses[Length(Sockses)-1].LOGIN :=LOGIN;
  Sockses[Length(Sockses)-1].PASSW :=PASSW;
end;
procedure TLink.AddS(Socks: TSocks);
begin
  SetLength(Sockses, Length(Sockses)+1);
  Sockses[Length(Sockses)-1].IP :=Socks.IP;
  Sockses[Length(Sockses)-1].PORT :=Socks.PORT;
  Sockses[Length(Sockses)-1].STYPE :=Socks.STYPE;
  Sockses[Length(Sockses)-1].LOGIN :=Socks.LOGIN;
end;
//Удаляем прокси из ссылки
procedure TLink.DelS;
Var i: Integer;
begin
  if Length(Sockses)>1 then
    begin
      for i:=1 to Length(Sockses)-1 do
          Sockses[i-1] :=Sockses[i];
      SetLength(Sockses,Length(Sockses)-1);
    end else SetLength(Sockses,0);
end;

{ TLinks}
//Парсим прокси на текущей ссылке
procedure TLink.SocksRandomize;
Var i,j,x: Word;
    dSocks: TSocks;
begin
  j :=Length(Sockses);
  Randomize;
  If j>0 then
    try
      For i:=0 to j-1 do
        begin
          dSocks :=Sockses[i];
          x :=Random(j);
          Sockses[i] :=Sockses[x];
          Sockses[x] :=dSocks;
        end;
    except
    end;
end;
function TLink.ParseSocks: Boolean;
Var i: Word;
    dSocks: TSocks;
    dS: String;
begin
  With R do
    try
      dS :=Parser.AsHTML(Url);
      RMathes :=RegEx.Matches(dS,RE_GL4);
      if RMathes.Count>0 then
        begin
          For i:=0 to RMathes.Count-1 do
            try
                dSocks.IP :=RegEx.Match(RMathes[i].Value,RE_GL_IP).Value;
                dSocks.PORT :=RegEx.Match(RMathes[i].Value,RE_GL_PORT).Value;
                AddS(dSocks);
            except
            end;
          Result :=True;
        end else Result :=False;
    except
    end;
end;
//Парсим ссылки с прокси
function TLinks.ParseLinks: Boolean;
Var i: Word;
    dS: String;
begin
  Result :=False;
  With R do
    try
      RMathes :=RegEx.Matches(Parser.AsHTML(google_search+IntToStr(n_google)),RE_GL2);
      For i:=0 to RMathes.Count-1 do
        begin
          dS :=RMathes.Item[i].Value;
          AddL(RegEx.Match(dS,(RE_GL5)).Value);
        end;
      if i>0 then Result :=True;
    except
    end;
end;
constructor TLinks.Create;
begin
  inherited;
  Parser :=TParser.Create;
  SetLength(Items,0);
  ItemIndex :=-1;
  n_google :=0;
end;
destructor TLinks.Destroy;
begin
  Parser.Free;
  SetLength(Items,0); ItemIndex :=-1;
  inherited;
end;
//Удаляем ссылку
procedure TLinks.DelL;
Var i: Integer;
begin
  if Length(Items)-1>ItemIndex then
    try
      for i:=ItemIndex+1 to Length(Items)-1 do
        Items[i-1] :=Items[i];
      Items[Length(Items)-1].Free;
      SetLength(Items,i);
    except
    end;
end;
//Добавляем ссылку
procedure TLinks.AddL(Url: String);
begin
  SetLength(Items, Length(Items)+1);
  Items[Length(Items)-1] :=TLink.Create(Self);
  Items[Length(Items)-1].Url :=Url;
end;
procedure TLinks.AddL(ALink: array of TLink);
Var i: Word;
begin
  If Length(ALink)>0 then
    For i :=0 to Length(ALink)-1 do AddL(ALink[i].Url);
end;

{ TQTor }
constructor TQTor.Create;
begin
  inherited;
//  inSearch :=False;
//  SocksParser :=TParser.Create;
//  SParser :=TParser.Create;
//  Links :=TLinks.Create;
end;
destructor TQTor.Destroy;
begin
//  Links.Free;
//  SocksParser.Free;
//  SParser.Free;
  inherited;
end;
//Поиск рабочего носка в Links
function TQTor.FindSocks(FindParam: Integer=0): TSocks;
begin
  Randomize;
  With Links do
  try
    if Length(Items)=0 then
      try
        AddL('http://www.gatherproxy.com/sockslist');
        ParseLinks;
        ItemIndex :=0;
      except
      end;
      try
        Enable :=True;
        While Enable and (Length(Items)>0) do
          try
            if ItemIndex>Length(Items) then ItemIndex :=0;
            If Length(Items[ItemIndex].Sockses)=0 then
              begin
                if not Items[ItemIndex].ParseSocks then DelL else
                  Items[ItemIndex].SocksRandomize;
              end else
              try
                While Enable and (Length(Items[ItemIndex].Sockses)>0) do
                  try
//                    if not CheckSocks(Items[ItemIndex].Sockses[0]) then
//                      begin
//                        Sleep(500);
//                        Items[ItemIndex].DelS;
//                      end else
//                      begin
//                        Enable :=False;
//                        Sleep(500);
//                      end;
                  except
                  end;
                if Length(Items[ItemIndex].Sockses)=0 then inc(ItemIndex);
              except
              end;
          except
          end;
        Result :=Items[ItemIndex].Sockses[0];
      except
      end
  except
  end;
end;
//Меняем прокси, путем того, что добавляем его в torrc,
//завершаем процесс tor.exe, и принимаем перезапуск tor.exe в TOR Browser
//Если TOR Browser закрыт - открываем его
procedure TQTOR.ChangeSocks(dSocks: TSocks);
Var i: Word;
    etb: String;
    Storrc: TStrings;
begin
  if torrc<>'' then
    try
      If FileExists(torrc) then
        try
          Storrc :=TStringList.Create;
          Storrc.LoadFromFile(torrc);
          i:=0;
          While i<Storrc.Count do
            begin
            if (Pos('Socks4Proxy',Storrc[i])>0) or (Pos('Socks5Proxy',Storrc[i])>0) or
                (Pos('Socks5ProxyUsername',Storrc[i])>0) or (Pos('Socks5ProxyPassword',Storrc[i])>0)
                or (Pos('HTTPSProxy',Storrc[i])>0) or (Pos('HTTPSProxyAuthenticator',Storrc[i])>0) then
                  Storrc.Delete(i) else inc(i);
            end;
          if dSocks.IP<>'' then Storrc.AddStrings(dSocks.InStrings);
          Storrc.SaveToFile(torrc);
          Storrc.Free;
          if dSocks.IP<>'' then
            begin
              if Pathproc('tor.exe',True)<>'' then
                try
                  While FindWindow('MozillaDialogClass',nil)=0 do Sleep(200);
                  While FindWindow('MozillaDialogClass',nil)>0 do
                  try
                    SetForegroundWindow(FindWindow('MozillaDialogClass',nil));
                    keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0), 0, 0);
                    keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0),KEYEVENTF_KEYUP , 0);
                  except
                  end;
                  Sleep(5000);
                except
                end
              else
                try
                  etb :=UpDir(tor_dir,2)+'firefox.exe';
                  if FileExists(etb) then
                    With QTorWindow do
                      begin
                        ShellExecute(1, 'open', PWideChar(etb), nil ,nil, SW_NORMAL);
                      end;
                  Sleep(5000);
                except
                end;
            end;
        except
        end;
    except
    end;
end;

end.
